use anchor_lang::prelude::*;
use solana_sha256_hasher as sha256;
use solana_bn254::prelude::{
    alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing as alt_bn128_pairing_syscall,
};
use solana_keccak_hasher as keccak;
use solana_secp256k1_recover::secp256k1_recover;

use opaque_privacy_pool::{Pool, ROOT_HISTORY};

declare_id!("7sDCTbMDwjzYA3KHhNPZUVa8Swvj6adJTgSkJqmsn6V7");

// Conditional disclosure on Solana (spec/conditional-disclosure.md): a privacy-pool
// note's (value, label) may be put on the record for a requester iff (a) an M-of-N
// custodian quorum FROST-signs the request — verified here as a standard BIP-340
// Schnorr signature over the request `context` via the secp256k1_recover syscall —
// and (b) a Groth16 `conditional_disclosure` proof (alt_bn254 syscalls, embedded
// vkey) shows the note is in the pool's state tree and its value exceeds the policy
// threshold. The circuit enforces qualification, so custodians authorize blind.
// Disclosure nullifiers are init-once PDAs under THIS program: disclosing never
// spends the note, spending never blocks disclosure.
//
// Testnet only; same audit gates as the pool.

/// BN254 scalar field r, big-endian.
const SCALAR_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
/// BN254 base field q, big-endian (G1 y-negation for the pairing check).
const BASE_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];
/// secp256k1 group order n, big-endian.
const SECP_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// secp256k1 base-field prime p, big-endian.
const SECP_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];
/// sha256("BIP0340/challenge") — the BIP-340 tagged-hash prefix.
const CHALLENGE_TAG: [u8; 32] = [
    0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32, 0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
    0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f, 0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
];

#[program]
pub mod conditional_disclosure {
    use super::*;

    /// Register an immutable disclosure policy binding a custodian FROST group key
    /// to a pool and a qualification threshold. The policy PDA is keyed by the
    /// group key, so rotation (a new DKG) registers a new policy.
    pub fn register_policy(
        ctx: Context<RegisterPolicy>,
        group_key_x: [u8; 32],
        threshold: u64,
        m: u8,
        n: u8,
    ) -> Result<()> {
        require!(
            group_key_x != [0u8; 32] && lt_be(&group_key_x, &SECP_P),
            DisclosureError::InvalidGroupKey
        );
        require!(m >= 1 && n >= m, DisclosureError::InvalidQuorum);
        let policy = &mut ctx.accounts.policy;
        policy.bump = ctx.bumps.policy;
        policy.pool = ctx.accounts.pool.key();
        policy.group_key_x = group_key_x;
        policy.threshold = threshold;
        policy.m = m;
        policy.n = n;
        emit!(PolicyRegistered {
            policy: policy.key(),
            pool: policy.pool,
            group_key_x,
            threshold,
            m,
            n,
        });
        Ok(())
    }

    /// Submit a quorum-authorized disclosure. Circuit public-signal order:
    /// [value, label, threshold, state_root, disclosure_nullifier, context];
    /// `threshold` comes from the policy and `context` is recomputed here from
    /// (policy, case_id, requester), so neither is caller-supplied.
    #[allow(clippy::too_many_arguments)]
    pub fn disclose(
        ctx: Context<Disclose>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        value: u64,
        label: [u8; 32],
        state_root: [u8; 32],
        disclosure_nullifier: [u8; 32],
        case_id: [u8; 32],
        sig_rx: [u8; 32],
        sig_ry: [u8; 32],
        sig_s: [u8; 32],
    ) -> Result<()> {
        let policy = &ctx.accounts.policy;
        let requester = ctx.accounts.requester.key();

        // context = keccak256(policy ‖ case_id ‖ requester), top 3 bits cleared so it
        // is a valid field element (the prover and SDK recompute it identically).
        let mut context = keccak::hashv(&[
            policy.key().as_ref(),
            &case_id,
            requester.as_ref(),
        ])
        .to_bytes();
        context[0] &= 0x1f;

        // The custodian quorum authorized this exact request.
        require!(
            verify_schnorr(&policy.group_key_x, &context, &sig_rx, &sig_ry, &sig_s),
            DisclosureError::InvalidQuorumSignature
        );

        // The state root is a real root of the policy's pool (address-checked account).
        require!(
            is_known_root(&ctx.accounts.pool, &state_root),
            DisclosureError::UnknownStateRoot
        );

        // The disclosure proof itself.
        let pub_signals: [[u8; 32]; 6] = [
            value_to_field(value),
            label,
            value_to_field(policy.threshold),
            state_root,
            disclosure_nullifier,
            context,
        ];
        require!(
            verify_disclosure(proof_a, proof_b, proof_c, &pub_signals)?,
            DisclosureError::InvalidProof
        );

        // The nullifier PDA is init-once: a replayed disclosure fails at creation.
        ctx.accounts.nullifier.bump = ctx.bumps.nullifier;

        emit!(DisclosureEvent {
            policy: policy.key(),
            case_id,
            requester,
            label,
            value,
            disclosure_nullifier,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pool root history (read-only view over the pool program's account)
// ---------------------------------------------------------------------------

fn is_known_root(pool: &Account<Pool>, root: &[u8; 32]) -> bool {
    if *root == [0u8; 32] {
        return false;
    }
    let mut i = pool.current_root_index as usize;
    loop {
        if pool.roots[i] == *root {
            return true;
        }
        if i == 0 {
            i = ROOT_HISTORY;
        }
        i -= 1;
        if i == pool.current_root_index as usize {
            break;
        }
    }
    false
}

/// u64 → big-endian 32-byte field element.
fn value_to_field(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// BIP-340 Schnorr verification (secp256k1_recover syscall; spec §5)
//
//   e = int(sha256(tag ‖ tag ‖ Rx ‖ Px ‖ m)) mod n
//   valid ⟺ s·G == R + e·P   ⟺   recover(z = -s·Px, recid 0, r = Px, s' = -e·Px) == R
// ---------------------------------------------------------------------------

fn verify_schnorr(
    px: &[u8; 32],
    msg: &[u8; 32],
    rx: &[u8; 32],
    ry: &[u8; 32],
    s: &[u8; 32],
) -> bool {
    if *px == [0u8; 32] || !lt_be(px, &SECP_P) {
        return false;
    }
    if !lt_be(s, &SECP_N) {
        return false;
    }
    if !lt_be(rx, &SECP_P) || !lt_be(ry, &SECP_P) {
        return false;
    }
    // R must have even Y (BIP-340) and lie on the curve: y² = x³ + 7 (mod p).
    if ry[31] & 1 != 0 {
        return false;
    }
    let y2 = modmul(ry, ry, &SECP_P);
    let x2 = modmul(rx, rx, &SECP_P);
    let mut x3p7 = modmul(&x2, rx, &SECP_P);
    let seven = {
        let mut v = [0u8; 32];
        v[31] = 7;
        v
    };
    x3p7 = modadd(&x3p7, &seven, &SECP_P);
    if y2 != x3p7 {
        return false;
    }

    // Tagged challenge hash, reduced mod n (2^256 < 2n, one conditional subtract).
    let e_hash = sha256::hashv(&[&CHALLENGE_TAG, &CHALLENGE_TAG, rx, px, msg]).to_bytes();
    let e = reduce_once(&e_hash, &SECP_N);

    let z = modneg(&modmul(s, px, &SECP_N), &SECP_N); // -s·Px mod n
    let s_sig = modneg(&modmul(&e, px, &SECP_N), &SECP_N); // -e·Px mod n
    if z == [0u8; 32] || s_sig == [0u8; 32] {
        return false; // degenerate; recover would reject anyway
    }

    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(px);
    sig64[32..].copy_from_slice(&s_sig);
    let recovered = match secp256k1_recover(&z, 0, &sig64) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let q = recovered.to_bytes();
    q[..32] == rx[..] && q[32..] == ry[..]
}

// 256-bit big-endian modular arithmetic over [u64; 4] limbs (little-endian limbs).

fn to_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for i in 0..4 {
        l[3 - i] = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    l
}

fn from_limbs(l: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[i * 8..(i + 1) * 8].copy_from_slice(&l[3 - i].to_be_bytes());
    }
    b
}

fn limbs_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// a + b, returning (sum, carry).
fn limbs_add(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry as u64);
        out[i] = s2;
        carry = c1 || c2;
    }
    (out, carry)
}

/// a - b (assumes a >= b).
fn limbs_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        out[i] = d2;
        borrow = b1 || b2;
    }
    out
}

/// (a + b) mod m, where a, b < m.
fn limbs_addmod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let (sum, carry) = limbs_add(a, b);
    if carry || !limbs_lt(&sum, m) {
        limbs_sub(&sum, m)
    } else {
        sum
    }
}

/// x mod m for x < 2m (one conditional subtraction).
fn reduce_once(x: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let xl = to_limbs(x);
    let ml = to_limbs(m);
    if limbs_lt(&xl, &ml) {
        *x
    } else {
        from_limbs(&limbs_sub(&xl, &ml))
    }
}

/// (a · b) mod m via double-and-add (constant 256 iterations).
fn modmul(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let ml = to_limbs(m);
    let al = to_limbs(&reduce_once(a, m));
    let bl = to_limbs(&reduce_once(b, m));
    let mut acc = [0u64; 4];
    for bit in (0..256).rev() {
        acc = limbs_addmod(&acc, &acc, &ml);
        if (al[bit / 64] >> (bit % 64)) & 1 == 1 {
            acc = limbs_addmod(&acc, &bl, &ml);
        }
    }
    from_limbs(&acc)
}

fn modadd(a: &[u8; 32], b: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let ml = to_limbs(m);
    let al = to_limbs(&reduce_once(a, m));
    let bl = to_limbs(&reduce_once(b, m));
    from_limbs(&limbs_addmod(&al, &bl, &ml))
}

/// (-a) mod m (a < m).
fn modneg(a: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    if *a == [0u8; 32] {
        return [0u8; 32];
    }
    let ml = to_limbs(m);
    let al = to_limbs(a);
    from_limbs(&limbs_sub(&ml, &al))
}

/// Big-endian strict less-than.
fn lt_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

fn is_valid_scalar(v: &[u8; 32]) -> bool {
    lt_be(v, &SCALAR_FIELD)
}

// ---------------------------------------------------------------------------
// Groth16 verification (alt_bn254 syscalls; conditional_disclosure vkey)
// ---------------------------------------------------------------------------

fn verify_disclosure(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    pub_signals: &[[u8; 32]; 6],
) -> Result<bool> {
    for s in pub_signals {
        require!(is_valid_scalar(s), DisclosureError::InvalidPublicSignal);
    }
    let mut vk_x = VK_IC_DISCLOSURE[0];
    for i in 0..6 {
        let m = alt_bn128_g1_mul(&VK_IC_DISCLOSURE[i + 1], &pub_signals[i])?;
        vk_x = alt_bn128_g1_add(&vk_x, &m)?;
    }
    run_pairing_check(proof_a, proof_b, proof_c, vk_x)
}

fn run_pairing_check(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    vk_x: [u8; 64],
) -> Result<bool> {
    let mut neg_a = proof_a;
    let neg_a_y = field_negate(&proof_a[32..64]);
    neg_a[32..64].copy_from_slice(&neg_a_y);

    let mut input = Vec::with_capacity(768);
    input.extend_from_slice(&neg_a);
    input.extend_from_slice(&proof_b);
    input.extend_from_slice(&VK_ALPHA_DISCLOSURE);
    input.extend_from_slice(&VK_BETA_DISCLOSURE);
    input.extend_from_slice(&vk_x);
    input.extend_from_slice(&VK_GAMMA_DISCLOSURE);
    input.extend_from_slice(&proof_c);
    input.extend_from_slice(&VK_DELTA_DISCLOSURE);

    let result = alt_bn128_pairing_syscall(&input)
        .map_err(|_| error!(DisclosureError::PairingFailed))?;
    Ok(result[31] == 1 && result[..31].iter().all(|&b| b == 0))
}

fn field_negate(a: &[u8]) -> [u8; 32] {
    if a.iter().all(|&b| b == 0) {
        return [0u8; 32];
    }
    let mut result = [0u8; 32];
    let mut borrow = false;
    for i in (0..32).rev() {
        let (d1, b1) = BASE_FIELD[i].overflowing_sub(a[i]);
        let (d2, b2) = d1.overflowing_sub(if borrow { 1 } else { 0 });
        result[i] = d2;
        borrow = b1 || b2;
    }
    result
}

fn alt_bn128_g1_add(a: &[u8; 64], b: &[u8; 64]) -> Result<[u8; 64]> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);
    let r = alt_bn128_addition(&input).map_err(|_| error!(DisclosureError::Bn128Failed))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&r[..64]);
    Ok(out)
}

fn alt_bn128_g1_mul(point: &[u8; 64], scalar: &[u8; 32]) -> Result<[u8; 64]> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar);
    let r = alt_bn128_multiplication(&input).map_err(|_| error!(DisclosureError::Bn128Failed))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&r[..64]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(group_key_x: [u8; 32])]
pub struct RegisterPolicy<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Policy::LEN,
        seeds = [b"policy", group_key_x.as_ref()],
        bump,
    )]
    pub policy: Account<'info, Policy>,
    /// The privacy pool this policy can disclose from (owner-checked Pool account).
    pub pool: Box<Account<'info, Pool>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64], proof_b: [u8; 128], proof_c: [u8; 64],
    value: u64, label: [u8; 32], state_root: [u8; 32], disclosure_nullifier: [u8; 32]
)]
pub struct Disclose<'info> {
    #[account(seeds = [b"policy", policy.group_key_x.as_ref()], bump = policy.bump)]
    pub policy: Account<'info, Policy>,
    /// The policy's pool, read-only (root-history check).
    #[account(address = policy.pool @ DisclosureError::WrongPool)]
    pub pool: Box<Account<'info, Pool>>,
    #[account(
        init,
        payer = requester,
        space = 8 + DisclosureNullifier::LEN,
        seeds = [b"nullifier", disclosure_nullifier.as_ref()],
        bump,
    )]
    pub nullifier: Account<'info, DisclosureNullifier>,
    /// The requester receives the disclosure and is bound into `context`.
    #[account(mut)]
    pub requester: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ---------------------------------------------------------------------------
// State / events / errors
// ---------------------------------------------------------------------------

#[account]
pub struct Policy {
    pub pool: Pubkey,
    pub group_key_x: [u8; 32],
    pub threshold: u64,
    pub m: u8,
    pub n: u8,
    pub bump: u8,
}

impl Policy {
    pub const LEN: usize = 32 + 32 + 8 + 1 + 1 + 1;
}

#[account]
pub struct DisclosureNullifier {
    pub bump: u8,
}

impl DisclosureNullifier {
    pub const LEN: usize = 1;
}

#[event]
pub struct PolicyRegistered {
    pub policy: Pubkey,
    pub pool: Pubkey,
    pub group_key_x: [u8; 32],
    pub threshold: u64,
    pub m: u8,
    pub n: u8,
}

#[event]
pub struct DisclosureEvent {
    pub policy: Pubkey,
    pub case_id: [u8; 32],
    pub requester: Pubkey,
    pub label: [u8; 32],
    pub value: u64,
    pub disclosure_nullifier: [u8; 32],
}

#[error_code]
pub enum DisclosureError {
    #[msg("Group key is zero or not a valid field element")]
    InvalidGroupKey,
    #[msg("Quorum descriptor is invalid (need 1 <= m <= n)")]
    InvalidQuorum,
    #[msg("Pool account does not match the policy")]
    WrongPool,
    #[msg("Invalid custodian quorum signature")]
    InvalidQuorumSignature,
    #[msg("Unknown state root")]
    UnknownStateRoot,
    #[msg("Public signal is not in the scalar field")]
    InvalidPublicSignal,
    #[msg("Invalid disclosure proof")]
    InvalidProof,
    #[msg("BN254 group operation failed")]
    Bn128Failed,
    #[msg("BN254 pairing failed")]
    PairingFailed,
}
const VK_ALPHA_DISCLOSURE: [u8; 64] = [
    0x2d, 0x4d, 0x9a, 0xa7, 0xe3, 0x02, 0xd9, 0xdf, 0x41, 0x74, 0x9d, 0x55, 0x07, 0x94, 0x9d, 0x05,
    0xdb, 0xea, 0x33, 0xfb, 0xb1, 0x6c, 0x64, 0x3b, 0x22, 0xf5, 0x99, 0xa2, 0xbe, 0x6d, 0xf2, 0xe2,
    0x14, 0xbe, 0xdd, 0x50, 0x3c, 0x37, 0xce, 0xb0, 0x61, 0xd8, 0xec, 0x60, 0x20, 0x9f, 0xe3, 0x45,
    0xce, 0x89, 0x83, 0x0a, 0x19, 0x23, 0x03, 0x01, 0xf0, 0x76, 0xca, 0xff, 0x00, 0x4d, 0x19, 0x26,
];

const VK_BETA_DISCLOSURE: [u8; 128] = [
    0x09, 0x67, 0x03, 0x2f, 0xcb, 0xf7, 0x76, 0xd1, 0xaf, 0xc9, 0x85, 0xf8, 0x88, 0x77, 0xf1, 0x82,
    0xd3, 0x84, 0x80, 0xa6, 0x53, 0xf2, 0xde, 0xca, 0xa9, 0x79, 0x4c, 0xbc, 0x3b, 0xf3, 0x06, 0x0c,
    0x0e, 0x18, 0x78, 0x47, 0xad, 0x4c, 0x79, 0x83, 0x74, 0xd0, 0xd6, 0x73, 0x2b, 0xf5, 0x01, 0x84,
    0x7d, 0xd6, 0x8b, 0xc0, 0xe0, 0x71, 0x24, 0x1e, 0x02, 0x13, 0xbc, 0x7f, 0xc1, 0x3d, 0xb7, 0xab,
    0x30, 0x4c, 0xfb, 0xd1, 0xe0, 0x8a, 0x70, 0x4a, 0x99, 0xf5, 0xe8, 0x47, 0xd9, 0x3f, 0x8c, 0x3c,
    0xaa, 0xfd, 0xde, 0xc4, 0x6b, 0x7a, 0x0d, 0x37, 0x9d, 0xa6, 0x9a, 0x4d, 0x11, 0x23, 0x46, 0xa7,
    0x17, 0x39, 0xc1, 0xb1, 0xa4, 0x57, 0xa8, 0xc7, 0x31, 0x31, 0x23, 0xd2, 0x4d, 0x2f, 0x91, 0x92,
    0xf8, 0x96, 0xb7, 0xc6, 0x3e, 0xea, 0x05, 0xa9, 0xd5, 0x7f, 0x06, 0x54, 0x7a, 0xd0, 0xce, 0xc8,
];

const VK_GAMMA_DISCLOSURE: [u8; 128] = [
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
];

const VK_DELTA_DISCLOSURE: [u8; 128] = [
    0x15, 0xd0, 0xe8, 0x1b, 0xf7, 0x6e, 0xd8, 0x65, 0xb8, 0x69, 0x2a, 0x16, 0x6e, 0xa1, 0xbc, 0xa4,
    0xf2, 0x4c, 0x85, 0x51, 0x66, 0x4d, 0x32, 0x24, 0xf3, 0xf5, 0x2e, 0x77, 0xa8, 0xfe, 0xba, 0xef,
    0x0f, 0x70, 0xed, 0x11, 0xed, 0xc2, 0x1e, 0x8c, 0x0c, 0x59, 0xdc, 0x21, 0x7c, 0xe3, 0x25, 0x95,
    0x8e, 0x81, 0xc9, 0xd1, 0x7f, 0xb1, 0x72, 0x84, 0x09, 0x4d, 0x8b, 0x5f, 0x96, 0x82, 0x3d, 0xe9,
    0x10, 0x52, 0xc3, 0x14, 0xb7, 0xf1, 0x3f, 0x6f, 0xfd, 0x36, 0xf5, 0x13, 0x8a, 0x58, 0xcb, 0x87,
    0x73, 0x5f, 0x99, 0x4d, 0x97, 0x4c, 0x00, 0x0d, 0x2e, 0xbe, 0xa0, 0x11, 0x5b, 0x29, 0x8b, 0x77,
    0x13, 0xc5, 0x68, 0xee, 0x1a, 0x07, 0xee, 0x64, 0x8a, 0xde, 0x24, 0x17, 0x45, 0xc4, 0xfd, 0xd7,
    0xee, 0x29, 0x81, 0x3e, 0x86, 0x1d, 0xb5, 0x8e, 0x01, 0x0d, 0x32, 0xa1, 0x5c, 0xe3, 0x6d, 0xbe,
];

const VK_IC_DISCLOSURE: [[u8; 64]; 7] = [
    // IC0
    [
        0x03, 0x6c, 0x7a, 0x2b, 0xb7, 0x2d, 0x5c, 0xee, 0x12, 0xa2, 0x8e, 0x2f, 0x38, 0x37, 0x3d, 0xda,
        0xa3, 0x7a, 0xe4, 0x9e, 0x06, 0x75, 0x36, 0x60, 0x49, 0x86, 0x51, 0xb8, 0xc4, 0x6b, 0x73, 0x0d,
        0x2f, 0x56, 0x90, 0x3b, 0x62, 0xdd, 0xaa, 0xcb, 0x9a, 0x9f, 0xb6, 0xf3, 0x9b, 0xb6, 0x02, 0xdd,
        0x10, 0xbc, 0xda, 0x12, 0xaa, 0x43, 0xf6, 0xe4, 0x56, 0x26, 0xdf, 0xa4, 0x4c, 0xa7, 0x24, 0x1a,
    ],
    // IC1
    [
        0x1f, 0x71, 0xa8, 0xe4, 0xf8, 0xb7, 0x1d, 0x68, 0xb9, 0x5a, 0x1c, 0xcd, 0x2e, 0x63, 0x76, 0x9e,
        0xa7, 0xde, 0x85, 0xf7, 0x5d, 0x06, 0x75, 0xf6, 0x04, 0x52, 0x38, 0xb1, 0x19, 0x62, 0xea, 0xbe,
        0x1d, 0xc7, 0x51, 0xa7, 0x61, 0x5b, 0x02, 0x98, 0x7e, 0xb2, 0xa2, 0xa7, 0xb2, 0x97, 0x65, 0x84,
        0x45, 0xa8, 0xea, 0x14, 0xa2, 0xb9, 0xa5, 0x3a, 0xcc, 0xfe, 0x79, 0x90, 0x64, 0x74, 0x91, 0x0a,
    ],
    // IC2
    [
        0x0f, 0x38, 0xda, 0xb6, 0x22, 0x64, 0x1e, 0xbb, 0x71, 0x21, 0x60, 0xf5, 0xcd, 0x05, 0xde, 0x66,
        0x8b, 0xfa, 0x9e, 0x45, 0x08, 0x80, 0x56, 0xa1, 0x5a, 0xfe, 0xc5, 0xcc, 0xd7, 0x38, 0xde, 0xc8,
        0x24, 0x2c, 0x87, 0xe4, 0xf3, 0xd8, 0x22, 0x95, 0x3a, 0x5a, 0x01, 0x7d, 0x75, 0xd7, 0x2d, 0x2a,
        0x7a, 0xbe, 0x2b, 0xa6, 0x31, 0x4c, 0x91, 0xbe, 0xa5, 0x92, 0x2f, 0x6e, 0xe9, 0x6f, 0x24, 0xb5,
    ],
    // IC3
    [
        0x1d, 0xa3, 0x4f, 0x4d, 0xa0, 0x43, 0xe6, 0x16, 0xac, 0x00, 0x36, 0xdc, 0x89, 0x88, 0x3e, 0xef,
        0x64, 0xaf, 0xf0, 0x98, 0x06, 0x3d, 0x2c, 0x01, 0x7a, 0xe6, 0x95, 0xc6, 0x7a, 0x96, 0x7a, 0xc3,
        0x2f, 0x1a, 0x37, 0xf1, 0xff, 0x66, 0x56, 0x8d, 0x97, 0x0d, 0x2c, 0xba, 0x35, 0x15, 0x8d, 0xb5,
        0x8c, 0xe7, 0xb2, 0x4e, 0xd4, 0xba, 0x76, 0x9b, 0xde, 0xbd, 0xec, 0x2e, 0x7a, 0x9d, 0xb0, 0xdf,
    ],
    // IC4
    [
        0x19, 0x59, 0x75, 0x01, 0xf6, 0x77, 0x4a, 0xfa, 0x40, 0xe8, 0x36, 0x1b, 0xc9, 0x38, 0x1b, 0x0a,
        0xe7, 0x93, 0x14, 0x04, 0x23, 0xa2, 0x27, 0xa9, 0x11, 0x2d, 0x34, 0x89, 0x68, 0x7a, 0x3d, 0x64,
        0x2f, 0x04, 0xe8, 0x0f, 0x89, 0xde, 0x57, 0x1d, 0x0b, 0xaf, 0xff, 0x58, 0x2d, 0x54, 0xc2, 0x74,
        0xfe, 0xdb, 0xdc, 0x5e, 0x20, 0xba, 0xa5, 0xb3, 0x6a, 0xf3, 0xd1, 0x01, 0x65, 0x0b, 0xda, 0x15,
    ],
    // IC5
    [
        0x14, 0x10, 0x8b, 0xb4, 0x17, 0x7a, 0xf6, 0x55, 0xe1, 0x99, 0xdb, 0xe0, 0x65, 0x78, 0x39, 0xc1,
        0xc3, 0x2b, 0x93, 0xa5, 0x40, 0xa9, 0x10, 0x55, 0x1d, 0x1a, 0x31, 0xae, 0x07, 0xd3, 0x5e, 0x73,
        0x07, 0x45, 0x3b, 0x00, 0x49, 0x1f, 0x8f, 0xf1, 0xa1, 0x0d, 0xb8, 0xc7, 0xe3, 0xe8, 0xee, 0x80,
        0xe1, 0xe4, 0x0f, 0x81, 0x3c, 0xfb, 0xe3, 0x3f, 0xb6, 0x41, 0x2e, 0xdd, 0xf5, 0x9a, 0x5d, 0x31,
    ],
    // IC6
    [
        0x0b, 0x53, 0x96, 0xa9, 0xa9, 0x0d, 0x7d, 0x3a, 0x82, 0xce, 0x1e, 0x4b, 0xcb, 0x5e, 0x73, 0xf8,
        0x6f, 0x73, 0x4f, 0x41, 0x33, 0xa6, 0xfe, 0x7a, 0x2c, 0x88, 0x72, 0x3e, 0xe8, 0x22, 0xfb, 0x62,
        0x1b, 0x69, 0x2d, 0x24, 0xd6, 0x4f, 0x78, 0x60, 0xb1, 0x44, 0x09, 0x30, 0xfe, 0xc3, 0xa2, 0x0e,
        0xda, 0x73, 0xcc, 0xe9, 0x64, 0xf9, 0x22, 0x53, 0x37, 0x31, 0xd3, 0x47, 0x04, 0x35, 0x64, 0xa3,
    ],
];
