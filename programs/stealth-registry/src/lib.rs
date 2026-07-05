use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};

declare_id!("E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno");

/// Native Ed25519 SigVerify program address.
const ED25519_PROGRAM_ID: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");

/// Stealth Meta-Address Registry — maps Solana accounts to their stealth meta-addresses.
/// Equivalent to ERC-6538 on Ethereum. One singleton per cluster.
/// schemeId 1 = secp256k1 with view tags.
#[program]
pub mod stealth_registry {
    use super::*;

    /// Register the caller's stealth meta-address for the given scheme.
    /// Creates or updates the registry entry PDA.
    pub fn register_keys(
        ctx: Context<RegisterKeys>,
        scheme_id: u64,
        stealth_meta_address: Vec<u8>,
    ) -> Result<()> {
        require!(
            stealth_meta_address.len() == 98,
            RegistryError::InvalidMetaAddress
        );

        let entry = &mut ctx.accounts.registry_entry;
        entry.registrant = ctx.accounts.registrant.key();
        entry.scheme_id = scheme_id;
        entry.stealth_meta_address = stealth_meta_address.clone();
        entry.bump = ctx.bumps.registry_entry;

        emit!(StealthMetaAddressSet {
            registrant: ctx.accounts.registrant.key(),
            scheme_id,
            stealth_meta_address,
        });

        Ok(())
    }

    /// Register on behalf of another account (requires ED25519 signature verification).
    ///
    /// The registrant authorises the registration out-of-band by signing a canonical
    /// message with their ed25519 key; a separate `payer` then submits the transaction
    /// (gasless / relayed registration). The transaction MUST include an Ed25519
    /// SigVerify instruction over that exact message before this one; the native Ed25519
    /// program checks the signature cryptographically and this handler confirms the
    /// verified `(pubkey, message)` pair is the one it requires. The message binds the
    /// program id, registrant, scheme, current nonce, and meta-address, and the nonce is
    /// consumed on success so the signature cannot be replayed.
    pub fn register_keys_on_behalf(
        ctx: Context<RegisterKeysOnBehalf>,
        scheme_id: u64,
        stealth_meta_address: Vec<u8>,
    ) -> Result<()> {
        require!(
            stealth_meta_address.len() == 98,
            RegistryError::InvalidMetaAddress
        );

        let registrant = ctx.accounts.registrant.key();
        let current_nonce = ctx.accounts.nonce_account.nonce;

        let message = build_authorization_message(
            &registrant,
            scheme_id,
            current_nonce,
            &stealth_meta_address,
        );
        verify_ed25519_authorization(
            &ctx.accounts.instructions_sysvar.to_account_info(),
            &registrant,
            &message,
        )?;

        let entry = &mut ctx.accounts.registry_entry;
        entry.registrant = registrant;
        entry.scheme_id = scheme_id;
        entry.stealth_meta_address = stealth_meta_address.clone();
        entry.bump = ctx.bumps.registry_entry;

        // Consume the nonce so the authorising signature cannot be replayed.
        ctx.accounts.nonce_account.nonce = current_nonce
            .checked_add(1)
            .ok_or(RegistryError::InvalidSignature)?;

        emit!(StealthMetaAddressSet {
            registrant,
            scheme_id,
            stealth_meta_address,
        });

        Ok(())
    }

    /// Increment the registrant's nonce to invalidate any existing off-chain signatures.
    pub fn increment_nonce(ctx: Context<IncrementNonce>) -> Result<()> {
        let nonce_account = &mut ctx.accounts.nonce_account;
        nonce_account.nonce += 1;

        emit!(NonceIncremented {
            registrant: ctx.accounts.registrant.key(),
            new_nonce: nonce_account.nonce,
        });

        Ok(())
    }

    /// Read-only: fetch a registrant's stealth meta-address.
    /// (Clients can also read the PDA account directly.)
    pub fn resolve(ctx: Context<Resolve>) -> Result<Vec<u8>> {
        Ok(ctx.accounts.registry_entry.stealth_meta_address.clone())
    }
}

// ---------------------------------------------------------------------------
// Ed25519 authorization for register_keys_on_behalf
// ---------------------------------------------------------------------------

/// Domain tag for the canonical message the registrant signs to authorise a
/// `register_keys_on_behalf`. Bump when the message layout changes.
const REGISTER_ON_BEHALF_DOMAIN: &[u8] = b"opaque-stealth-register-on-behalf-v1";

/// Build the canonical message that `registrant` must sign. Binding the program
/// id, registrant, scheme, current nonce, and meta-address prevents the
/// signature from being reused for a different program, registrant, scheme, or
/// meta-address, and (with the monotonic nonce) from being replayed.
fn build_authorization_message(
    registrant: &Pubkey,
    scheme_id: u64,
    nonce: u64,
    stealth_meta_address: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        REGISTER_ON_BEHALF_DOMAIN.len() + 32 + 32 + 8 + 8 + stealth_meta_address.len(),
    );
    msg.extend_from_slice(REGISTER_ON_BEHALF_DOMAIN);
    msg.extend_from_slice(crate::ID.as_ref());
    msg.extend_from_slice(registrant.as_ref());
    msg.extend_from_slice(&scheme_id.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.extend_from_slice(stealth_meta_address);
    msg
}

/// Confirm the transaction contains an Ed25519 SigVerify instruction (before the
/// current instruction) proving `expected_signer` signed `expected_message`. The
/// native Ed25519 program has already verified the signature cryptographically;
/// we only re-derive that the verified `(pubkey, message)` pair is the one we
/// require and that it is carried inline in that instruction.
fn verify_ed25519_authorization(
    instructions_sysvar: &AccountInfo,
    expected_signer: &Pubkey,
    expected_message: &[u8],
) -> Result<()> {
    let current_index = load_current_index_checked(instructions_sysvar)? as usize;
    for i in 0..current_index {
        let ix = load_instruction_at_checked(i, instructions_sysvar)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        if ed25519_instruction_authorizes(&ix.data, i as u16, expected_signer, expected_message) {
            return Ok(());
        }
    }
    Err(RegistryError::InvalidSignature.into())
}

/// Parse a single-signature Ed25519 SigVerify instruction and check that it
/// verified `expected_signer` over `expected_message`, with the public key,
/// signature, and message all carried inline in this same instruction (rather
/// than borrowed from another, attacker-controlled instruction).
fn ed25519_instruction_authorizes(
    data: &[u8],
    ix_index: u16,
    expected_signer: &Pubkey,
    expected_message: &[u8],
) -> bool {
    const HEADER_LEN: usize = 16;
    const SIGNATURE_LEN: usize = 64;
    const PUBKEY_LEN: usize = 32;
    // The native/web3.js builder uses u16::MAX to mean "data lives in this ix".
    const IX_INDEX_CURRENT: u16 = u16::MAX;

    if data.len() < HEADER_LEN {
        return false;
    }
    // Exactly one signature is expected.
    if data[0] != 1 {
        return false;
    }

    let read_u16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
    let signature_offset = read_u16(2) as usize;
    let signature_ix_index = read_u16(4);
    let public_key_offset = read_u16(6) as usize;
    let public_key_ix_index = read_u16(8);
    let message_data_offset = read_u16(10) as usize;
    let message_data_size = read_u16(12) as usize;
    let message_ix_index = read_u16(14);

    let inline = |idx: u16| idx == IX_INDEX_CURRENT || idx == ix_index;
    if !inline(signature_ix_index) || !inline(public_key_ix_index) || !inline(message_ix_index) {
        return false;
    }

    let pk_end = match public_key_offset.checked_add(PUBKEY_LEN) {
        Some(v) => v,
        None => return false,
    };
    let sig_end = match signature_offset.checked_add(SIGNATURE_LEN) {
        Some(v) => v,
        None => return false,
    };
    let msg_end = match message_data_offset.checked_add(message_data_size) {
        Some(v) => v,
        None => return false,
    };
    if pk_end > data.len() || sig_end > data.len() || msg_end > data.len() {
        return false;
    }

    let pubkey = &data[public_key_offset..pk_end];
    let message = &data[message_data_offset..msg_end];
    pubkey == expected_signer.as_ref() && message == expected_message
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(scheme_id: u64)]
pub struct RegisterKeys<'info> {
    #[account(
        init_if_needed,
        payer = registrant,
        space = RegistryEntry::space(),
        seeds = [b"stealth_meta", registrant.key().as_ref(), &scheme_id.to_le_bytes()],
        bump,
    )]
    pub registry_entry: Account<'info, RegistryEntry>,

    #[account(mut)]
    pub registrant: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(scheme_id: u64)]
pub struct RegisterKeysOnBehalf<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = RegistryEntry::space(),
        seeds = [b"stealth_meta", registrant.key().as_ref(), &scheme_id.to_le_bytes()],
        bump,
    )]
    pub registry_entry: Account<'info, RegistryEntry>,

    /// The registrant whose meta-address is being set.
    /// CHECK: validated by the caller who provides the signature.
    pub registrant: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = payer,
        space = NonceAccount::SPACE,
        seeds = [b"nonce", registrant.key().as_ref()],
        bump,
    )]
    pub nonce_account: Account<'info, NonceAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,

    /// Instructions sysvar, introspected to confirm the Ed25519 SigVerify
    /// instruction that authorises this registration.
    /// CHECK: constrained to the Instructions sysvar address.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct IncrementNonce<'info> {
    #[account(
        init_if_needed,
        payer = registrant,
        space = NonceAccount::SPACE,
        seeds = [b"nonce", registrant.key().as_ref()],
        bump,
    )]
    pub nonce_account: Account<'info, NonceAccount>,

    #[account(mut)]
    pub registrant: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Resolve<'info> {
    pub registry_entry: Account<'info, RegistryEntry>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct RegistryEntry {
    pub registrant: Pubkey,
    pub scheme_id: u64,
    /// 98 bytes: compressed(V) || compressed(S) (secp256k1) || S_ed (ed25519 Solana spend key).
    pub stealth_meta_address: Vec<u8>,
    pub bump: u8,
}

impl RegistryEntry {
    pub fn space() -> usize {
        8  // discriminator
        + 32 // registrant
        + 8  // scheme_id
        + 4 + 98 // stealth_meta_address (vec prefix + 98 bytes)
        + 1  // bump
    }
}

#[account]
pub struct NonceAccount {
    pub nonce: u64,
}

impl NonceAccount {
    pub const SPACE: usize = 8 + 8; // discriminator + nonce
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct StealthMetaAddressSet {
    pub registrant: Pubkey,
    pub scheme_id: u64,
    pub stealth_meta_address: Vec<u8>,
}

#[event]
pub struct NonceIncremented {
    pub registrant: Pubkey,
    pub new_nonce: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum RegistryError {
    #[msg("Stealth meta-address must be exactly 98 bytes (compressed V + S + ed25519 S_ed)")]
    InvalidMetaAddress,
    #[msg("Invalid signature for registerKeysOnBehalf")]
    InvalidSignature,
}
