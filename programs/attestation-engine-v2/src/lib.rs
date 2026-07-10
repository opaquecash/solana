use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

declare_id!("4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM");

// ---------------------------------------------------------------------------
// Attestation Engine V2 — Stealth Reputation Protocol
//
// Issues and revokes attestations that are anchored to a registered schema.
// Every attestation records the issuer (must be schema authority or delegate),
// supports optional expiration, and preserves data on revocation for auditability.
//
// The resolver CPI hook allows schema creators to gate attestation issuance
// with arbitrary logic (payments, whitelists, NFT ownership, etc.).
// ---------------------------------------------------------------------------

/// Maximum payload bytes stored in an attestation.
const MAX_DATA_LEN: usize = 512;

#[program]
pub mod attestation_engine_v2 {
    use super::*;

    /// Issue an attestation under a registered schema.
    ///
    /// Permission check: the signer must be the schema authority or a delegate.
    /// The schema must not be deprecated or expired.
    /// If the schema has a resolver, a CPI hook is fired — any error reverts the tx.
    pub fn attest(
        ctx: Context<Attest>,
        stealth_address_hash: [u8; 32],
        data: Vec<u8>,
        expiration_slot: u64,
        ref_uid: [u8; 32],
    ) -> Result<()> {
        // Only the byte length is enforced on-chain; the engine does NOT validate `data`
        // against the schema's `field_definitions`. Data-shape conformance is intentionally the
        // issuer's (at write) and consumer's (at read) responsibility — documented so an
        // integrator does not assume on-chain schema validation (OPQ-042d).
        require!(data.len() <= MAX_DATA_LEN, AttestationError::DataTooLarge);

        let schema = &ctx.accounts.schema_pda;
        let issuer = ctx.accounts.issuer.key();
        let current_slot = Clock::get()?.slot;

        // Core permission check — this is the key V2 invariant
        require!(
            schema.is_authorized_issuer(&issuer),
            AttestationError::UnauthorizedIssuer
        );

        // Schema must be active (not deprecated, not expired)
        require!(
            schema.is_active(current_slot),
            AttestationError::SchemaInactive
        );

        // Build the attestation UID: SHA256(schema_id || issuer || stealth_address_hash || slot)
        let uid = compute_attestation_uid(
            &schema.schema_id,
            &issuer,
            &stealth_address_hash,
            current_slot,
        );

        let attestation = &mut ctx.accounts.attestation_pda;
        // With init_if_needed this PDA may already hold a prior attestation for the same
        // (schema, issuer, subject). Only overwrite it when that prior one is revoked or
        // expired — never clobber a still-live attestation (OPQ-026). A fresh account has a
        // zero uid.
        if attestation.uid != [0u8; 32] {
            let revoked = attestation.revocation_slot != 0;
            let expired = attestation.expiration_slot != 0 && current_slot >= attestation.expiration_slot;
            require!(revoked || expired, AttestationError::AttestationStillLive);
        }
        attestation.bump = ctx.bumps.attestation_pda;
        attestation.uid = uid;
        attestation.schema_pda = schema.key();
        attestation.schema_id = schema.schema_id;
        attestation.issuer = issuer;
        attestation.stealth_address_hash = stealth_address_hash;
        attestation.data = data;
        attestation.created_at = current_slot;
        attestation.expiration_slot = expiration_slot;
        attestation.revocation_slot = 0;
        attestation.ref_uid = ref_uid;

        // Resolver CPI hook — if configured on the schema
        // The resolver can reject the attestation by returning an error, which reverts the tx.
        // We clone all data we need BEFORE taking the mutable borrow so the borrow checker
        // doesn't complain about mixed mutable/immutable borrows on ctx.accounts.
        let resolver_key = schema.resolver;
        let schema_id_val = schema.schema_id;
        let data_clone = attestation.data.clone();

        if resolver_key != Pubkey::default() {
            let resolver_program = ctx.accounts.resolver_program
                .as_ref()
                .ok_or(AttestationError::MissingResolverProgram)?;

            // Validate the program ID matches what the schema declares
            require!(
                resolver_program.key() == resolver_key,
                AttestationError::ResolverMismatch
            );
            // …and that it is actually executable, so a mis-set non-program resolver fails
            // fast with a clear error instead of an opaque CPI failure (OPQ-042b).
            require!(
                resolver_program.executable,
                AttestationError::ResolverMismatch
            );

            fire_resolver_on_attest(
                &resolver_program.to_account_info(),
                &ctx.accounts.schema_pda.to_account_info(),
                &ctx.accounts.attestation_pda.to_account_info(),
                &ctx.accounts.issuer.to_account_info(),
                uid,
                schema_id_val,
                stealth_address_hash,
                &data_clone,
            )?;
        }

        emit!(AttestationCreated {
            uid,
            schema_id: schema.schema_id,
            issuer,
            stealth_address_hash,
            expiration_slot,
            created_at: current_slot,
        });

        Ok(())
    }

    /// Revoke an attestation. Only the schema authority can revoke (not delegates).
    /// The schema must have `revocable = true`.
    ///
    /// Data is preserved — the revocation_slot is set to the current slot,
    /// making the on-chain history fully auditable.
    pub fn revoke(
        ctx: Context<Revoke>,
        _attestation_uid: [u8; 32],
    ) -> Result<()> {
        // Extract everything we need BEFORE taking any borrows on the accounts
        let schema_key = ctx.accounts.schema_pda.key();
        let revoker = ctx.accounts.revoker.key();
        let resolver_key_rev = ctx.accounts.schema_pda.resolver;
        let schema_id_rev = ctx.accounts.schema_pda.schema_id;
        let att_uid_rev = ctx.accounts.attestation_pda.uid;
        let att_issuer = ctx.accounts.attestation_pda.issuer;
        let att_schema_pda_ref = ctx.accounts.attestation_pda.schema_pda;

        // Only the authority can revoke — not delegates
        require!(
            revoker == ctx.accounts.schema_pda.authority,
            AttestationError::OnlyAuthorityCanRevoke
        );
        require!(ctx.accounts.schema_pda.revocable, AttestationError::SchemaNotRevocable);
        require!(
            ctx.accounts.attestation_pda.revocation_slot == 0,
            AttestationError::AlreadyRevoked
        );
        require!(att_schema_pda_ref == schema_key, AttestationError::SchemaMismatch);

        let current_slot = Clock::get()?.slot;

        // Record revocation — DATA IS NOT DELETED for auditability
        ctx.accounts.attestation_pda.revocation_slot = current_slot;

        // Resolver CPI hook for revocation — must happen after writing the slot but we
        // pass only pre-cloned account infos so there's no borrow conflict.
        if resolver_key_rev != Pubkey::default() {
            let resolver_program = ctx.accounts.resolver_program
                .as_ref()
                .ok_or(AttestationError::MissingResolverProgram)?;

            require!(
                resolver_program.key() == resolver_key_rev,
                AttestationError::ResolverMismatch
            );
            require!(
                resolver_program.executable,
                AttestationError::ResolverMismatch
            );

            let resolver_ai = resolver_program.to_account_info();
            let schema_ai = ctx.accounts.schema_pda.to_account_info();
            let attestation_ai = ctx.accounts.attestation_pda.to_account_info();

            fire_resolver_on_revoke(
                &resolver_ai,
                &schema_ai,
                &attestation_ai,
                att_uid_rev,
                schema_id_rev,
                current_slot,
            )?;
        }

        emit!(AttestationRevoked {
            uid: att_uid_rev,
            schema_id: schema_id_rev,
            issuer: att_issuer,
            revocation_slot: current_slot,
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Resolver CPI helpers
//
// The resolver interface uses fixed 8-byte discriminators so any resolver
// program can implement the same interface without an IDL dependency.
// We use anchor_lang::solana_program to stay on the same version as Anchor.
// ---------------------------------------------------------------------------

use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

const ON_ATTEST_DISCRIMINATOR: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const ON_REVOKE_DISCRIMINATOR: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[allow(clippy::too_many_arguments)]
fn fire_resolver_on_attest<'a>(
    resolver_program: &AccountInfo<'a>,
    schema_account: &AccountInfo<'a>,
    attestation_account: &AccountInfo<'a>,
    issuer_account: &AccountInfo<'a>,
    attestation_uid: [u8; 32],
    schema_id: [u8; 32],
    stealth_address_hash: [u8; 32],
    data: &[u8],
) -> Result<()> {
    let mut ix_data = Vec::with_capacity(8 + 32 + 32 + 32 + 32 + 4 + data.len());
    ix_data.extend_from_slice(&ON_ATTEST_DISCRIMINATOR);
    ix_data.extend_from_slice(&schema_id);
    ix_data.extend_from_slice(issuer_account.key.as_ref());
    ix_data.extend_from_slice(&stealth_address_hash);
    ix_data.extend_from_slice(&attestation_uid);
    ix_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
    ix_data.extend_from_slice(data);

    let ix = Instruction {
        program_id: *resolver_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*schema_account.key, false),
            AccountMeta::new_readonly(*attestation_account.key, false),
            AccountMeta::new_readonly(*issuer_account.key, true),
        ],
        data: ix_data,
    };

    invoke(
        &ix,
        &[
            resolver_program.clone(),
            schema_account.clone(),
            attestation_account.clone(),
            issuer_account.clone(),
        ],
    )
    .map_err(|_| error!(AttestationError::ResolverRejected))
}

fn fire_resolver_on_revoke<'a>(
    resolver_program: &AccountInfo<'a>,
    schema_account: &AccountInfo<'a>,
    attestation_account: &AccountInfo<'a>,
    attestation_uid: [u8; 32],
    schema_id: [u8; 32],
    revocation_slot: u64,
) -> Result<()> {
    let mut ix_data = Vec::with_capacity(8 + 32 + 32 + 8);
    ix_data.extend_from_slice(&ON_REVOKE_DISCRIMINATOR);
    ix_data.extend_from_slice(&schema_id);
    ix_data.extend_from_slice(&attestation_uid);
    ix_data.extend_from_slice(&revocation_slot.to_le_bytes());

    let ix = Instruction {
        program_id: *resolver_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*schema_account.key, false),
            AccountMeta::new_readonly(*attestation_account.key, false),
        ],
        data: ix_data,
    };

    invoke(
        &ix,
        &[
            resolver_program.clone(),
            schema_account.clone(),
            attestation_account.clone(),
        ],
    )
    .map_err(|_| error!(AttestationError::ResolverRejected))
}

// ---------------------------------------------------------------------------
// UID computation
// ---------------------------------------------------------------------------

fn compute_attestation_uid(
    schema_id: &[u8; 32],
    issuer: &Pubkey,
    stealth_address_hash: &[u8; 32],
    slot: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(schema_id);
    hasher.update(issuer.as_ref());
    hasher.update(stealth_address_hash);
    hasher.update(slot.to_le_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Account structs
// ---------------------------------------------------------------------------

// The attestation engine reads the real `SchemaPDA` account type from the schema_registry
// crate (below), validated by owner + discriminator via Anchor's `Account<'info, SchemaPDA>`.
// A hand-mirrored `SchemaPDARef` plain struct used to live here; it was dead code whose comment
// invited future raw deserialization that would bypass those checks — removed (OPQ-042c).

// Reuse the schema_registry SchemaPDA account type directly via the extern crate.
// The attestation engine reads SchemaPDA accounts owned by schema_registry::ID.
use schema_registry::SchemaPDA;

#[derive(Accounts)]
#[instruction(stealth_address_hash: [u8; 32])]
pub struct Attest<'info> {
    /// The schema this attestation is issued under. Must be owned by schema_registry.
    #[account(
        constraint = schema_pda.is_authorized_issuer(&issuer.key()) @ AttestationError::UnauthorizedIssuer,
        constraint = schema_pda.is_active(Clock::get().unwrap().slot) @ AttestationError::SchemaInactive,
    )]
    pub schema_pda: Account<'info, SchemaPDA>,

    /// The attestation account.
    /// Seeds: ["attestation_v2", schema_id, issuer, stealth_address_hash]
    /// `init_if_needed` so a credential can be RE-ISSUED to the same (schema, issuer, subject)
    /// after the prior attestation was revoked or expired; the handler guards overwrite so a
    /// still-live attestation is never clobbered (OPQ-026).
    #[account(
        init_if_needed,
        payer = issuer,
        space = AttestationPDA::MAX_SIZE,
        seeds = [
            b"attestation_v2",
            schema_pda.schema_id.as_ref(),
            issuer.key().as_ref(),
            stealth_address_hash.as_ref(),
        ],
        bump
    )]
    pub attestation_pda: Account<'info, AttestationPDA>,

    #[account(mut)]
    pub issuer: Signer<'info>,

    /// Optional resolver program. Required when schema.resolver != Pubkey::default().
    /// CHECK: address is validated against schema_pda.resolver inside the instruction.
    pub resolver_program: Option<UncheckedAccount<'info>>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(attestation_uid: [u8; 32])]
pub struct Revoke<'info> {
    #[account(
        constraint = schema_pda.authority == revoker.key() @ AttestationError::OnlyAuthorityCanRevoke,
        constraint = schema_pda.revocable @ AttestationError::SchemaNotRevocable,
    )]
    pub schema_pda: Account<'info, SchemaPDA>,

    #[account(
        mut,
        seeds = [
            b"attestation_v2",
            attestation_pda.schema_id.as_ref(),
            attestation_pda.issuer.as_ref(),
            attestation_pda.stealth_address_hash.as_ref(),
        ],
        bump = attestation_pda.bump,
        constraint = attestation_pda.uid == attestation_uid @ AttestationError::AttestationNotFound,
        constraint = attestation_pda.revocation_slot == 0 @ AttestationError::AlreadyRevoked,
    )]
    pub attestation_pda: Account<'info, AttestationPDA>,

    pub revoker: Signer<'info>,

    /// Optional resolver program for revocation hook.
    /// CHECK: address is validated against schema_pda.resolver inside the instruction.
    pub resolver_program: Option<UncheckedAccount<'info>>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct AttestationPDA {
    pub bump: u8,

    /// Unique UID: SHA256(schema_id || issuer || stealth_address_hash || slot)
    pub uid: [u8; 32],

    /// Reference to the SchemaPDA this was issued under (on-chain pointer)
    pub schema_pda: Pubkey,

    /// schema_id cached here so the ZK verifier can validate it without
    /// loading the schema account a second time.
    pub schema_id: [u8; 32],

    /// The wallet that issued this attestation — must be authority or delegate
    pub issuer: Pubkey,

    /// Privacy-preserving stealth address reference.
    /// The full stealth address is in the encrypted announcement; only the hash is stored here.
    pub stealth_address_hash: [u8; 32],

    /// ABI-encoded payload conforming to schema field_definitions. Max 512 bytes.
    pub data: Vec<u8>,

    /// Slot when this attestation was created
    pub created_at: u64,

    /// 0 = no expiry. Attestation is expired when current_slot >= expiration_slot.
    pub expiration_slot: u64,

    /// 0 = not revoked. Non-zero = slot when revoked. Data preserved for auditability.
    pub revocation_slot: u64,

    /// Optional reference to a prior attestation UID (for chained credentials). Zero = none.
    pub ref_uid: [u8; 32],
}

impl AttestationPDA {
    pub const MAX_SIZE: usize = 8      // discriminator
        + 1                             // bump
        + 32                            // uid
        + 32                            // schema_pda
        + 32                            // schema_id
        + 32                            // issuer
        + 32                            // stealth_address_hash
        + 4 + MAX_DATA_LEN              // data vec
        + 8                             // created_at
        + 8                             // expiration_slot
        + 8                             // revocation_slot
        + 32;                           // ref_uid

    /// Returns true if this attestation is currently valid (not revoked, not expired).
    pub fn is_valid(&self, current_slot: u64) -> bool {
        self.revocation_slot == 0
            && (self.expiration_slot == 0 || current_slot < self.expiration_slot)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct AttestationCreated {
    pub uid: [u8; 32],
    pub schema_id: [u8; 32],
    pub issuer: Pubkey,
    pub stealth_address_hash: [u8; 32],
    pub expiration_slot: u64,
    pub created_at: u64,
}

#[event]
pub struct AttestationRevoked {
    pub uid: [u8; 32],
    pub schema_id: [u8; 32],
    pub issuer: Pubkey,
    pub revocation_slot: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum AttestationError {
    #[msg("Caller is not the schema authority or a registered delegate")]
    UnauthorizedIssuer,
    #[msg("Schema is deprecated or expired — no new attestations accepted")]
    SchemaInactive,
    #[msg("Attestation data exceeds 512-byte maximum")]
    DataTooLarge,
    #[msg("Only the schema authority can revoke attestations")]
    OnlyAuthorityCanRevoke,
    #[msg("Schema is not marked as revocable")]
    SchemaNotRevocable,
    #[msg("Attestation has already been revoked")]
    AlreadyRevoked,
    #[msg("Schema on attestation does not match provided schema PDA")]
    SchemaMismatch,
    #[msg("Resolver program account is required but was not provided")]
    MissingResolverProgram,
    #[msg("Resolver program address does not match the schema's registered resolver")]
    ResolverMismatch,
    #[msg("Resolver rejected the attestation or revocation")]
    ResolverRejected,
    #[msg("Attestation UID does not match the attestation_pda account")]
    AttestationNotFound,
    #[msg("An existing attestation for this subject is still live; revoke or let it expire before re-issuing")]
    AttestationStillLive,
}
