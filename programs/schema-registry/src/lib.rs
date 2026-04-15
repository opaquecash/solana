use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

declare_id!("FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB");

// ---------------------------------------------------------------------------
// Schema Registry — V2 Stealth Reputation Protocol
//
// Acts as the source of truth for attestation schemas. Only a schema's
// authority (or an explicitly added delegate) can issue attestations under
// that schema. This eliminates the V1 permissioning gap where any wallet
// could attach any trait to any announcement.
// ---------------------------------------------------------------------------

#[program]
pub mod schema_registry {
    use super::*;

    /// Register a new schema. Creates a SchemaPDA whose seeds include the
    /// authority's pubkey, so the same authority can hold many schemas.
    ///
    /// `schema_id` is computed off-chain as SHA256(authority || name || version=1)
    /// and passed in so the PDA seeds can be derived deterministically by clients.
    pub fn register_schema(
        ctx: Context<RegisterSchema>,
        schema_id: [u8; 32],
        name: String,
        field_definitions: String,
        revocable: bool,
        resolver: Option<Pubkey>,
        schema_expiry_slot: u64,
    ) -> Result<()> {
        require!(name.len() <= 64, SchemaError::NameTooLong);
        require!(
            field_definitions.len() <= 256,
            SchemaError::FieldDefsTooLong
        );

        // Verify the provided schema_id matches the canonical derivation
        let expected_id = compute_schema_id(&ctx.accounts.authority.key(), &name, 1u8);
        require!(schema_id == expected_id, SchemaError::InvalidSchemaId);

        let schema = &mut ctx.accounts.schema_pda;
        schema.bump = ctx.bumps.schema_pda;
        schema.schema_id = schema_id;
        schema.authority = ctx.accounts.authority.key();
        schema.resolver = resolver.unwrap_or_default();
        schema.revocable = revocable;
        schema.name = name.clone();
        schema.field_definitions = field_definitions.clone();
        schema.version = 1;
        schema.delegates = Vec::new();
        schema.created_at = Clock::get()?.slot;
        schema.schema_expiry_slot = schema_expiry_slot;
        schema.deprecated = false;

        emit!(SchemaRegistered {
            schema_id,
            authority: ctx.accounts.authority.key(),
            name,
            field_definitions,
            revocable,
        });

        Ok(())
    }

    /// Add a delegate issuer to a schema. Only the schema authority can call this.
    /// Delegates can issue attestations under the schema but cannot manage it.
    pub fn add_delegate(
        ctx: Context<ManageSchema>,
        delegate: Pubkey,
    ) -> Result<()> {
        let schema = &mut ctx.accounts.schema_pda;
        require!(
            schema.authority == ctx.accounts.authority.key(),
            SchemaError::Unauthorized
        );
        require!(
            schema.delegates.len() < 10,
            SchemaError::DelegateLimitReached
        );
        require!(
            !schema.delegates.contains(&delegate),
            SchemaError::DelegateAlreadyExists
        );

        schema.delegates.push(delegate);

        emit!(DelegateAdded {
            schema_id: schema.schema_id,
            delegate,
        });

        Ok(())
    }

    /// Remove a delegate issuer from a schema. Only the authority can call this.
    pub fn remove_delegate(
        ctx: Context<ManageSchema>,
        delegate: Pubkey,
    ) -> Result<()> {
        let schema = &mut ctx.accounts.schema_pda;
        require!(
            schema.authority == ctx.accounts.authority.key(),
            SchemaError::Unauthorized
        );

        let initial_len = schema.delegates.len();
        schema.delegates.retain(|d| d != &delegate);
        require!(
            schema.delegates.len() < initial_len,
            SchemaError::DelegateNotFound
        );

        emit!(DelegateRemoved {
            schema_id: schema.schema_id,
            delegate,
        });

        Ok(())
    }

    /// Update the resolver program attached to a schema.
    /// Pass `Pubkey::default()` to remove the resolver.
    pub fn update_resolver(
        ctx: Context<ManageSchema>,
        new_resolver: Pubkey,
    ) -> Result<()> {
        let schema = &mut ctx.accounts.schema_pda;
        require!(
            schema.authority == ctx.accounts.authority.key(),
            SchemaError::Unauthorized
        );

        schema.resolver = new_resolver;

        emit!(ResolverUpdated {
            schema_id: schema.schema_id,
            resolver: new_resolver,
        });

        Ok(())
    }

    /// Deprecate a schema. No new attestations will be accepted under it.
    /// Existing attestations remain valid and readable. Irreversible.
    pub fn deprecate_schema(ctx: Context<ManageSchema>) -> Result<()> {
        let schema = &mut ctx.accounts.schema_pda;
        require!(
            schema.authority == ctx.accounts.authority.key(),
            SchemaError::Unauthorized
        );
        require!(!schema.deprecated, SchemaError::AlreadyDeprecated);

        schema.deprecated = true;

        emit!(SchemaDeprecated {
            schema_id: schema.schema_id,
            deprecated_at: Clock::get()?.slot,
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonical schema_id derivation: SHA256(authority_bytes || name_bytes || [version])
pub fn compute_schema_id(authority: &Pubkey, name: &str, version: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(authority.as_ref());
    hasher.update(name.as_bytes());
    hasher.update([version]);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(schema_id: [u8; 32], name: String, field_definitions: String)]
pub struct RegisterSchema<'info> {
    #[account(
        init,
        payer = authority,
        space = SchemaPDA::MAX_SIZE,
        seeds = [
            b"schema",
            authority.key().as_ref(),
            schema_id.as_ref(),
        ],
        bump
    )]
    pub schema_pda: Account<'info, SchemaPDA>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ManageSchema<'info> {
    #[account(
        mut,
        seeds = [
            b"schema",
            authority.key().as_ref(),
            schema_pda.schema_id.as_ref(),
        ],
        bump = schema_pda.bump,
    )]
    pub schema_pda: Account<'info, SchemaPDA>,

    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct SchemaPDA {
    /// Bump seed for PDA derivation
    pub bump: u8,

    /// Globally unique schema identifier — SHA256(authority || name || version)
    pub schema_id: [u8; 32],

    /// The wallet that created this schema and holds permanent authority
    pub authority: Pubkey,

    /// Optional CPI resolver program. Pubkey::default() = no resolver.
    pub resolver: Pubkey,

    /// Whether attestations under this schema can be revoked. Immutable after registration.
    pub revocable: bool,

    /// Human-readable name, e.g. "KYC Verified". Max 64 chars.
    pub name: String,

    /// ABI-style field definitions, e.g. "bool passed, u64 score, string notes". Max 256 chars.
    pub field_definitions: String,

    /// Schema version — currently always 1 (increment on field_definitions changes).
    pub version: u8,

    /// Optional list of delegate pubkeys allowed to attest under this schema. Max 10.
    pub delegates: Vec<Pubkey>,

    /// Slot at which this schema was registered
    pub created_at: u64,

    /// Optional expiry for the schema itself. 0 = no expiry.
    /// All attestation attempts after this slot are rejected.
    pub schema_expiry_slot: u64,

    /// Whether this schema has been deprecated. Irreversible.
    pub deprecated: bool,
}

impl SchemaPDA {
    pub const MAX_SIZE: usize = 8      // discriminator
        + 1                             // bump
        + 32                            // schema_id
        + 32                            // authority
        + 32                            // resolver
        + 1                             // revocable
        + 4 + 64                        // name (vec prefix + max 64 bytes)
        + 4 + 256                       // field_definitions (vec prefix + max 256 bytes)
        + 1                             // version
        + 4 + (32 * 10)                 // delegates vec (max 10)
        + 8                             // created_at
        + 8                             // schema_expiry_slot
        + 1;                            // deprecated

    /// Returns true if the given pubkey is the authority or a registered delegate.
    pub fn is_authorized_issuer(&self, candidate: &Pubkey) -> bool {
        *candidate == self.authority || self.delegates.contains(candidate)
    }

    /// Returns true if new attestations can currently be created under this schema.
    pub fn is_active(&self, current_slot: u64) -> bool {
        !self.deprecated
            && (self.schema_expiry_slot == 0 || current_slot < self.schema_expiry_slot)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct SchemaRegistered {
    pub schema_id: [u8; 32],
    pub authority: Pubkey,
    pub name: String,
    pub field_definitions: String,
    pub revocable: bool,
}

#[event]
pub struct DelegateAdded {
    pub schema_id: [u8; 32],
    pub delegate: Pubkey,
}

#[event]
pub struct DelegateRemoved {
    pub schema_id: [u8; 32],
    pub delegate: Pubkey,
}

#[event]
pub struct ResolverUpdated {
    pub schema_id: [u8; 32],
    pub resolver: Pubkey,
}

#[event]
pub struct SchemaDeprecated {
    pub schema_id: [u8; 32],
    pub deprecated_at: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum SchemaError {
    #[msg("Schema name must be at most 64 characters")]
    NameTooLong,
    #[msg("Field definitions must be at most 256 characters")]
    FieldDefsTooLong,
    #[msg("Provided schema_id does not match SHA256(authority || name || version)")]
    InvalidSchemaId,
    #[msg("Caller is not the schema authority")]
    Unauthorized,
    #[msg("Schema already has 10 delegates (maximum)")]
    DelegateLimitReached,
    #[msg("Delegate pubkey is already registered")]
    DelegateAlreadyExists,
    #[msg("Delegate pubkey was not found in the delegates list")]
    DelegateNotFound,
    #[msg("Schema is already deprecated")]
    AlreadyDeprecated,
}
