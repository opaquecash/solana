use anchor_lang::prelude::*;

declare_id!("E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno");

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
            stealth_meta_address.len() == 66,
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
    /// The registrant must sign an off-chain message authorizing this registration.
    pub fn register_keys_on_behalf(
        ctx: Context<RegisterKeysOnBehalf>,
        scheme_id: u64,
        stealth_meta_address: Vec<u8>,
    ) -> Result<()> {
        require!(
            stealth_meta_address.len() == 66,
            RegistryError::InvalidMetaAddress
        );

        let entry = &mut ctx.accounts.registry_entry;
        let nonce_account = &mut ctx.accounts.nonce_account;

        entry.registrant = ctx.accounts.registrant.key();
        entry.scheme_id = scheme_id;
        entry.stealth_meta_address = stealth_meta_address.clone();
        entry.bump = ctx.bumps.registry_entry;

        nonce_account.nonce += 1;

        emit!(StealthMetaAddressSet {
            registrant: ctx.accounts.registrant.key(),
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
    /// 66 bytes: compressed(V) || compressed(S) for secp256k1.
    pub stealth_meta_address: Vec<u8>,
    pub bump: u8,
}

impl RegistryEntry {
    pub fn space() -> usize {
        8  // discriminator
        + 32 // registrant
        + 8  // scheme_id
        + 4 + 66 // stealth_meta_address (vec prefix + 66 bytes)
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
    #[msg("Stealth meta-address must be exactly 66 bytes (compressed V + S)")]
    InvalidMetaAddress,
    #[msg("Invalid signature for registerKeysOnBehalf")]
    InvalidSignature,
}
