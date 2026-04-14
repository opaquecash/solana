use anchor_lang::prelude::*;

declare_id!("BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM");

/// Maximum age of a Merkle root (in seconds) before it's considered stale.
const ROOT_EXPIRY_SECS: i64 = 3600; // 1 hour

/// Maximum number of roots kept in history.
const MAX_ROOT_HISTORY: usize = 100;

/// OpaqueReputationVerifier — on-chain verifier for Stealth Attestation ZK-SNARK proofs.
/// Accepts Groth16 proofs that a user owns a stealth address with a specific
/// attestation without revealing the address.
///
/// Uses a nullifier registry to prevent Sybil attacks (same key + same action = same nullifier).
/// The Merkle root is validated against recent roots stored by the admin.
#[program]
pub mod reputation_verifier {
    use super::*;

    /// Initialize the verifier config. Called once after deployment.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.groth16_verifier = ctx.accounts.groth16_program.key();
        config.bump = ctx.bumps.config;
        Ok(())
    }

    /// Submit a new Merkle root from the announcement tree.
    /// Called by the admin/relayer after indexing new announcements.
    pub fn update_merkle_root(ctx: Context<UpdateMerkleRoot>, root: [u8; 32]) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(
            ctx.accounts.admin.key() == config.admin,
            ReputationError::Unauthorized
        );

        let root_entry = &mut ctx.accounts.root_entry;
        root_entry.root = root;
        root_entry.timestamp = Clock::get()?.unix_timestamp;
        root_entry.bump = ctx.bumps.root_entry;

        let history = &mut ctx.accounts.root_history;
        if history.roots.len() >= MAX_ROOT_HISTORY {
            history.roots.remove(0);
        }
        history.roots.push(root);

        emit!(MerkleRootUpdated {
            root,
            slot: Clock::get()?.slot,
        });

        Ok(())
    }

    /// Verify a Stealth Attestation ZK-SNARK proof.
    ///
    /// Public signals layout (matching the Circom circuit):
    ///   [0] nullifier           (circuit output)
    ///   [1] is_valid            (circuit output, must be 1)
    ///   [2] merkle_root         (public input)
    ///   [3] attestation_id      (public input)
    ///   [4] external_nullifier  (public input)
    pub fn verify_reputation(
        ctx: Context<VerifyReputation>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        root: [u8; 32],
        attestation_id: u64,
        external_nullifier: u64,
        nullifier: [u8; 32],
    ) -> Result<()> {
        // Check root is valid and not expired
        let root_entry = &ctx.accounts.root_entry;
        let now = Clock::get()?.unix_timestamp;
        require!(
            (now - root_entry.timestamp) <= ROOT_EXPIRY_SECS,
            ReputationError::RootExpired
        );

        // Build public signals array
        let mut pub_signals = [[0u8; 32]; 5];
        pub_signals[0] = nullifier;
        pub_signals[1] = {
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        };
        pub_signals[2] = root;
        pub_signals[3] = u64_to_be32(attestation_id);
        pub_signals[4] = u64_to_be32(external_nullifier);

        // CPI to the Groth16 verifier
        let cpi_program = ctx.accounts.groth16_program.to_account_info();
        let cpi_accounts = groth16_verifier::cpi::accounts::VerifyProof {
            caller: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        let valid = groth16_verifier::cpi::verify_proof(
            cpi_ctx,
            proof_a,
            proof_b,
            proof_c,
            pub_signals,
        )?;

        require!(
            valid.get(),
            ReputationError::InvalidProof
        );

        // Mark nullifier as used
        let nullifier_entry = &mut ctx.accounts.nullifier_entry;
        nullifier_entry.used = true;
        nullifier_entry.bump = ctx.bumps.nullifier_entry;

        emit!(ReputationVerified {
            attestation_id,
            nullifier,
            verifier: ctx.accounts.user.key(),
            merkle_root: root,
        });

        Ok(())
    }

    /// Read-only verification (does not consume the nullifier).
    /// Returns true if the proof would be valid.
    pub fn verify_reputation_view(
        ctx: Context<VerifyReputationView>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        root: [u8; 32],
        attestation_id: u64,
        external_nullifier: u64,
        nullifier: [u8; 32],
    ) -> Result<bool> {
        let root_entry = &ctx.accounts.root_entry;
        let now = Clock::get()?.unix_timestamp;
        if (now - root_entry.timestamp) > ROOT_EXPIRY_SECS {
            return Ok(false);
        }

        let mut pub_signals = [[0u8; 32]; 5];
        pub_signals[0] = nullifier;
        pub_signals[1] = {
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        };
        pub_signals[2] = root;
        pub_signals[3] = u64_to_be32(attestation_id);
        pub_signals[4] = u64_to_be32(external_nullifier);

        let cpi_program = ctx.accounts.groth16_program.to_account_info();
        let cpi_accounts = groth16_verifier::cpi::accounts::VerifyProof {
            caller: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        let valid = groth16_verifier::cpi::verify_proof(
            cpi_ctx,
            proof_a,
            proof_b,
            proof_c,
            pub_signals,
        )?;

        Ok(valid.get())
    }

    /// Transfer admin role. Use Pubkey::default() to renounce.
    pub fn transfer_admin(ctx: Context<TransferAdmin>, new_admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(
            ctx.accounts.admin.key() == config.admin,
            ReputationError::Unauthorized
        );
        config.admin = new_admin;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn u64_to_be32(val: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&val.to_be_bytes());
    bytes
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = VerifierConfig::SPACE,
        seeds = [b"verifier_config"],
        bump,
    )]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        init,
        payer = admin,
        space = RootHistory::SPACE,
        seeds = [b"root_history"],
        bump,
    )]
    pub root_history: Account<'info, RootHistory>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: The Groth16 verifier program ID.
    pub groth16_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(root: [u8; 32])]
pub struct UpdateMerkleRoot<'info> {
    #[account(seeds = [b"verifier_config"], bump = config.bump)]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        init_if_needed,
        payer = admin,
        space = MerkleRootEntry::SPACE,
        seeds = [b"merkle_root", root.as_ref()],
        bump,
    )]
    pub root_entry: Account<'info, MerkleRootEntry>,

    #[account(
        mut,
        seeds = [b"root_history"],
        bump,
    )]
    pub root_history: Account<'info, RootHistory>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    root: [u8; 32],
    attestation_id: u64,
    external_nullifier: u64,
    nullifier: [u8; 32],
)]
pub struct VerifyReputation<'info> {
    #[account(seeds = [b"verifier_config"], bump = config.bump)]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        seeds = [b"merkle_root", root.as_ref()],
        bump = root_entry.bump,
    )]
    pub root_entry: Account<'info, MerkleRootEntry>,

    #[account(
        init,
        payer = user,
        space = NullifierEntry::SPACE,
        seeds = [b"nullifier", nullifier.as_ref()],
        bump,
    )]
    pub nullifier_entry: Account<'info, NullifierEntry>,

    /// CHECK: The Groth16 verifier program (validated against config).
    #[account(address = config.groth16_verifier)]
    pub groth16_program: UncheckedAccount<'info>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    root: [u8; 32],
    attestation_id: u64,
    external_nullifier: u64,
    nullifier: [u8; 32],
)]
pub struct VerifyReputationView<'info> {
    #[account(seeds = [b"verifier_config"], bump = config.bump)]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        seeds = [b"merkle_root", root.as_ref()],
        bump = root_entry.bump,
    )]
    pub root_entry: Account<'info, MerkleRootEntry>,

    /// CHECK: The Groth16 verifier program.
    #[account(address = config.groth16_verifier)]
    pub groth16_program: UncheckedAccount<'info>,

    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferAdmin<'info> {
    #[account(mut, seeds = [b"verifier_config"], bump = config.bump)]
    pub config: Account<'info, VerifierConfig>,

    pub admin: Signer<'info>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct VerifierConfig {
    pub admin: Pubkey,
    pub groth16_verifier: Pubkey,
    pub bump: u8,
}

impl VerifierConfig {
    pub const SPACE: usize = 8 + 32 + 32 + 1;
}

#[account]
pub struct MerkleRootEntry {
    pub root: [u8; 32],
    pub timestamp: i64,
    pub bump: u8,
}

impl MerkleRootEntry {
    pub const SPACE: usize = 8 + 32 + 8 + 1;
}

#[account]
pub struct NullifierEntry {
    pub used: bool,
    pub bump: u8,
}

impl NullifierEntry {
    pub const SPACE: usize = 8 + 1 + 1;
}

#[account]
pub struct RootHistory {
    pub roots: Vec<[u8; 32]>,
}

impl RootHistory {
    // 8 (discriminator) + 4 (vec len) + 100 * 32 (max roots)
    pub const SPACE: usize = 8 + 4 + (MAX_ROOT_HISTORY * 32);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct ReputationVerified {
    pub attestation_id: u64,
    pub nullifier: [u8; 32],
    pub verifier: Pubkey,
    pub merkle_root: [u8; 32],
}

#[event]
pub struct MerkleRootUpdated {
    pub root: [u8; 32],
    pub slot: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum ReputationError {
    #[msg("Invalid Groth16 proof")]
    InvalidProof,
    #[msg("Nullifier has already been used")]
    NullifierAlreadyUsed,
    #[msg("Invalid or unregistered Merkle root")]
    InvalidMerkleRoot,
    #[msg("Merkle root has expired")]
    RootExpired,
    #[msg("Unauthorized: caller is not the admin")]
    Unauthorized,
}
