use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    system_instruction, sysvar,
};
use solana_keccak_hasher as keccak;

declare_id!("5gfK9J8FJi3FpsQD33Hkrfwq8KqN4yadB2PDF9REnwMT");

// Opaque Name Service Solana-originated claims (spec/ONS.md 4.2). A Solana-only user
// claims `label.<parent>` by creating a provisional PDA and publishing the ONS claim
// payload to Wormhole; the canonical OpaqueNameRegistry on Ethereum applies it
// first-come-first-served (canonical-chain-wins) and its mirror publication is the
// confirmation signal. `reconcile` closes the provisional PDA against the mirror state
// (confirmed or lost), or unconditionally after the 24 h pending window (expired).

/// Wormhole Core Contract on Solana devnet (Testnet environment).
pub const WORMHOLE_CORE: Pubkey = pubkey!("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

/// Wormhole chain id stamped on this chain's messages (Solana = 1).
pub const CHAIN_ID_SOLANA: u16 = 1;

/// Pending window after which an unconfirmed claim may be reconciled as expired.
pub const PENDING_WINDOW_SECS: i64 = 24 * 60 * 60;

const PAYLOAD_VERSION: u8 = 1;
const ACTION_CLAIM: u8 = 1;

// ons-mirror OnsRecord layout: 8 (discriminator) + name_hash 32 + spend 33 + view 33 +
// eth_owner 20 = offset 126 for sol_authority; trailing bump + revoked flag.
// Keep in sync with programs/ons-mirror OnsRecord::LEN.
const MIRROR_OFF_NAME_HASH: usize = 8;
const MIRROR_OFF_SOL_AUTHORITY: usize = 126;
const MIRROR_RECORD_LEN: usize = 8 + 168;

#[program]
pub mod ons_registration {
    use super::*;

    /// Create the config: parent name in force and the mirror program whose records
    /// confirm claims.
    pub fn initialize(
        ctx: Context<Initialize>,
        parent_name: String,
        mirror_program: Pubkey,
    ) -> Result<()> {
        require!(
            !parent_name.is_empty() && parent_name.len() <= 64,
            OnsRegistrationError::InvalidParentName
        );
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.parent_name = parent_name;
        cfg.mirror_program = mirror_program;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Update the parent name / mirror program (admin only; testnet convenience).
    pub fn set_config(
        ctx: Context<SetConfig>,
        parent_name: String,
        mirror_program: Pubkey,
    ) -> Result<()> {
        require!(
            !parent_name.is_empty() && parent_name.len() <= 64,
            OnsRegistrationError::InvalidParentName
        );
        let cfg = &mut ctx.accounts.config;
        cfg.parent_name = parent_name;
        cfg.mirror_program = mirror_program;
        Ok(())
    }

    /// Claim `label.<parent>` from Solana: create the provisional PDA and publish the
    /// ONS claim payload (spec/ONS.md 5.2) through the Wormhole Core Contract. The
    /// claim is PROVISIONAL: it loses to any concurrent direct Ethereum registration.
    pub fn claim(
        ctx: Context<Claim>,
        name_hash: [u8; 32],
        label: String,
        spend_pubkey: [u8; 33],
        view_pubkey: [u8; 33],
        batch_id: u32,
        wormhole_fee: u64,
    ) -> Result<()> {
        require!(is_valid_label(label.as_bytes()), OnsRegistrationError::InvalidLabel);
        require!(
            spend_pubkey[0] == 2 || spend_pubkey[0] == 3,
            OnsRegistrationError::InvalidKey
        );
        require!(
            view_pubkey[0] == 2 || view_pubkey[0] == 3,
            OnsRegistrationError::InvalidKey
        );

        // The claim PDA seeds must bind to the label being claimed.
        let cfg = &ctx.accounts.config;
        let full_name = format!("{}.{}", label, cfg.parent_name);
        require!(
            keccak::hash(full_name.as_bytes()).to_bytes() == name_hash,
            OnsRegistrationError::NameHashMismatch
        );

        let c = &mut ctx.accounts.claim;
        c.claimer = ctx.accounts.claimer.key();
        c.name_hash = name_hash;
        c.created_at = Clock::get()?.unix_timestamp;
        c.bump = ctx.bumps.claim;

        // Emitted before the CPI so the provisional claim is observable in logs even
        // on validators without the core bridge (localnet CPI-boundary tests).
        emit!(NameClaimed {
            name_hash,
            claimer: c.claimer,
            label: label.clone(),
        });

        // Build the claim payload: version(1) action(1) sol_authority(32) spend(33)
        // view(33) label_len(1) label(L).
        let label_bytes = label.as_bytes();
        let mut payload = Vec::with_capacity(101 + label_bytes.len());
        payload.push(PAYLOAD_VERSION);
        payload.push(ACTION_CLAIM);
        payload.extend_from_slice(ctx.accounts.claimer.key().as_ref());
        payload.extend_from_slice(&spend_pubkey);
        payload.extend_from_slice(&view_pubkey);
        payload.push(label_bytes.len() as u8);
        payload.extend_from_slice(label_bytes);

        // Pay the Wormhole message fee (0 on devnet) to the fee collector.
        if wormhole_fee > 0 {
            invoke(
                &system_instruction::transfer(
                    &ctx.accounts.claimer.key(),
                    &ctx.accounts.wormhole_fee_collector.key(),
                    wormhole_fee,
                ),
                &[
                    ctx.accounts.claimer.to_account_info(),
                    ctx.accounts.wormhole_fee_collector.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                ],
            )?;
        }

        // CPI Wormhole core bridge `post_message` (instruction tag 1).
        let mut data = vec![1u8];
        data.extend_from_slice(&batch_id.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(&payload);
        data.push(1u8); // Finality::Finalized

        let ix = Instruction {
            program_id: ctx.accounts.wormhole_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.wormhole_config.key(), false),
                AccountMeta::new(ctx.accounts.wormhole_message.key(), true),
                AccountMeta::new_readonly(ctx.accounts.wormhole_emitter.key(), true),
                AccountMeta::new(ctx.accounts.wormhole_sequence.key(), false),
                AccountMeta::new(ctx.accounts.claimer.key(), true),
                AccountMeta::new(ctx.accounts.wormhole_fee_collector.key(), false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
            ],
            data,
        };

        let emitter_bump = ctx.bumps.wormhole_emitter;
        let signer_seeds: &[&[&[u8]]] = &[&[b"emitter", &[emitter_bump]]];

        invoke_signed(
            &ix,
            &[
                ctx.accounts.wormhole_config.to_account_info(),
                ctx.accounts.wormhole_message.to_account_info(),
                ctx.accounts.wormhole_emitter.to_account_info(),
                ctx.accounts.wormhole_sequence.to_account_info(),
                ctx.accounts.claimer.to_account_info(),
                ctx.accounts.wormhole_fee_collector.to_account_info(),
                ctx.accounts.clock.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
                ctx.accounts.rent.to_account_info(),
                ctx.accounts.wormhole_program.to_account_info(),
            ],
            signer_seeds,
        )?;

        Ok(())
    }

    /// Close a provisional claim against the mirror state (spec/ONS.md 6):
    /// confirmed (mirror sol_authority == claimer), lost (mirror exists for another
    /// owner), or expired (no mirror record after the pending window). Permissionless;
    /// rent always returns to the claimer.
    pub fn reconcile(ctx: Context<Reconcile>, name_hash: [u8; 32]) -> Result<()> {
        let claim = &ctx.accounts.claim;
        let mirror = &ctx.accounts.mirror_record;
        let cfg = &ctx.accounts.config;

        let outcome: u8 = if mirror.owner == &cfg.mirror_program && !mirror.data_is_empty() {
            let data = mirror.try_borrow_data()?;
            require!(data.len() == MIRROR_RECORD_LEN, OnsRegistrationError::BadMirrorRecord);
            require!(
                data[MIRROR_OFF_NAME_HASH..MIRROR_OFF_NAME_HASH + 32] == name_hash,
                OnsRegistrationError::BadMirrorRecord
            );
            let sol_authority = Pubkey::new_from_array(
                data[MIRROR_OFF_SOL_AUTHORITY..MIRROR_OFF_SOL_AUTHORITY + 32]
                    .try_into()
                    .unwrap(),
            );
            if sol_authority == claim.claimer {
                OUTCOME_CONFIRMED
            } else {
                OUTCOME_LOST
            }
        } else {
            // No mirror record: only reconcilable once the pending window has passed.
            let now = Clock::get()?.unix_timestamp;
            require!(
                now >= claim.created_at + PENDING_WINDOW_SECS,
                OnsRegistrationError::StillPending
            );
            OUTCOME_EXPIRED
        };

        emit!(ClaimReconciled {
            name_hash,
            claimer: claim.claimer,
            outcome,
        });
        Ok(())
    }
}

pub const OUTCOME_CONFIRMED: u8 = 1;
pub const OUTCOME_LOST: u8 = 2;
pub const OUTCOME_EXPIRED: u8 = 3;

/// v1 labels: [a-z0-9-]{1,63}, no leading/trailing hyphen (spec/ONS.md 1.2).
fn is_valid_label(label: &[u8]) -> bool {
    let len = label.len();
    if len == 0 || len > 63 {
        return false;
    }
    if label[0] == b'-' || label[len - 1] == b'-' {
        return false;
    }
    label
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + Config::LEN, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetConfig<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(name_hash: [u8; 32])]
pub struct Claim<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// Provisional claim; init-once, so a duplicate open claim for the same name fails.
    #[account(
        init,
        payer = claimer,
        space = 8 + ProvisionalClaim::LEN,
        seeds = [b"ons_claim", name_hash.as_ref()],
        bump,
    )]
    pub claim: Account<'info, ProvisionalClaim>,

    #[account(mut)]
    pub claimer: Signer<'info>,

    /// CHECK: this program's Wormhole emitter PDA; signed via seeds in the CPI.
    #[account(seeds = [b"emitter"], bump)]
    pub wormhole_emitter: UncheckedAccount<'info>,

    /// CHECK: Wormhole config (Bridge) PDA, owned by the core bridge.
    #[account(mut, seeds = [b"Bridge"], bump, seeds::program = wormhole_program.key())]
    pub wormhole_config: UncheckedAccount<'info>,

    /// CHECK: Wormhole fee collector PDA, owned by the core bridge.
    #[account(mut, seeds = [b"fee_collector"], bump, seeds::program = wormhole_program.key())]
    pub wormhole_fee_collector: UncheckedAccount<'info>,

    /// CHECK: Wormhole sequence tracker PDA for this emitter, owned by the core bridge.
    #[account(mut, seeds = [b"Sequence", wormhole_emitter.key().as_ref()], bump, seeds::program = wormhole_program.key())]
    pub wormhole_sequence: UncheckedAccount<'info>,

    /// CHECK: fresh message account (client keypair signer); created by the core bridge.
    #[account(mut)]
    pub wormhole_message: Signer<'info>,

    /// CHECK: Wormhole Core Contract program.
    #[account(address = WORMHOLE_CORE)]
    pub wormhole_program: UncheckedAccount<'info>,

    pub clock: Sysvar<'info, Clock>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(name_hash: [u8; 32])]
pub struct Reconcile<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [b"ons_claim", name_hash.as_ref()],
        bump = claim.bump,
        close = claimer,
    )]
    pub claim: Account<'info, ProvisionalClaim>,

    /// CHECK: rent destination; must be the recorded claimer.
    #[account(mut, address = claim.claimer)]
    pub claimer: UncheckedAccount<'info>,

    /// CHECK: the ons-mirror record PDA for this name (may be empty/nonexistent);
    /// ownership and layout are validated in the handler before any read.
    pub mirror_record: UncheckedAccount<'info>,

    pub payer: Signer<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub mirror_program: Pubkey,
    pub parent_name: String,
    pub bump: u8,
}

impl Config {
    // 4-byte string prefix + up to 64 bytes of parent name.
    pub const LEN: usize = 32 + 32 + 4 + 64 + 1;
}

#[account]
pub struct ProvisionalClaim {
    pub claimer: Pubkey,
    pub name_hash: [u8; 32],
    pub created_at: i64,
    pub bump: u8,
}

impl ProvisionalClaim {
    pub const LEN: usize = 32 + 32 + 8 + 1;
}

#[event]
pub struct NameClaimed {
    pub name_hash: [u8; 32],
    pub claimer: Pubkey,
    pub label: String,
}

#[event]
pub struct ClaimReconciled {
    pub name_hash: [u8; 32],
    pub claimer: Pubkey,
    pub outcome: u8,
}

#[error_code]
pub enum OnsRegistrationError {
    #[msg("Invalid parent name")]
    InvalidParentName,
    #[msg("Invalid label: lowercase LDH, 1-63 chars, no leading/trailing hyphen")]
    InvalidLabel,
    #[msg("Invalid compressed secp256k1 key")]
    InvalidKey,
    #[msg("name_hash does not match keccak256(label.parent_name)")]
    NameHashMismatch,
    #[msg("Mirror record does not match this name")]
    BadMirrorRecord,
    #[msg("Claim is still inside the pending window and has no mirror record")]
    StillPending,
    #[msg("Unauthorized")]
    Unauthorized,
}
