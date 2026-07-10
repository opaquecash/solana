use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    system_instruction,
    sysvar,
};

declare_id!("HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf");

/// Wormhole Core Contract on Solana devnet (Testnet environment).
pub const WORMHOLE_CORE: Pubkey = pubkey!("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

/// Wormhole chain id of Solana (stamped into the cross-chain payload).
pub const CHAIN_ID_SOLANA: u16 = 1;

/// Upper bounds on native `announce`/`announce_with_log` payloads so a caller cannot emit an
/// unbounded event or grow an unbounded log PDA (OPQ-042e). Generous enough for any CSAP
/// stealth address and a full V2 attestation metadata (view_tag ‖ marker ‖ 4×32 = 130 bytes).
const MAX_STEALTH_ADDRESS_LEN: usize = 64;
const MAX_METADATA_LEN: usize = 512;

/// Stealth Address Announcer — emits Announcement events when something is sent
/// to a stealth address. Equivalent to ERC-5564 on Ethereum.
/// One deployment per cluster so scanners can subscribe to a single log source.
///
/// schemeId 1 = secp256k1 with view tags. metadata[0] = view tag byte;
/// remaining bytes can carry encrypted payment IDs or attestation data.
#[program]
pub mod stealth_announcer {
    use super::*;

    /// Emit an announcement so the recipient's scanner can detect the transfer.
    ///
    /// * `scheme_id` — Stealth scheme (1 = secp256k1).
    /// * `stealth_address` — The one-time stealth address (as 20-byte Ethereum-compatible
    ///   address or 32-byte Solana pubkey, stored as bytes for cross-chain flexibility).
    /// * `ephemeral_pub_key` — Compressed secp256k1 ephemeral public key (33 bytes).
    /// * `metadata` — First byte MUST be the view tag; rest is optional.
    pub fn announce(
        ctx: Context<Announce>,
        scheme_id: u64,
        stealth_address: Vec<u8>,
        ephemeral_pub_key: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<()> {
        require!(
            ephemeral_pub_key.len() == 33,
            AnnouncerError::InvalidEphemeralKey
        );
        require!(!metadata.is_empty(), AnnouncerError::MetadataMissingViewTag);
        // Bound the payload so a caller can't emit an unbounded event / grow an unbounded log
        // PDA (self-funded, but keep native announces within sane limits — OPQ-042e).
        require!(stealth_address.len() <= MAX_STEALTH_ADDRESS_LEN, AnnouncerError::InvalidStealthAddress);
        require!(metadata.len() <= MAX_METADATA_LEN, AnnouncerError::MetadataTooLong);

        emit!(Announcement {
            scheme_id,
            stealth_address,
            caller: ctx.accounts.caller.key(),
            ephemeral_pub_key,
            metadata,
        });

        Ok(())
    }

    /// Announce with an on-chain log record for indexing.
    /// Creates a small PDA so indexers can use getProgramAccounts queries
    /// in addition to parsing transaction logs.
    ///
    /// `log_id` — unique 32-byte id for this log PDA (e.g. random bytes or a hash of payload + nonce).
    pub fn announce_with_log(
        ctx: Context<AnnounceWithLog>,
        scheme_id: u64,
        stealth_address: Vec<u8>,
        ephemeral_pub_key: Vec<u8>,
        metadata: Vec<u8>,
        log_id: [u8; 32],
    ) -> Result<()> {
        require!(
            ephemeral_pub_key.len() == 33,
            AnnouncerError::InvalidEphemeralKey
        );
        require!(!metadata.is_empty(), AnnouncerError::MetadataMissingViewTag);
        // Bound the payload so a caller can't emit an unbounded event / grow an unbounded log
        // PDA (self-funded, but keep native announces within sane limits — OPQ-042e).
        require!(stealth_address.len() <= MAX_STEALTH_ADDRESS_LEN, AnnouncerError::InvalidStealthAddress);
        require!(metadata.len() <= MAX_METADATA_LEN, AnnouncerError::MetadataTooLong);

        let log = &mut ctx.accounts.announcement_log;
        log.scheme_id = scheme_id;
        log.stealth_address = stealth_address.clone();
        log.caller = ctx.accounts.caller.key();
        log.ephemeral_pub_key = ephemeral_pub_key.clone();
        log.metadata = metadata.clone();
        log.slot = Clock::get()?.slot;
        log.log_id = log_id;
        log.bump = ctx.bumps.announcement_log;

        emit!(Announcement {
            scheme_id,
            stealth_address,
            caller: ctx.accounts.caller.key(),
            ephemeral_pub_key,
            metadata,
        });

        Ok(())
    }

    /// Announce locally AND relay the announcement cross-chain via Wormhole.
    ///
    /// Emits the standard `Announcement` (so Solana scanners still see it) and publishes the
    /// 96-byte cross-chain payload (spec/payload-format.md) through the Wormhole Core Contract.
    /// `batch_id` is the Wormhole nonce; `wormhole_fee` is the current `messageFee` (0 on
    /// devnet) transferred to the fee collector before posting.
    pub fn announce_with_relay(
        ctx: Context<AnnounceWithRelay>,
        scheme_id: u64,
        stealth_address: Vec<u8>,
        ephemeral_pub_key: Vec<u8>,
        metadata: Vec<u8>,
        batch_id: u32,
        wormhole_fee: u64,
    ) -> Result<()> {
        require!(ephemeral_pub_key.len() == 33, AnnouncerError::InvalidEphemeralKey);
        require!(!metadata.is_empty(), AnnouncerError::MetadataMissingViewTag);
        // Bound the payload so a caller can't emit an unbounded event / grow an unbounded log
        // PDA (self-funded, but keep native announces within sane limits — OPQ-042e).
        require!(stealth_address.len() <= MAX_STEALTH_ADDRESS_LEN, AnnouncerError::InvalidStealthAddress);
        require!(metadata.len() <= MAX_METADATA_LEN, AnnouncerError::MetadataTooLong);
        require!(!stealth_address.is_empty() && stealth_address.len() <= 32, AnnouncerError::InvalidStealthAddress);
        require!(metadata.len() <= 25, AnnouncerError::MetadataTooLong); // view tag + 24

        // 1. Backwards-compatible local announcement.
        emit!(Announcement {
            scheme_id,
            stealth_address: stealth_address.clone(),
            caller: ctx.accounts.caller.key(),
            ephemeral_pub_key: ephemeral_pub_key.clone(),
            metadata: metadata.clone(),
        });

        // 2. Build the canonical 96-byte cross-chain payload.
        let mut payload = [0u8; 96];
        payload[0] = metadata[0]; // view tag
        payload[1..34].copy_from_slice(&ephemeral_pub_key); // 33
        let start = 66 - stealth_address.len(); // left-pad into [34..66)
        payload[start..66].copy_from_slice(&stealth_address);
        payload[66..68].copy_from_slice(&CHAIN_ID_SOLANA.to_be_bytes()); // source chain id = 1
        payload[68..72].copy_from_slice(&(scheme_id as u32).to_be_bytes()); // scheme id
        let tail = metadata.len() - 1;
        payload[72..72 + tail].copy_from_slice(&metadata[1..]); // metadata tail
        let payload = payload.to_vec();

        // 3. Pay the Wormhole message fee (0 on devnet) to the fee collector.
        if wormhole_fee > 0 {
            invoke(
                &system_instruction::transfer(
                    &ctx.accounts.caller.key(),
                    &ctx.accounts.wormhole_fee_collector.key(),
                    wormhole_fee,
                ),
                &[
                    ctx.accounts.caller.to_account_info(),
                    ctx.accounts.wormhole_fee_collector.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                ],
            )?;
        }

        // 4. CPI Wormhole core bridge `post_message` (instruction tag 1).
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
                AccountMeta::new(ctx.accounts.caller.key(), true),
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
                ctx.accounts.caller.to_account_info(),
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
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Announce<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    scheme_id: u64,
    stealth_address: Vec<u8>,
    ephemeral_pub_key: Vec<u8>,
    metadata: Vec<u8>,
    log_id: [u8; 32],
)]
pub struct AnnounceWithLog<'info> {
    #[account(
        init,
        payer = caller,
        space = AnnouncementLog::space(&stealth_address, &ephemeral_pub_key, &metadata),
        seeds = [b"announcement", caller.key().as_ref(), log_id.as_ref()],
        bump,
    )]
    pub announcement_log: Account<'info, AnnouncementLog>,

    #[account(mut)]
    pub caller: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AnnounceWithRelay<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct AnnouncementLog {
    pub scheme_id: u64,
    pub stealth_address: Vec<u8>,
    pub caller: Pubkey,
    pub ephemeral_pub_key: Vec<u8>,
    pub metadata: Vec<u8>,
    pub slot: u64,
    pub log_id: [u8; 32],
    pub bump: u8,
}

impl AnnouncementLog {
    pub fn space(
        stealth_address: &[u8],
        ephemeral_pub_key: &[u8],
        metadata: &[u8],
    ) -> usize {
        8  // discriminator
        + 8  // scheme_id
        + 4 + stealth_address.len() // stealth_address vec
        + 32 // caller
        + 4 + ephemeral_pub_key.len() // ephemeral_pub_key vec
        + 4 + metadata.len() // metadata vec
        + 8  // slot
        + 32 // log_id
        + 1  // bump
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct Announcement {
    pub scheme_id: u64,
    pub stealth_address: Vec<u8>,
    pub caller: Pubkey,
    pub ephemeral_pub_key: Vec<u8>,
    pub metadata: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum AnnouncerError {
    #[msg("Ephemeral public key must be exactly 33 bytes (compressed secp256k1)")]
    InvalidEphemeralKey,
    #[msg("Metadata must contain at least the view tag byte")]
    MetadataMissingViewTag,
    #[msg("Stealth address must be 1..=32 bytes")]
    InvalidStealthAddress,
    #[msg("Metadata exceeds the 24-byte cross-chain payload budget")]
    MetadataTooLong,
}
