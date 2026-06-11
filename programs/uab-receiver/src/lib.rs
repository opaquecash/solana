use anchor_lang::prelude::*;

declare_id!("7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM");

// Universal Announcement Bus receiver (Solana). Reads a Wormhole VAA that was posted to the
// core bridge, checks it came from the registered cross-chain sender, and re-emits the
// 96-byte payload as a local event so Solana scanners see the other chain's announcement.
// See spec/UAB.md.

/// Wormhole Core Contract on Solana devnet (Testnet environment).
pub const WORMHOLE_CORE: Pubkey = pubkey!("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

// Posted-VAA account byte offsets (Wormhole core bridge layout).
const VAA_MAGIC: [u8; 3] = *b"vaa";
const OFF_SEQUENCE: usize = 49;
const OFF_EMITTER_CHAIN: usize = 57;
const OFF_EMITTER_ADDRESS: usize = 59;
const OFF_PAYLOAD_LEN: usize = 91;
const OFF_PAYLOAD: usize = 95;
const UAB_PAYLOAD_LEN: usize = 96;

#[program]
pub mod uab_receiver {
    use super::*;

    /// Create the config that pins the trusted cross-chain sender.
    pub fn initialize(ctx: Context<Initialize>, source_chain: u16, source_emitter: [u8; 32]) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.source_chain = source_chain;
        cfg.source_emitter = source_emitter;
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Update the trusted source emitter (admin only).
    pub fn set_source_emitter(
        ctx: Context<SetSourceEmitter>,
        source_chain: u16,
        source_emitter: [u8; 32],
    ) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.source_chain = source_chain;
        cfg.source_emitter = source_emitter;
        emit!(SourceEmitterUpdated { source_chain, source_emitter });
        Ok(())
    }

    /// Verify a posted VAA from the trusted source emitter and re-emit its payload locally.
    pub fn receive_announcement(ctx: Context<ReceiveAnnouncement>) -> Result<()> {
        let vaa = &ctx.accounts.posted_vaa;
        require_keys_eq!(*vaa.owner, WORMHOLE_CORE, UabError::NotWormholeOwned);

        let data = vaa.try_borrow_data()?;
        require!(data.len() >= OFF_PAYLOAD, UabError::MalformedVaa);
        require!(data[..3] == VAA_MAGIC, UabError::NotPostedVaa);

        let emitter_chain = u16::from_le_bytes([data[OFF_EMITTER_CHAIN], data[OFF_EMITTER_CHAIN + 1]]);
        let mut emitter_address = [0u8; 32];
        emitter_address.copy_from_slice(&data[OFF_EMITTER_ADDRESS..OFF_EMITTER_ADDRESS + 32]);

        let cfg = &ctx.accounts.config;
        require!(emitter_chain == cfg.source_chain, UabError::UnknownEmitter);
        require!(emitter_address == cfg.source_emitter, UabError::UnknownEmitter);

        let payload_len = u32::from_le_bytes([
            data[OFF_PAYLOAD_LEN],
            data[OFF_PAYLOAD_LEN + 1],
            data[OFF_PAYLOAD_LEN + 2],
            data[OFF_PAYLOAD_LEN + 3],
        ]) as usize;
        require!(payload_len == UAB_PAYLOAD_LEN, UabError::BadPayloadLength);
        require!(data.len() >= OFF_PAYLOAD + payload_len, UabError::MalformedVaa);

        let sequence = u64::from_le_bytes(data[OFF_SEQUENCE..OFF_SEQUENCE + 8].try_into().unwrap());
        let payload = data[OFF_PAYLOAD..OFF_PAYLOAD + payload_len].to_vec();

        // The `processed` PDA is init-once, so a replayed VAA fails at account creation.
        ctx.accounts.processed.bump = ctx.bumps.processed;

        emit!(CrossChainAnnouncement {
            source_chain: emitter_chain,
            source_emitter: emitter_address,
            sequence,
            payload,
        });
        Ok(())
    }
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
pub struct SetSourceEmitter<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReceiveAnnouncement<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// CHECK: posted VAA account; ownership + contents validated in the handler.
    pub posted_vaa: UncheckedAccount<'info>,

    #[account(
        init,
        payer = relayer,
        space = 8 + Processed::LEN,
        seeds = [b"processed", posted_vaa.key().as_ref()],
        bump,
    )]
    pub processed: Account<'info, Processed>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub source_chain: u16,
    pub source_emitter: [u8; 32],
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = 32 + 2 + 32 + 1;
}

#[account]
pub struct Processed {
    pub bump: u8,
}

impl Processed {
    pub const LEN: usize = 1;
}

#[event]
pub struct CrossChainAnnouncement {
    pub source_chain: u16,
    pub source_emitter: [u8; 32],
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[event]
pub struct SourceEmitterUpdated {
    pub source_chain: u16,
    pub source_emitter: [u8; 32],
}

#[error_code]
pub enum UabError {
    #[msg("Posted VAA account is not owned by the Wormhole core bridge")]
    NotWormholeOwned,
    #[msg("Account is not a posted VAA")]
    NotPostedVaa,
    #[msg("Malformed VAA account data")]
    MalformedVaa,
    #[msg("VAA is not from the configured source emitter")]
    UnknownEmitter,
    #[msg("Payload is not the expected 96-byte UAB body")]
    BadPayloadLength,
}
