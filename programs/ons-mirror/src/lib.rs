use anchor_lang::prelude::*;

declare_id!("D7EXuwcsGrUAYC6k69jrKvsKethsKYgR1pokkTcFvWsk");

// Opaque Name Service mirror (Solana). Holds one read-only PDA per ONS name, written
// exclusively from Wormhole VAAs emitted by the canonical OpaqueNameRegistry on Ethereum.
// A Phantom sender resolves `alice.opq.eth` by deriving the PDA from
// keccak256(full name) client-side and reading a single account — no Ethereum RPC.
// Consistency is eventually consistent, canonical-chain-wins (spec/ONS.md).

/// Wormhole Core Contract on Solana devnet (Testnet environment).
pub const WORMHOLE_CORE: Pubkey = pubkey!("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

// Posted-VAA account byte offsets (Wormhole core bridge layout).
const VAA_MAGIC: [u8; 3] = *b"vaa";
const OFF_SEQUENCE: usize = 49;
const OFF_EMITTER_CHAIN: usize = 57;
const OFF_EMITTER_ADDRESS: usize = 59;
const OFF_PAYLOAD_LEN: usize = 91;
const OFF_PAYLOAD: usize = 95;

// ONS mirror payload (spec/ONS.md 5.1): version(1) action(1) name_hash(32) spend(33)
// view(33) eth_owner(32, left-padded 20-byte address) sol_authority(32) = 164 bytes.
const ONS_PAYLOAD_LEN: usize = 164;
const PAYLOAD_VERSION: u8 = 1;
const ACTION_UPSERT: u8 = 1;
const ACTION_REVOKE: u8 = 2;

#[program]
pub mod ons_mirror {
    use super::*;

    /// Create the config that pins the canonical Ethereum registry emitter.
    pub fn initialize(
        ctx: Context<Initialize>,
        source_chain: u16,
        source_emitter: [u8; 32],
    ) -> Result<()> {
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

    /// Apply an ONS mirror payload from a posted VAA: upsert (or close, on revoke) the
    /// record PDA for `name_hash`. The PDA is the only write path; stale or replayed
    /// updates are rejected by the per-VAA `processed` account and the monotonic
    /// Wormhole sequence stored on the record.
    pub fn receive_record(ctx: Context<ReceiveRecord>, name_hash: [u8; 32]) -> Result<()> {
        let vaa = &ctx.accounts.posted_vaa;
        require_keys_eq!(*vaa.owner, WORMHOLE_CORE, OnsMirrorError::NotWormholeOwned);

        let data = vaa.try_borrow_data()?;
        require!(data.len() >= OFF_PAYLOAD, OnsMirrorError::MalformedVaa);
        require!(data[..3] == VAA_MAGIC, OnsMirrorError::NotPostedVaa);

        let emitter_chain =
            u16::from_le_bytes([data[OFF_EMITTER_CHAIN], data[OFF_EMITTER_CHAIN + 1]]);
        let mut emitter_address = [0u8; 32];
        emitter_address.copy_from_slice(&data[OFF_EMITTER_ADDRESS..OFF_EMITTER_ADDRESS + 32]);

        let cfg = &ctx.accounts.config;
        require!(emitter_chain == cfg.source_chain, OnsMirrorError::UnknownEmitter);
        require!(emitter_address == cfg.source_emitter, OnsMirrorError::UnknownEmitter);

        let payload_len = u32::from_le_bytes([
            data[OFF_PAYLOAD_LEN],
            data[OFF_PAYLOAD_LEN + 1],
            data[OFF_PAYLOAD_LEN + 2],
            data[OFF_PAYLOAD_LEN + 3],
        ]) as usize;
        require!(payload_len == ONS_PAYLOAD_LEN, OnsMirrorError::BadPayloadLength);
        require!(data.len() >= OFF_PAYLOAD + payload_len, OnsMirrorError::MalformedVaa);

        let payload = &data[OFF_PAYLOAD..OFF_PAYLOAD + payload_len];
        require!(payload[0] == PAYLOAD_VERSION, OnsMirrorError::BadPayloadVersion);
        let action = payload[1];
        require!(
            action == ACTION_UPSERT || action == ACTION_REVOKE,
            OnsMirrorError::BadAction
        );

        // The record PDA seeds must bind to the payload's name, not the relayer's word.
        require!(payload[2..34] == name_hash, OnsMirrorError::NameHashMismatch);

        let sequence =
            u64::from_le_bytes(data[OFF_SEQUENCE..OFF_SEQUENCE + 8].try_into().unwrap());

        let record = &mut ctx.accounts.record;
        // A pre-existing record only moves forward in sequence (out-of-order delivery).
        if record.name_hash == name_hash {
            require!(sequence > record.wormhole_sequence, OnsMirrorError::StaleSequence);
        }

        ctx.accounts.processed.bump = ctx.bumps.processed;

        if action == ACTION_REVOKE {
            emit!(NameRecordRevoked { name_hash, sequence });
            record.close(ctx.accounts.relayer.to_account_info())?;
            return Ok(());
        }

        record.name_hash = name_hash;
        record.spend_pubkey.copy_from_slice(&payload[34..67]);
        record.view_pubkey.copy_from_slice(&payload[67..100]);
        record.eth_owner.copy_from_slice(&payload[112..132]); // low 20 bytes of the padded word
        record.sol_authority = Pubkey::new_from_array(payload[132..164].try_into().unwrap());
        record.wormhole_sequence = sequence;
        record.updated_at = Clock::get()?.unix_timestamp;
        record.bump = ctx.bumps.record;

        emit!(NameRecordUpserted {
            name_hash,
            sol_authority: record.sol_authority,
            sequence,
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
#[instruction(name_hash: [u8; 32])]
pub struct ReceiveRecord<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// CHECK: posted VAA account; ownership + contents validated in the handler.
    pub posted_vaa: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = relayer,
        space = 8 + OnsRecord::LEN,
        seeds = [b"ons_mirror", name_hash.as_ref()],
        bump,
    )]
    pub record: Account<'info, OnsRecord>,

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

/// One mirrored ONS name (spec/ONS.md 3). Read-only from Solana's perspective.
#[account]
pub struct OnsRecord {
    pub name_hash: [u8; 32],
    pub spend_pubkey: [u8; 33],
    pub view_pubkey: [u8; 33],
    pub eth_owner: [u8; 20],
    pub sol_authority: Pubkey,
    pub wormhole_sequence: u64,
    pub updated_at: i64,
    pub bump: u8,
}

impl OnsRecord {
    pub const LEN: usize = 32 + 33 + 33 + 20 + 32 + 8 + 8 + 1;
}

#[account]
pub struct Processed {
    pub bump: u8,
}

impl Processed {
    pub const LEN: usize = 1;
}

#[event]
pub struct NameRecordUpserted {
    pub name_hash: [u8; 32],
    pub sol_authority: Pubkey,
    pub sequence: u64,
}

#[event]
pub struct NameRecordRevoked {
    pub name_hash: [u8; 32],
    pub sequence: u64,
}

#[event]
pub struct SourceEmitterUpdated {
    pub source_chain: u16,
    pub source_emitter: [u8; 32],
}

#[error_code]
pub enum OnsMirrorError {
    #[msg("Posted VAA account is not owned by the Wormhole core bridge")]
    NotWormholeOwned,
    #[msg("Account is not a posted VAA")]
    NotPostedVaa,
    #[msg("Malformed VAA account data")]
    MalformedVaa,
    #[msg("VAA is not from the configured canonical registry emitter")]
    UnknownEmitter,
    #[msg("Payload is not the expected 164-byte ONS mirror body")]
    BadPayloadLength,
    #[msg("Unsupported ONS payload version")]
    BadPayloadVersion,
    #[msg("Unsupported ONS action")]
    BadAction,
    #[msg("Payload name hash does not match the record PDA seeds")]
    NameHashMismatch,
    #[msg("VAA sequence is not newer than the stored record")]
    StaleSequence,
}
