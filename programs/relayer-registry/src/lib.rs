use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
    system_instruction,
};
use solana_keccak_hasher as keccak;

declare_id!("E4xmYaAU31dbNTbhfMfp2F24b48DAxJigvZTVbsKJREg");

// Relayer market (spec/relayer-market.md) on Solana: combined stake registry and
// gas-private job escrow. A job commits to a hidden inner instruction via
// payload_hash = keccak256(program_id || u32_le(n_accounts) ||
// [pubkey || is_signer || is_writable]... || data); the accepting relayer bonds the
// fee from free stake and must reveal + execute the instruction (CPI) before the
// deadline or the creator claims the bond. Inner accounts MUST NOT require signers:
// the escrow signs nothing on the inner instruction's behalf.

/// Minimum stake to register (testnet parameter): 0.1 SOL.
pub const MINIMUM_STAKE: u64 = 100_000_000;

/// Delay between request_unstake and withdraw.
pub const UNSTAKE_COOLDOWN_SECS: i64 = 60 * 60;

pub const MAX_ENDPOINT_LEN: usize = 128;

#[program]
pub mod relayer_registry {
    use super::*;

    /// Register as a relayer (or top up + refresh keys): deposits `stake_lamports`
    /// into the relayer PDA and advertises the x25519 key payloads are encrypted to.
    pub fn register(
        ctx: Context<Register>,
        x25519_pub_key: [u8; 32],
        endpoint: String,
        stake_lamports: u64,
    ) -> Result<()> {
        require!(endpoint.len() <= MAX_ENDPOINT_LEN, MarketError::EndpointTooLong);
        let r = &mut ctx.accounts.relayer;
        if r.operator == Pubkey::default() {
            r.operator = ctx.accounts.operator.key();
            r.bump = ctx.bumps.relayer;
        }
        if stake_lamports > 0 {
            transfer_in(
                &ctx.accounts.operator,
                &r.to_account_info(),
                &ctx.accounts.system_program,
                stake_lamports,
            )?;
            r.stake += stake_lamports;
        }
        require!(r.stake >= MINIMUM_STAKE, MarketError::InsufficientStake);
        r.x25519_pub_key = x25519_pub_key;
        r.endpoint = endpoint;
        emit!(RelayerRegistered {
            operator: r.operator,
            stake: r.stake,
            x25519_pub_key,
        });
        Ok(())
    }

    /// Move free stake into the unstake queue; withdrawable after the cooldown.
    pub fn request_unstake(ctx: Context<OperatorOnly>, amount: u64) -> Result<()> {
        let r = &mut ctx.accounts.relayer;
        require!(amount <= r.stake - r.bonded, MarketError::InsufficientFreeStake);
        r.stake -= amount;
        r.unstaking += amount;
        r.unstake_available_at = Clock::get()?.unix_timestamp + UNSTAKE_COOLDOWN_SECS;
        Ok(())
    }

    pub fn withdraw(ctx: Context<OperatorOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let r = &mut ctx.accounts.relayer;
        let amount = r.unstaking;
        require!(amount > 0, MarketError::NothingToWithdraw);
        require!(now >= r.unstake_available_at, MarketError::CooldownActive);
        r.unstaking = 0;
        transfer_out(&r.to_account_info(), &ctx.accounts.operator.to_account_info(), amount)?;
        Ok(())
    }

    /// Escrow a job: `fee` lamports against the payload commitment.
    pub fn create_job(
        ctx: Context<CreateJob>,
        job_id: [u8; 32],
        payload_hash: [u8; 32],
        deadline: i64,
        fee: u64,
    ) -> Result<()> {
        require!(fee > 0, MarketError::ZeroFee);
        require!(deadline > Clock::get()?.unix_timestamp, MarketError::DeadlineInPast);
        let j = &mut ctx.accounts.job;
        j.job_id = job_id;
        j.creator = ctx.accounts.creator.key();
        j.fee = fee;
        j.payload_hash = payload_hash;
        j.deadline = deadline;
        j.bump = ctx.bumps.job;
        transfer_in(
            &ctx.accounts.creator,
            &j.to_account_info(),
            &ctx.accounts.system_program,
            fee,
        )?;
        emit!(JobCreated {
            job_id,
            creator: j.creator,
            fee,
            payload_hash,
            deadline,
        });
        Ok(())
    }

    /// Accept a job, bonding `fee` from free stake. First valid accept wins.
    pub fn accept_job(ctx: Context<AcceptJob>, _job_id: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let j = &mut ctx.accounts.job;
        require!(!j.closed, MarketError::JobClosed);
        require!(j.relayer == Pubkey::default(), MarketError::AlreadyAccepted);
        require!(now < j.deadline, MarketError::DeadlinePassed);
        let r = &mut ctx.accounts.relayer;
        require!(r.stake >= MINIMUM_STAKE, MarketError::NotRegistered);
        require!(r.stake - r.bonded >= j.fee, MarketError::InsufficientFreeStake);
        r.bonded += j.fee;
        j.relayer = r.operator;
        emit!(JobAccepted { job_id: j.job_id, relayer: r.operator, bond: j.fee });
        Ok(())
    }

    /// Reveal and execute the committed inner instruction. Remaining accounts are
    /// the inner instruction's accounts followed by the inner program account.
    /// Verifies the §2.3 hash, requires no inner signers, CPIs the instruction,
    /// then pays the fee and releases the bond atomically.
    pub fn submit_job<'info>(
        ctx: Context<'_, '_, 'info, 'info, SubmitJob<'info>>,
        _job_id: [u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        let j = &mut ctx.accounts.job;
        require!(!j.closed, MarketError::JobClosed);
        // After the deadline only slashing is valid; a late submit must not race the creator's
        // slash and dodge the penalty (OPQ-023).
        require!(
            Clock::get()?.unix_timestamp < j.deadline,
            MarketError::DeadlinePassed
        );
        require!(
            j.relayer == ctx.accounts.operator.key(),
            MarketError::NotJobRelayer
        );
        require!(!ctx.remaining_accounts.is_empty(), MarketError::MissingInnerProgram);

        let (inner_accounts, program_tail) =
            ctx.remaining_accounts.split_at(ctx.remaining_accounts.len() - 1);
        let inner_program = &program_tail[0];

        // Re-derive the payload hash from what will actually execute.
        let mut preimage =
            Vec::with_capacity(32 + 4 + inner_accounts.len() * 34 + data.len());
        preimage.extend_from_slice(inner_program.key().as_ref());
        preimage.extend_from_slice(&(inner_accounts.len() as u32).to_le_bytes());
        let mut metas = Vec::with_capacity(inner_accounts.len());
        for a in inner_accounts {
            require!(!a.is_signer, MarketError::InnerSignerForbidden);
            preimage.extend_from_slice(a.key().as_ref());
            preimage.push(0); // is_signer (always false, committed as such)
            preimage.push(a.is_writable as u8);
            metas.push(if a.is_writable {
                AccountMeta::new(a.key(), false)
            } else {
                AccountMeta::new_readonly(a.key(), false)
            });
        }
        preimage.extend_from_slice(&data);
        require!(
            keccak::hash(&preimage).to_bytes() == j.payload_hash,
            MarketError::PayloadMismatch
        );

        // Effects before the inner call.
        j.submitted = true;
        j.closed = true;
        let fee = j.fee;
        let r = &mut ctx.accounts.relayer;
        r.bonded -= fee;
        let job_id = j.job_id;
        let inner_program_key = inner_program.key();

        let ix = Instruction { program_id: inner_program_key, accounts: metas, data };
        let mut infos: Vec<AccountInfo> = inner_accounts.to_vec();
        infos.push(inner_program.clone());
        invoke(&ix, &infos)?;

        transfer_out(
            &ctx.accounts.job.to_account_info(),
            &ctx.accounts.operator.to_account_info(),
            fee,
        )?;
        emit!(JobSubmitted { job_id, relayer: ctx.accounts.operator.key(), inner_program: inner_program_key });
        Ok(())
    }

    /// After the deadline, an accepted-but-unsubmitted job lets the creator claim
    /// the relayer's bond plus the fee refund.
    pub fn slash_job(ctx: Context<SlashJob>, _job_id: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let j = &mut ctx.accounts.job;
        require!(!j.closed, MarketError::JobClosed);
        require!(j.relayer != Pubkey::default(), MarketError::NotAccepted);
        require!(now >= j.deadline, MarketError::DeadlineNotReached);

        j.closed = true;
        let fee = j.fee;
        let r = &mut ctx.accounts.relayer;
        require!(r.operator == j.relayer, MarketError::WrongRelayerAccount);
        r.bonded -= fee;
        r.stake -= fee; // the bond is forfeited

        // Bond from the relayer PDA + fee refund from the job PDA.
        transfer_out(&r.to_account_info(), &ctx.accounts.creator.to_account_info(), fee)?;
        transfer_out(
            &ctx.accounts.job.to_account_info(),
            &ctx.accounts.creator.to_account_info(),
            fee,
        )?;
        emit!(JobSlashed { job_id: ctx.accounts.job.job_id, relayer: ctx.accounts.relayer.operator, amount: fee });
        Ok(())
    }

    /// After the deadline, an unaccepted job refunds its fee.
    pub fn cancel_job(ctx: Context<CancelJob>, _job_id: [u8; 32]) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let job_info = ctx.accounts.job.to_account_info();
        let j = &mut ctx.accounts.job;
        require!(!j.closed, MarketError::JobClosed);
        require!(j.relayer == Pubkey::default(), MarketError::AlreadyAccepted);
        require!(now >= j.deadline, MarketError::DeadlineNotReached);
        j.closed = true;
        let fee = j.fee;
        let job_id = j.job_id;
        transfer_out(&job_info, &ctx.accounts.creator.to_account_info(), fee)?;
        emit!(JobCancelled { job_id });
        Ok(())
    }
}

/// System transfer into a (possibly program-owned) account.
fn transfer_in<'info>(
    from: &Signer<'info>,
    to: &AccountInfo<'info>,
    system_program: &Program<'info, System>,
    lamports: u64,
) -> Result<()> {
    invoke(
        &system_instruction::transfer(&from.key(), &to.key(), lamports),
        &[
            from.to_account_info(),
            to.clone(),
            system_program.to_account_info(),
        ],
    )?;
    Ok(())
}

/// Direct lamport debit from a program-owned account (keeps rent intact because all
/// tracked balances sit on top of the rent-exempt minimum).
fn transfer_out<'info>(
    from: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    lamports: u64,
) -> Result<()> {
    from.sub_lamports(lamports)?;
    to.add_lamports(lamports)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Register<'info> {
    #[account(
        init_if_needed,
        payer = operator,
        space = 8 + RelayerAccount::LEN,
        seeds = [b"relayer", operator.key().as_ref()],
        bump,
    )]
    pub relayer: Account<'info, RelayerAccount>,
    #[account(mut)]
    pub operator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OperatorOnly<'info> {
    #[account(mut, seeds = [b"relayer", operator.key().as_ref()], bump = relayer.bump)]
    pub relayer: Account<'info, RelayerAccount>,
    #[account(mut)]
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(job_id: [u8; 32])]
pub struct CreateJob<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + JobAccount::LEN,
        seeds = [b"job", job_id.as_ref()],
        bump,
    )]
    pub job: Account<'info, JobAccount>,
    #[account(mut)]
    pub creator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(job_id: [u8; 32])]
pub struct AcceptJob<'info> {
    #[account(mut, seeds = [b"job", job_id.as_ref()], bump = job.bump)]
    pub job: Account<'info, JobAccount>,
    #[account(mut, seeds = [b"relayer", operator.key().as_ref()], bump = relayer.bump)]
    pub relayer: Account<'info, RelayerAccount>,
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(job_id: [u8; 32])]
pub struct SubmitJob<'info> {
    // The successful-submit path intentionally does NOT close the job PDA to the creator: the
    // creator is not among these accounts (the relayer submits), and threading it here would
    // ripple into the off-chain relayer node's submit builder. The ~0.0016 SOL job-account rent
    // is therefore retained on submit (reclaimed on slash/cancel); a known minor cost (OPQ-036).
    #[account(mut, seeds = [b"job", job_id.as_ref()], bump = job.bump)]
    pub job: Account<'info, JobAccount>,
    #[account(mut, seeds = [b"relayer", operator.key().as_ref()], bump = relayer.bump)]
    pub relayer: Account<'info, RelayerAccount>,
    #[account(mut)]
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(job_id: [u8; 32])]
pub struct SlashJob<'info> {
    // Close the finished job PDA back to the creator so its rent is reclaimed, not stranded
    // as a closed-but-allocated orphan (OPQ-036).
    #[account(mut, seeds = [b"job", job_id.as_ref()], bump = job.bump, has_one = creator, close = creator)]
    pub job: Account<'info, JobAccount>,
    /// CHECK: the slashed relayer's PDA; bound to job.relayer in the handler.
    #[account(mut, seeds = [b"relayer", job.relayer.as_ref()], bump = relayer.bump)]
    pub relayer: Account<'info, RelayerAccount>,
    #[account(mut)]
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(job_id: [u8; 32])]
pub struct CancelJob<'info> {
    // Close the cancelled job PDA back to the creator so its rent is reclaimed (OPQ-036).
    #[account(mut, seeds = [b"job", job_id.as_ref()], bump = job.bump, has_one = creator, close = creator)]
    pub job: Account<'info, JobAccount>,
    #[account(mut)]
    pub creator: Signer<'info>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct RelayerAccount {
    pub operator: Pubkey,
    /// Total staked (free + bonded), excluding pending unstake; lamports held by this PDA.
    pub stake: u64,
    /// Portion of `stake` bonded to accepted-but-unfinished jobs.
    pub bonded: u64,
    /// Pending unstake amount (withdrawable after the cooldown).
    pub unstaking: u64,
    pub unstake_available_at: i64,
    /// x25519 public key bids advertise; payloads are encrypted to it.
    pub x25519_pub_key: [u8; 32],
    /// Optional HTTP gateway URL.
    pub endpoint: String,
    pub bump: u8,
}

impl RelayerAccount {
    pub const LEN: usize = 32 + 8 + 8 + 8 + 8 + 32 + 4 + MAX_ENDPOINT_LEN + 1;
}

#[account]
pub struct JobAccount {
    pub job_id: [u8; 32],
    pub creator: Pubkey,
    /// Zero until accepted.
    pub relayer: Pubkey,
    pub fee: u64,
    pub payload_hash: [u8; 32],
    pub deadline: i64,
    pub submitted: bool,
    pub closed: bool,
    pub bump: u8,
}

impl JobAccount {
    pub const LEN: usize = 32 + 32 + 32 + 8 + 32 + 8 + 1 + 1 + 1;
}

// ---------------------------------------------------------------------------
// Events / errors
// ---------------------------------------------------------------------------

#[event]
pub struct RelayerRegistered {
    pub operator: Pubkey,
    pub stake: u64,
    pub x25519_pub_key: [u8; 32],
}

#[event]
pub struct JobCreated {
    pub job_id: [u8; 32],
    pub creator: Pubkey,
    pub fee: u64,
    pub payload_hash: [u8; 32],
    pub deadline: i64,
}

#[event]
pub struct JobAccepted {
    pub job_id: [u8; 32],
    pub relayer: Pubkey,
    pub bond: u64,
}

#[event]
pub struct JobSubmitted {
    pub job_id: [u8; 32],
    pub relayer: Pubkey,
    pub inner_program: Pubkey,
}

#[event]
pub struct JobSlashed {
    pub job_id: [u8; 32],
    pub relayer: Pubkey,
    pub amount: u64,
}

#[event]
pub struct JobCancelled {
    pub job_id: [u8; 32],
}

#[error_code]
pub enum MarketError {
    #[msg("Stake below the registration minimum")]
    InsufficientStake,
    #[msg("Relayer is not registered")]
    NotRegistered,
    #[msg("Free (unbonded) stake is insufficient")]
    InsufficientFreeStake,
    #[msg("Unstake cooldown has not elapsed")]
    CooldownActive,
    #[msg("No pending unstake")]
    NothingToWithdraw,
    #[msg("Endpoint exceeds the maximum length")]
    EndpointTooLong,
    #[msg("Fee must be non-zero")]
    ZeroFee,
    #[msg("Deadline is in the past")]
    DeadlineInPast,
    #[msg("Deadline has passed")]
    DeadlinePassed,
    #[msg("Deadline has not been reached")]
    DeadlineNotReached,
    #[msg("Job already accepted")]
    AlreadyAccepted,
    #[msg("Job has not been accepted")]
    NotAccepted,
    #[msg("Job is closed")]
    JobClosed,
    #[msg("Caller is not the accepting relayer")]
    NotJobRelayer,
    #[msg("Inner program account is missing")]
    MissingInnerProgram,
    #[msg("Inner accounts must not require signatures")]
    InnerSignerForbidden,
    #[msg("Payload does not match the committed hash")]
    PayloadMismatch,
    #[msg("Relayer account does not match the job's relayer")]
    WrongRelayerAccount,
}
