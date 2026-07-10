/**
 * Relayer market tests (spec/relayer-market.md): stake registry + job escrow on the
 * Anchor local validator, raw-instruction style. The committed inner instruction is
 * stealth_registry::resolve (read-only, signerless), proving the escrow CPI path on
 * a real deployed program.
 */
import { expect } from "chai";
import {
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { keccak_256 } from "@noble/hashes/sha3";

import {
  connection,
  disc,
  payer,
  pda,
  PROGRAMS,
  send,
  sendExpectFail,
  str,
  u64le,
  vec,
} from "./helpers";

const RELAYER_REGISTRY = new PublicKey("E4xmYaAU31dbNTbhfMfp2F24b48DAxJigvZTVbsKJREg");
const SYS = SystemProgram.programId;

const STAKE = BigInt(LAMPORTS_PER_SOL) / 5n; // 0.2 SOL
const FEE = BigInt(LAMPORTS_PER_SOL) / 100n; // 0.01 SOL
const X25519 = Buffer.alloc(32, 0xaa);

// The relayer operator (distinct from the job creator = payer).
const operator = Keypair.generate();

const relayerPda = (op: PublicKey) =>
  pda(RELAYER_REGISTRY, [Buffer.from("relayer"), op.toBuffer()]);
const jobPda = (jobId: Buffer) => pda(RELAYER_REGISTRY, [Buffer.from("job"), jobId]);

const i64le = (n: bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(n);
  return b;
};

/** The §2.3 payload commitment over an inner instruction. */
function payloadHash(ix: TransactionInstruction): Buffer {
  const parts: Buffer[] = [ix.programId.toBuffer()];
  const n = Buffer.alloc(4);
  n.writeUInt32LE(ix.keys.length);
  parts.push(n);
  for (const k of ix.keys) {
    parts.push(k.pubkey.toBuffer(), Buffer.from([0]), Buffer.from([k.isWritable ? 1 : 0]));
  }
  parts.push(Buffer.from(ix.data));
  return Buffer.from(keccak_256(Buffer.concat(parts)));
}

/** Inner instruction: stealth_registry::resolve over the payer's registry entry. */
function innerResolveIx(): TransactionInstruction {
  const entry = pda(PROGRAMS.stealthRegistry, [
    Buffer.from("stealth_meta"),
    payer.publicKey.toBuffer(),
    u64le(1n),
  ]);
  return new TransactionInstruction({
    programId: PROGRAMS.stealthRegistry,
    keys: [{ pubkey: entry, isSigner: false, isWritable: false }],
    data: disc("resolve"),
  });
}

function registerIx(stake: bigint): TransactionInstruction {
  return new TransactionInstruction({
    programId: RELAYER_REGISTRY,
    keys: [
      { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
      { pubkey: operator.publicKey, isSigner: true, isWritable: true },
      { pubkey: SYS, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([disc("register"), X25519, str("http://localhost:8787"), u64le(stake)]),
  });
}

function createJobIx(jobId: Buffer, hash: Buffer, deadline: bigint, fee: bigint) {
  return new TransactionInstruction({
    programId: RELAYER_REGISTRY,
    keys: [
      { pubkey: jobPda(jobId), isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SYS, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([disc("create_job"), jobId, hash, i64le(deadline), u64le(fee)]),
  });
}

function acceptJobIx(jobId: Buffer) {
  return new TransactionInstruction({
    programId: RELAYER_REGISTRY,
    keys: [
      { pubkey: jobPda(jobId), isSigner: false, isWritable: true },
      { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
      { pubkey: operator.publicKey, isSigner: true, isWritable: false },
    ],
    data: Buffer.concat([disc("accept_job"), jobId]),
  });
}

function submitJobIx(jobId: Buffer, inner: TransactionInstruction) {
  return new TransactionInstruction({
    programId: RELAYER_REGISTRY,
    keys: [
      { pubkey: jobPda(jobId), isSigner: false, isWritable: true },
      { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
      { pubkey: operator.publicKey, isSigner: true, isWritable: true },
      // remaining accounts: inner accounts then the inner program
      ...inner.keys,
      { pubkey: inner.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([disc("submit_job"), jobId, vec(inner.data)]),
  });
}

const now = () => BigInt(Math.floor(Date.now() / 1000));

describe("relayer-market", () => {
  before(async () => {
    // Fund the operator and make sure the payer has a registry entry to resolve.
    await send([
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: operator.publicKey,
        lamports: Number(STAKE) + LAMPORTS_PER_SOL,
      }),
    ]);
    const entry = pda(PROGRAMS.stealthRegistry, [
      Buffer.from("stealth_meta"),
      payer.publicKey.toBuffer(),
      u64le(1n),
    ]);
    if (!(await connection.getAccountInfo(entry))) {
      await send([
        new TransactionInstruction({
          programId: PROGRAMS.stealthRegistry,
          keys: [
            { pubkey: entry, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([disc("register_keys"), u64le(1n), vec(Buffer.alloc(98, 2))]),
        }),
      ]);
    }
  });

  it("rejects registration below the minimum stake", async () => {
    const logs = await sendExpectFail([registerIx(1000n)], [operator]);
    expect(logs).to.include("InsufficientStake");
  });

  it("registers a relayer with stake in the PDA", async () => {
    await send([registerIx(STAKE)], [operator]);
    const info = await connection.getAccountInfo(relayerPda(operator.publicKey));
    expect(info).to.not.be.null;
    expect(info!.lamports).to.be.greaterThan(Number(STAKE));
  });

  it("create -> accept -> submit executes the inner CPI and pays the fee", async () => {
    const jobId = Buffer.alloc(32, 1);
    const inner = innerResolveIx();
    await send([createJobIx(jobId, payloadHash(inner), now() + 3600n, FEE)]);
    await send([acceptJobIx(jobId)], [operator]);

    const before = await connection.getBalance(operator.publicKey);
    const sig = await send([submitJobIx(jobId, inner)], [operator]);
    const after = await connection.getBalance(operator.publicKey);
    expect(after - before).to.equal(Number(FEE)); // payer covers the outer tx fee

    const tx = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const logLine = tx!.meta!.logMessages!.join("\n");
    expect(logLine).to.include(`Program ${PROGRAMS.stealthRegistry.toBase58()} invoke [2]`);
  });

  it("rejects double-submit, wrong payloads, and foreign submitters", async () => {
    const jobId = Buffer.alloc(32, 1);
    const inner = innerResolveIx();
    let logs = await sendExpectFail([submitJobIx(jobId, inner)], [operator]);
    expect(logs).to.include("JobClosed");

    const jobId2 = Buffer.alloc(32, 2);
    await send([createJobIx(jobId2, payloadHash(inner), now() + 3600n, FEE)]);
    await send([acceptJobIx(jobId2)], [operator]);

    const tampered = new TransactionInstruction({
      programId: inner.programId,
      keys: inner.keys,
      data: Buffer.concat([inner.data, Buffer.from([1])]),
    });
    logs = await sendExpectFail([submitJobIx(jobId2, tampered)], [operator]);
    expect(logs).to.include("PayloadMismatch");

    // Inner accounts must not demand signatures.
    const signerInner = new TransactionInstruction({
      programId: inner.programId,
      keys: [{ pubkey: operator.publicKey, isSigner: true, isWritable: false }],
      data: inner.data,
    });
    logs = await sendExpectFail([submitJobIx(jobId2, signerInner)], [operator]);
    expect(logs).to.include("InnerSignerForbidden");
  });

  it("slashes an accepted job and refunds an unaccepted one after the deadline", async function () {
    this.timeout(60_000);
    const slashId = Buffer.alloc(32, 3);
    const cancelId = Buffer.alloc(32, 4);
    const inner = innerResolveIx();
    const deadline = now() + 12n;
    await send([
      createJobIx(slashId, payloadHash(inner), deadline, FEE),
      createJobIx(cancelId, payloadHash(inner), deadline, FEE),
    ]);
    await send([acceptJobIx(slashId)], [operator]);

    let logs = await sendExpectFail([
      new TransactionInstruction({
        programId: RELAYER_REGISTRY,
        keys: [
          { pubkey: jobPda(slashId), isSigner: false, isWritable: true },
          { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.concat([disc("slash_job"), slashId]),
      }),
    ]);
    expect(logs).to.include("DeadlineNotReached");

    await new Promise((r) => setTimeout(r, 14_000));

    // Accepting after the deadline is also blocked (fresh job would be needed anyway).
    logs = await sendExpectFail([acceptJobIx(cancelId)], [operator]);
    expect(logs).to.include("DeadlinePassed");

    const relayerBefore = (await connection.getAccountInfo(relayerPda(operator.publicKey)))!
      .lamports;
    const before = await connection.getBalance(payer.publicKey);
    await send([
      new TransactionInstruction({
        programId: RELAYER_REGISTRY,
        keys: [
          { pubkey: jobPda(slashId), isSigner: false, isWritable: true },
          { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.concat([disc("slash_job"), slashId]),
      }),
      new TransactionInstruction({
        programId: RELAYER_REGISTRY,
        keys: [
          { pubkey: jobPda(cancelId), isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.concat([disc("cancel_job"), cancelId]),
      }),
    ]);
    const after = await connection.getBalance(payer.publicKey);
    const relayerAfter = (await connection.getAccountInfo(relayerPda(operator.publicKey)))!
      .lamports;

    // Creator gains bond + slashed-job refund + cancelled-job refund (3x FEE), PLUS the
    // reclaimed rent of the two now-closed job PDAs (OPQ-036), less the tx base fee.
    const gain = after - before;
    expect(gain).to.be.greaterThan(Number(FEE) * 3 - 10_000);
    // Upper bound: 3x FEE plus at most ~0.01 SOL of reclaimed job-account rent.
    expect(gain).to.be.lessThan(Number(FEE) * 3 + 10_000_000);
    // The bond left the relayer PDA exactly.
    expect(relayerBefore - relayerAfter).to.equal(Number(FEE));
  });

  it("enforces the unstake cooldown", async () => {
    const logs = await sendExpectFail(
      [
        new TransactionInstruction({
          programId: RELAYER_REGISTRY,
          keys: [
            { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
            { pubkey: operator.publicKey, isSigner: true, isWritable: true },
          ],
          data: Buffer.concat([disc("request_unstake"), u64le(1000n)]),
        }),
        new TransactionInstruction({
          programId: RELAYER_REGISTRY,
          keys: [
            { pubkey: relayerPda(operator.publicKey), isSigner: false, isWritable: true },
            { pubkey: operator.publicKey, isSigner: true, isWritable: true },
          ],
          data: disc("withdraw"),
        }),
      ],
      [operator],
    );
    expect(logs).to.include("CooldownActive");
  });
});
