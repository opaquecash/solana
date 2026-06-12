/**
 * Live privacy-pool acceptance on Solana devnet (spec/privacy-pool.md): initialize the
 * pool, a real deposit, a fresh Groth16 withdrawal proof generated from the on-chain
 * tree state, and an on-chain withdraw that pays out, consumes the nullifier, and
 * inserts the remainder. Also proves the program's native Bn254X5 Poseidon matches the
 * circomlibjs Poseidon used by the circuit + SDK (the on-chain root must equal the
 * locally computed root).
 *
 *   SOLANA_RPC_URL=<devnet rpc> node scripts/e2e-privacy-pool.mjs
 *
 * Uses the deployed program + circuit artifacts in circuits/v2/build.
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { keccak_256 } from "@noble/hashes/sha3";

const PROGRAM = new PublicKey("5NjweHM4z7NrG4NLVUyJ8rtX8jLM3xtBWAR1wSJZ7vjY");
const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const WASM = new URL("../../circuits/v2/build/withdrawal_js/withdrawal.wasm", import.meta.url).pathname;
const ZKEY = new URL("../../circuits/v2/build/withdrawal_final.zkey", import.meta.url).pathname;
const LEVELS = 20;

const conn = new Connection(RPC, "confirmed");
const payer = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync(`${homedir()}/.config/solana/id.json`, "utf8"))),
);

const disc = (name) => createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const be32 = (x) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");

const poolPda = PublicKey.findProgramAddressSync([Buffer.from("pool")], PROGRAM)[0];
const nullifierPda = (nh) =>
  PublicKey.findProgramAddressSync([Buffer.from("nullifier"), be32(nh)], PROGRAM)[0];

async function send(ixs, signers = []) {
  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 800_000 }),
    ...ixs,
  );
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.lastValidBlockHeight = lastValidBlockHeight;
  tx.feePayer = payer.publicKey;
  tx.sign(payer, ...signers);
  const sig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  for (let i = 0; i < 60; i++) {
    const st = (await conn.getSignatureStatuses([sig])).value[0];
    if (st?.err) throw new Error(`tx ${sig} failed: ${JSON.stringify(st.err)}`);
    if (st?.confirmationStatus === "confirmed" || st?.confirmationStatus === "finalized") return sig;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`confirm timeout ${sig}`);
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (xs) => F.toObject(poseidon(xs));
  const zeros = [0n];
  for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));
  const singleLeafRoot = (leaf) => { let n = leaf; for (let i = 0; i < LEVELS; i++) n = H([n, zeros[i]]); return n; };

  // Build the append-only state tree from an ordered leaf list; return root + a path.
  const buildTree = (leaves) => {
    const layers = [leaves.slice()];
    for (let lvl = 0; lvl < LEVELS; lvl++) {
      const cur = layers[lvl], next = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(H([cur[i], i + 1 < cur.length ? cur[i + 1] : zeros[lvl]]));
      }
      layers.push(next);
    }
    const root = layers[LEVELS].length ? layers[LEVELS][0] : zeros[LEVELS];
    const pathFor = (index) => {
      const siblings = [], idx = [];
      let j = index;
      for (let lvl = 0; lvl < LEVELS; lvl++) {
        const layer = layers[lvl], right = j % 2 === 1, sib = right ? j - 1 : j + 1;
        siblings.push(sib < layer.length ? layer[sib] : zeros[lvl]);
        idx.push(right ? 1 : 0);
        j = Math.floor(j / 2);
      }
      return { siblings, idx };
    };
    return { root, pathFor };
  };

  // Reconstruct the ordered state leaves from the pool's Deposit events.
  const collectCommitments = async () => {
    const evDisc = createHash("sha256").update("event:DepositEvent").digest().subarray(0, 8);
    const sigs = await conn.getSignaturesForAddress(poolPda, { limit: 500 });
    const byIndex = new Map();
    for (const s of sigs.reverse()) {
      const tx = await conn.getTransaction(s.signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      for (const log of tx?.meta?.logMessages ?? []) {
        const m = log.match(/^Program data: (.+)$/);
        if (!m) continue;
        const data = Buffer.from(m[1], "base64");
        if (data.length < 8 + 32 + 32 + 8 + 4 || !data.subarray(0, 8).equals(evDisc)) continue;
        const commitment = BigInt("0x" + data.subarray(8, 40).toString("hex"));
        const li = data.readUInt32LE(8 + 32 + 32 + 8);
        byIndex.set(li, commitment);
      }
    }
    const n = Math.max(...byIndex.keys()) + 1;
    return Array.from({ length: n }, (_, i) => byIndex.get(i) ?? 0n);
  };

  // Initialize the pool if needed (idempotent: skip if it exists).
  if (!(await conn.getAccountInfo(poolPda))) {
    console.log("initializing pool ...");
    await send([
      new TransactionInstruction({
        programId: PROGRAM,
        keys: [
          { pubkey: poolPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([disc("initialize"), payer.publicKey.toBuffer()]),
      }),
    ]);
  }
  // Read scope + next_index from the Pool account (layout: 8 disc, asp_authority 32,
  // scope 32 @40, asp_root 32 @72, next_index u32 @104, current_root_index u32 @108).
  let acct = await conn.getAccountInfo(poolPda);
  const scope = BigInt("0x" + acct.data.subarray(40, 72).toString("hex"));
  const leafIndex = acct.data.readUInt32LE(104);
  console.log("pool:", poolPda.toBase58(), "leafIndex:", leafIndex);

  // ── Deposit ────────────────────────────────────────────────────────────────
  const value = BigInt(0.02 * LAMPORTS_PER_SOL); // 0.02 SOL
  const nullifier = BigInt("0x" + createHash("sha256").update("opaque-pool-null" + Date.now()).digest("hex")) % F.p;
  const secret = BigInt("0x" + createHash("sha256").update("opaque-pool-secret" + Date.now()).digest("hex")) % F.p;
  const precommitment = H([nullifier, secret]);
  const label = H([scope, BigInt(leafIndex)]);
  const commitment = H([value, label, precommitment]);

  console.log("depositing 0.02 SOL ...");
  await send([
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: poolPda, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([disc("deposit"), be32(precommitment), u64le(value)]),
    }),
  ]);

  // The on-chain root after this single deposit (fresh pool) must match circomlibjs.
  acct = await conn.getAccountInfo(poolPda);
  const rootIndex = acct.data.readUInt32LE(108);
  // roots[] start at: 8 + 32 + 32 + 32 + 4 + 4 + (32*LEVELS filled_subtrees=640) = 752.
  const ROOTS_OFF = 8 + 32 + 32 + 32 + 4 + 4 + 32 * LEVELS;
  const onchainRoot = BigInt("0x" + acct.data.subarray(ROOTS_OFF + rootIndex * 32, ROOTS_OFF + rootIndex * 32 + 32).toString("hex"));

  // Reconstruct the full state tree from Deposit events and check it matches the chain.
  console.log("reconstructing state tree from Deposit events ...");
  const leaves = await collectCommitments();
  if (leaves[leafIndex] !== commitment) {
    throw new Error(`reconstructed leaf ${leafIndex} != my commitment`);
  }
  const state = buildTree(leaves);
  if (state.root !== onchainRoot) {
    throw new Error(`native Poseidon root mismatch:\n  on-chain  ${onchainRoot}\n  circomlib ${state.root}`);
  }
  console.log("  native Bn254X5 Poseidon root matches circomlibjs ✓ (", leaves.length, "leaves )");
  const stateRoot = onchainRoot;
  const statePath = state.pathFor(leafIndex);

  // ── ASP: approve this label ──────────────────────────────────────────────────
  const aspRoot = singleLeafRoot(label);
  await send([
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: poolPda, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: false },
      ],
      data: Buffer.concat([disc("set_asp_root"), be32(aspRoot)]),
    }),
  ]);

  // ── Build the withdrawal proof ───────────────────────────────────────────────
  const recipient = Keypair.generate().publicKey;
  // fee_recipient must be a real writable account even when fee = 0 (the System Program
  // / all-zero address is not writable); use the payer as the no-op fee recipient.
  const feeRecipient = payer.publicKey;
  const fee = 0n;
  // context = keccak256(recipient || fee_recipient || fee_be8 || scope), top 3 bits
  // cleared — identical to the program's compute_context.
  const ctxPre = Buffer.concat([recipient.toBuffer(), feeRecipient.toBuffer(), u64be(fee), be32(scope)]);
  const ctxHash = Buffer.from(keccak_256(ctxPre));
  ctxHash[0] &= 0x1f;
  const context = BigInt("0x" + ctxHash.toString("hex"));

  const withdrawnValue = BigInt(0.008 * LAMPORTS_PER_SOL);
  const remainder = value - withdrawnValue;
  const newNullifier = (nullifier + 1n) % F.p;
  const newSecret = (secret + 1n) % F.p;
  const newCommitment = H([remainder, label, H([newNullifier, newSecret])]);
  const nullifierHash = H([nullifier]);

  const input = {
    value: value.toString(), label: label.toString(),
    nullifier: nullifier.toString(), secret: secret.toString(),
    new_nullifier: newNullifier.toString(), new_secret: newSecret.toString(),
    state_siblings: statePath.siblings.map(String), state_index: statePath.idx.map(String),
    asp_siblings: zeros.slice(0, LEVELS).map(String), asp_index: Array(LEVELS).fill(0),
    withdrawn_value: withdrawnValue.toString(), state_root: stateRoot.toString(),
    asp_root: aspRoot.toString(), nullifier_hash: nullifierHash.toString(),
    new_commitment: newCommitment.toString(), context: context.toString(),
  };
  console.log("generating withdrawal proof ...");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  if (publicSignals[3] !== nullifierHash.toString()) throw new Error("nullifier hash mismatch");

  const g1 = (p) => Buffer.concat([be32(BigInt(p[0])), be32(BigInt(p[1]))]);
  const g2 = (p) => Buffer.concat([be32(BigInt(p[0][1])), be32(BigInt(p[0][0])), be32(BigInt(p[1][1])), be32(BigInt(p[1][0]))]);
  const proofA = g1(proof.pi_a);
  const proofB = g2(proof.pi_b);
  const proofC = g1(proof.pi_c);

  const before = await conn.getBalance(recipient);
  console.log("withdrawing 0.008 SOL to a fresh address ...");
  const sig = await send([
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: poolPda, isSigner: false, isWritable: true },
        { pubkey: nullifierPda(nullifierHash), isSigner: false, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: true },
        { pubkey: feeRecipient, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        disc("withdraw"), proofA, proofB, proofC,
        u64le(withdrawnValue), be32(stateRoot), be32(nullifierHash), be32(newCommitment), u64le(fee),
      ]),
    }),
  ]);
  const after = await conn.getBalance(recipient);

  console.log("\nACCEPTANCE:");
  console.log("  withdraw tx:", sig);
  console.log("  recipient received:", (after - before) / LAMPORTS_PER_SOL, "SOL (expected 0.008)");
  console.log("  nullifier PDA created:", !!(await conn.getAccountInfo(nullifierPda(nullifierHash))));
  if (after - before !== Number(withdrawnValue)) throw new Error("payout mismatch");
  console.log("  PASS — live deposit -> proof -> withdraw on Solana devnet");
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

function u64be(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }

main().then(() => process.exit(0)).catch((e) => { console.error(e.message ?? e); process.exit(1); });
