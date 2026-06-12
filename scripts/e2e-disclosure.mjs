/**
 * Live conditional-disclosure acceptance on Solana devnet
 * (spec/conditional-disclosure.md): a REAL 2-of-3 FROST DKG + threshold signing via
 * the frost-custodian CLI (no party ever holds the group secret), a policy
 * registration, a qualifying pool deposit, a fresh Groth16 disclosure proof from the
 * on-chain tree state, and an on-chain disclose that consumes the nullifier — plus
 * tampered-signature, below-threshold, and replay rejections.
 *
 *   SOLANA_RPC_URL=<devnet rpc> node scripts/e2e-disclosure.mjs
 *
 * Uses the deployed programs + circuit artifacts in circuits/v2/build + the
 * frost-custodian binary in ../sdk/tools/frost-custodian/target/debug.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import path from "node:path";
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

const PROGRAM = new PublicKey("7sDCTbMDwjzYA3KHhNPZUVa8Swvj6adJTgSkJqmsn6V7");
const POOL_PROGRAM = new PublicKey("5NjweHM4z7NrG4NLVUyJ8rtX8jLM3xtBWAR1wSJZ7vjY");
const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const WASM = new URL("../../circuits/v2/build/conditional_disclosure_js/conditional_disclosure.wasm", import.meta.url).pathname;
const ZKEY = new URL("../../circuits/v2/build/conditional_disclosure_final.zkey", import.meta.url).pathname;
const FROST = new URL("../../sdk/tools/frost-custodian/target/debug/frost-custodian", import.meta.url).pathname;
const LEVELS = 20;
// keccak256("opaque/disclosure/v1") mod r — spec §7.
const DOMAIN_DISCLOSURE = 2892858644728810973983554811705195156385130922452064297470708309156017996001n;

const conn = new Connection(RPC, "confirmed");
const payer = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync(`${homedir()}/.config/solana/id.json`, "utf8"))),
);

const disc = (name) => createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const be32 = (x) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");

const poolPda = PublicKey.findProgramAddressSync([Buffer.from("pool")], POOL_PROGRAM)[0];
const policyPda = (gkx) =>
  PublicKey.findProgramAddressSync([Buffer.from("policy"), gkx], PROGRAM)[0];
const nullifierPda = (nh) =>
  PublicKey.findProgramAddressSync([Buffer.from("nullifier"), be32(nh)], PROGRAM)[0];

async function send(ixs, { cu = 1_000_000 } = {}) {
  const tx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: cu }),
    ...ixs,
  );
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.lastValidBlockHeight = lastValidBlockHeight;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  const sig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  for (let i = 0; i < 60; i++) {
    const st = (await conn.getSignatureStatuses([sig])).value[0];
    if (st?.err) throw new Error(`tx ${sig} failed: ${JSON.stringify(st.err)}`);
    if (st?.confirmationStatus === "confirmed" || st?.confirmationStatus === "finalized") return sig;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(`confirm timeout ${sig}`);
}

async function expectFail(ixs, needle, what, opts = {}) {
  try {
    await send(ixs, opts);
  } catch (e) {
    const msg = String(e.transactionLogs ?? "") + String(e.message ?? e);
    if (!msg.includes(needle)) throw new Error(`${what}: failed but without "${needle}": ${msg}`);
    console.log(`  ${what} rejected ✓`);
    return;
  }
  throw new Error(`${what}: unexpectedly succeeded`);
}

function frost(args) {
  return execFileSync(FROST, args, { encoding: "utf8" });
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (xs) => F.toObject(poseidon(xs));
  const zeros = [0n];
  for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

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

  // The state tree holds deposit commitments AND withdrawal remainder commitments,
  // in insertion order. DepositEvent carries its leaf index; WithdrawalEvent's
  // new_commitment is appended at the then-next index, so we replay all pool events
  // chronologically and append as the program did.
  const collectCommitments = async () => {
    const depDisc = createHash("sha256").update("event:DepositEvent").digest().subarray(0, 8);
    const wdrDisc = createHash("sha256").update("event:WithdrawalEvent").digest().subarray(0, 8);
    const sigs = await conn.getSignaturesForAddress(poolPda, { limit: 500 });
    const leaves = [];
    for (const s of sigs.reverse()) {
      const tx = await conn.getTransaction(s.signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      if (tx?.meta?.err) continue;
      for (const log of tx?.meta?.logMessages ?? []) {
        const m = log.match(/^Program data: (.+)$/);
        if (!m) continue;
        const data = Buffer.from(m[1], "base64");
        if (data.length >= 8 + 32 + 32 + 8 + 4 && data.subarray(0, 8).equals(depDisc)) {
          const commitment = BigInt("0x" + data.subarray(8, 40).toString("hex"));
          const li = data.readUInt32LE(8 + 32 + 32 + 8);
          if (li !== leaves.length) throw new Error(`deposit leaf ${li} but ${leaves.length} leaves replayed`);
          leaves.push(commitment);
        } else if (data.length >= 8 + 32 + 32 + 8 + 32 && data.subarray(0, 8).equals(wdrDisc)) {
          leaves.push(BigInt("0x" + data.subarray(8 + 32, 8 + 64).toString("hex")));
        }
      }
    }
    return leaves;
  };

  // ── 1. FROST ceremony: 2-of-3 DKG, no dealer ────────────────────────────────
  console.log("running 2-of-3 FROST DKG (frost-custodian) ...");
  const dir = mkdtempSync(path.join(tmpdir(), "opaque-disclosure-"));
  const ceremony = path.join(dir, "ceremony");
  for (const i of [1, 2, 3]) frost(["dkg-part1", "--id", `${i}`, "--min", "2", "--max", "3", "--dir", ceremony]);
  for (const i of [1, 2, 3]) frost(["dkg-part2", "--id", `${i}`, "--dir", ceremony]);
  for (const i of [1, 2, 3]) frost(["dkg-finalize", "--id", `${i}`, "--dir", ceremony]);
  const group = JSON.parse(readFileSync(path.join(ceremony, "group.json"), "utf8"));
  const groupKeyX = Buffer.from(group.group_key_x, "hex");
  console.log("  group key (x-only):", "0x" + group.group_key_x);

  // ── 2. Register the policy on devnet ────────────────────────────────────────
  const threshold = 10_000_000n; // 0.01 SOL qualification bound
  console.log("registering policy (threshold 0.01 SOL, 2-of-3) ...");
  await send([
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: policyPda(groupKeyX), isSigner: false, isWritable: true },
        { pubkey: poolPda, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([disc("register_policy"), groupKeyX, u64le(threshold), Buffer.from([2, 3])]),
    }),
  ], { cu: 200_000 });
  console.log("  policy:", policyPda(groupKeyX).toBase58());

  // ── 3. Deposit a qualifying note (0.02 SOL > 0.01 SOL) ──────────────────────
  const acct0 = await conn.getAccountInfo(poolPda);
  const scope = BigInt("0x" + acct0.data.subarray(40, 72).toString("hex"));
  const leafIndex = acct0.data.readUInt32LE(104);
  const value = BigInt(0.02 * LAMPORTS_PER_SOL);
  const nullifier = BigInt("0x" + createHash("sha256").update("opaque-disc-null" + Date.now()).digest("hex")) % F.p;
  const secret = BigInt("0x" + createHash("sha256").update("opaque-disc-secret" + Date.now()).digest("hex")) % F.p;
  const label = H([scope, BigInt(leafIndex)]);
  const commitment = H([value, label, H([nullifier, secret])]);
  console.log("depositing 0.02 SOL (leaf", leafIndex, ") ...");
  await send([
    new TransactionInstruction({
      programId: POOL_PROGRAM,
      keys: [
        { pubkey: poolPda, isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([disc("deposit"), be32(H([nullifier, secret])), u64le(value)]),
    }),
  ], { cu: 800_000 });

  // ── 4. Rebuild the tree from events; root must match the chain ──────────────
  console.log("reconstructing state tree from Deposit events ...");
  const leaves = await collectCommitments();
  if (leaves[leafIndex] !== commitment) throw new Error("reconstructed leaf != my commitment");
  const state = buildTree(leaves);
  const acct1 = await conn.getAccountInfo(poolPda);
  const ri = acct1.data.readUInt32LE(108);
  const ROOTS_OFF = 8 + 32 + 32 + 32 + 4 + 4 + 32 * LEVELS;
  const onchainRoot = BigInt("0x" + acct1.data.subarray(ROOTS_OFF + ri * 32, ROOTS_OFF + ri * 32 + 32).toString("hex"));
  if (state.root !== onchainRoot) throw new Error("root mismatch vs chain");
  console.log("  root matches the chain ✓ (", leaves.length, "leaves )");

  // ── 5. Context + 2-of-3 threshold signature (custodians 1 and 3) ────────────
  const caseId = Buffer.alloc(32);
  caseId.write("devnet-acceptance-7.5");
  const ctxHash = Buffer.from(keccak_256(Buffer.concat([
    policyPda(groupKeyX).toBuffer(), caseId, payer.publicKey.toBuffer(),
  ])));
  ctxHash[0] &= 0x1f;
  const context = BigInt("0x" + ctxHash.toString("hex"));
  const msgHex = ctxHash.toString("hex");

  console.log("custodians 1 + 3 co-sign the context (M=2 of N=3) ...");
  const signing = path.join(dir, "signing");
  for (const i of [1, 3]) frost(["sign-round1", "--id", `${i}`, "--key", path.join(ceremony, `keys/${i}.key.secret.json`), "--dir", signing]);
  for (const i of [1, 3]) frost(["sign-round2", "--id", `${i}`, "--key", path.join(ceremony, `keys/${i}.key.secret.json`), "--message", msgHex, "--dir", signing]);
  frost(["aggregate", "--group", path.join(ceremony, "group.json"), "--message", msgHex, "--dir", signing]);
  const sig = JSON.parse(readFileSync(path.join(signing, "signature.json"), "utf8"));
  console.log("  aggregate BIP-340 signature ✓");

  // ── 6. Below-threshold qualification is unsatisfiable ───────────────────────
  const disclosureNullifier = H([nullifier, context, DOMAIN_DISCLOSURE]);
  const statePath = state.pathFor(leafIndex);
  const input = {
    nullifier: nullifier.toString(),
    secret: secret.toString(),
    state_siblings: statePath.siblings.map(String),
    state_index: statePath.idx,
    value: value.toString(),
    label: label.toString(),
    threshold: threshold.toString(),
    state_root: state.root.toString(),
    disclosure_nullifier: disclosureNullifier.toString(),
    context: context.toString(),
  };
  try {
    await snarkjs.groth16.fullProve({ ...input, threshold: value.toString() }, WASM, ZKEY);
    throw new Error("below-threshold witness unexpectedly satisfiable");
  } catch (e) {
    if (String(e).includes("unexpectedly")) throw e;
    console.log("  below-threshold note is unsatisfiable ✓");
  }

  // ── 7. Prove + disclose ──────────────────────────────────────────────────────
  console.log("generating disclosure proof ...");
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const g1 = (p) => Buffer.concat([be32(BigInt(p[0])), be32(BigInt(p[1]))]);
  const g2 = (p) => Buffer.concat([be32(BigInt(p[0][1])), be32(BigInt(p[0][0])), be32(BigInt(p[1][1])), be32(BigInt(p[1][0]))]);

  const discloseIx = (sHex) =>
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: policyPda(groupKeyX), isSigner: false, isWritable: false },
        { pubkey: poolPda, isSigner: false, isWritable: false },
        { pubkey: nullifierPda(disclosureNullifier), isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        disc("disclose"),
        g1(proof.pi_a), g2(proof.pi_b), g1(proof.pi_c),
        u64le(value), be32(label), be32(state.root), be32(disclosureNullifier),
        caseId,
        Buffer.from(sig.rx, "hex"), Buffer.from(sig.ry, "hex"), Buffer.from(sHex, "hex"),
      ]),
    });

  // Tampered quorum signature first.
  const badS = Buffer.from(sig.s, "hex");
  badS[31] ^= 1;
  await expectFail([discloseIx(badS.toString("hex"))], "InvalidQuorumSignature", "tampered quorum signature");

  console.log("submitting disclose ...");
  const txSig = await send([discloseIx(sig.s)]);
  console.log("  disclose tx:", txSig);

  const np = await conn.getAccountInfo(nullifierPda(disclosureNullifier));
  if (!np) throw new Error("nullifier PDA missing after disclose");
  console.log("  disclosure nullifier consumed ✓");

  // Different CU limit so the replay tx has a distinct signature (identical bytes
  // would be deduped by the cluster instead of executed).
  await expectFail([discloseIx(sig.s)], "already in use", "replay", { cu: 999_999 });

  console.log("\nACCEPTANCE (Solana devnet) ✓");
  console.log("  2-of-3 custodians authorized one qualifying disclosure;");
  console.log("  the group secret never existed in one place (FROST DKG);");
  console.log("  value disclosed:", value.toString(), "lamports; label:", label.toString());
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
