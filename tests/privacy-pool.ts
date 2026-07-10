/**
 * Privacy-pool program tests (spec/privacy-pool.md) on the Anchor local validator.
 * Validates init + deposit, that the on-chain native Bn254X5 Poseidon tree root equals
 * the circomlibjs root (cross-impl check vs the circuit/SDK), and — when the circuit
 * artifacts are present — a full deposit -> fresh-proof -> withdraw -> replay-rejection
 * flow on a fresh single-leaf pool.
 */
import { expect } from "chai";
import { existsSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { buildPoseidon } from "circomlibjs";
import { keccak_256 } from "@noble/hashes/sha3";
// @ts-expect-error untyped
import * as snarkjs from "snarkjs";

import { connection, disc, payer, pda, programData, send, sendExpectFail, u64le } from "./helpers";

const PROGRAM = new PublicKey("5NjweHM4z7NrG4NLVUyJ8rtX8jLM3xtBWAR1wSJZ7vjY");
const SYS = SystemProgram.programId;
const LEVELS = 20;
const CIRCUITS = path.join(__dirname, "..", "..", "circuits");
const WASM = path.join(CIRCUITS, "v2", "build", "withdrawal_js", "withdrawal.wasm");
const ZKEY = path.join(CIRCUITS, "v2", "build", "withdrawal_final.zkey");
const canProve = existsSync(WASM) && existsSync(ZKEY);

const be32 = (x: bigint) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");
const poolPda = pda(PROGRAM, [Buffer.from("pool")]);
const nullifierPda = (nh: bigint) => pda(PROGRAM, [Buffer.from("nullifier"), be32(nh)]);

const withCU = (ix: TransactionInstruction) => [
  ComputeBudgetProgram.setComputeUnitLimit({ units: 800_000 }),
  ix,
];

describe("opaque-privacy-pool", () => {
  let H: (xs: bigint[]) => bigint;
  let zeros: bigint[];
  let scope: bigint;

  const singleLeafRoot = (leaf: bigint) => {
    let n = leaf;
    for (let i = 0; i < LEVELS; i++) n = H([n, zeros[i]]);
    return n;
  };

  before(async () => {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    H = (xs) => F.toObject(poseidon(xs)) as bigint;
    zeros = [0n];
    for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

    if (!(await connection.getAccountInfo(poolPda))) {
      await send([
        new TransactionInstruction({
          programId: PROGRAM,
          keys: [
            { pubkey: poolPda, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: PROGRAM, isSigner: false, isWritable: false },
            { pubkey: programData(PROGRAM), isSigner: false, isWritable: false },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([disc("initialize"), payer.publicKey.toBuffer()]),
        }),
      ]);
    }
    const acct = (await connection.getAccountInfo(poolPda))!;
    scope = BigInt("0x" + acct.data.subarray(40, 72).toString("hex"));
  });

  after(async () => {
    if ((globalThis as any).curve_bn128) await (globalThis as any).curve_bn128.terminate();
  });

  it("deposits and the on-chain Poseidon root matches circomlibjs", async () => {
    const acct = (await connection.getAccountInfo(poolPda))!;
    const leafIndex = acct.data.readUInt32LE(104);

    const value = 20_000_000n; // 0.02 SOL
    const nullifier = 11111n;
    const secret = 22222n;
    const precommitment = H([nullifier, secret]);
    const label = H([scope, BigInt(leafIndex)]);
    const commitment = H([value, label, precommitment]);

    await send(
      withCU(
        new TransactionInstruction({
          programId: PROGRAM,
          keys: [
            { pubkey: poolPda, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([disc("deposit"), be32(precommitment), u64le(value)]),
        }),
      ),
    );

    if (leafIndex === 0) {
      const after = (await connection.getAccountInfo(poolPda))!;
      const ri = after.data.readUInt32LE(108);
      const off = 8 + 32 + 32 + 32 + 4 + 4 + 32 * LEVELS;
      const onchain = BigInt("0x" + after.data.subarray(off + ri * 32, off + ri * 32 + 32).toString("hex"));
      expect(onchain.toString()).to.equal(singleLeafRoot(commitment).toString());
    }
  });

  it("rejects zero-value deposits", async () => {
    const logs = await sendExpectFail(
      withCU(
        new TransactionInstruction({
          programId: PROGRAM,
          keys: [
            { pubkey: poolPda, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([disc("deposit"), be32(1n), u64le(0n)]),
        }),
      ),
    );
    expect(logs).to.include("ZeroValue");
  });

  (canProve ? it : it.skip)(
    "full deposit -> proof -> withdraw pays out and consumes the nullifier",
    async function () {
      this.timeout(120_000);
      // Fresh deposit; record its leaf index for the (single-leaf-or-reconstructed) path.
      const acct = (await connection.getAccountInfo(poolPda))!;
      const leafIndex = acct.data.readUInt32LE(104);
      const value = 20_000_000n;
      const nullifier = BigInt("0x" + createHash("sha256").update("pl-n" + Date.now()).digest("hex")) >> 8n;
      const secret = BigInt("0x" + createHash("sha256").update("pl-s" + Date.now()).digest("hex")) >> 8n;
      const precommitment = H([nullifier, secret]);
      const label = H([scope, BigInt(leafIndex)]);

      await send(
        withCU(
          new TransactionInstruction({
            programId: PROGRAM,
            keys: [
              { pubkey: poolPda, isSigner: false, isWritable: true },
              { pubkey: payer.publicKey, isSigner: true, isWritable: true },
              { pubkey: SYS, isSigner: false, isWritable: false },
            ],
            data: Buffer.concat([disc("deposit"), be32(precommitment), u64le(value)]),
          }),
        ),
      );

      // Path for the just-inserted (rightmost) leaf: read the on-chain root and derive
      // the siblings from the cached filled_subtrees — for each level, a bit-0 (left
      // child) sibling is the zero subtree, a bit-1 (right child) sibling is the cached
      // left node. Works at any leaf index without full tree reconstruction.
      const after = (await connection.getAccountInfo(poolPda))!;
      const ri = after.data.readUInt32LE(108);
      const FILLED_OFF = 8 + 32 + 32 + 32 + 4 + 4;
      const off = FILLED_OFF + 32 * LEVELS;
      const stateRoot = BigInt("0x" + after.data.subarray(off + ri * 32, off + ri * 32 + 32).toString("hex"));
      const filled = (i: number) =>
        BigInt("0x" + after.data.subarray(FILLED_OFF + i * 32, FILLED_OFF + i * 32 + 32).toString("hex"));
      const stateSiblings: bigint[] = [];
      const stateIndex: number[] = [];
      for (let i = 0; i < LEVELS; i++) {
        const bit = (leafIndex >> i) & 1;
        stateSiblings.push(bit === 1 ? filled(i) : zeros[i]);
        stateIndex.push(bit);
      }

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

      const recipient = Keypair.generate().publicKey;
      const feeRecipient = payer.publicKey;
      const fee = 0n;
      const ctxPre = Buffer.concat([recipient.toBuffer(), feeRecipient.toBuffer(), be64(fee), be32(scope)]);
      const ctxHash = Buffer.from(keccak_256(ctxPre));
      ctxHash[0] &= 0x1f;
      const context = BigInt("0x" + ctxHash.toString("hex"));

      const withdrawnValue = 8_000_000n;
      const remainder = value - withdrawnValue;
      const newNullifier = nullifier + 1n;
      const newSecret = secret + 1n;
      const newCommitment = H([remainder, label, H([newNullifier, newSecret])]);
      const nullifierHash = H([nullifier]);

      const input = {
        value: value.toString(), label: label.toString(),
        nullifier: nullifier.toString(), secret: secret.toString(),
        new_nullifier: newNullifier.toString(), new_secret: newSecret.toString(),
        state_siblings: stateSiblings.map(String), state_index: stateIndex.map(String),
        asp_siblings: zeros.slice(0, LEVELS).map(String), asp_index: Array(LEVELS).fill(0),
        withdrawn_value: withdrawnValue.toString(), state_root: stateRoot.toString(),
        asp_root: aspRoot.toString(), nullifier_hash: nullifierHash.toString(),
        new_commitment: newCommitment.toString(), context: context.toString(),
      };
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
      expect(publicSignals[3]).to.equal(nullifierHash.toString());

      const g1 = (p: string[]) => Buffer.concat([be32(BigInt(p[0])), be32(BigInt(p[1]))]);
      const g2 = (p: string[][]) =>
        Buffer.concat([be32(BigInt(p[0][1])), be32(BigInt(p[0][0])), be32(BigInt(p[1][1])), be32(BigInt(p[1][0]))]);

      const wIx = new TransactionInstruction({
        programId: PROGRAM,
        keys: [
          { pubkey: poolPda, isSigner: false, isWritable: true },
          { pubkey: nullifierPda(nullifierHash), isSigner: false, isWritable: true },
          { pubkey: recipient, isSigner: false, isWritable: true },
          { pubkey: feeRecipient, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          disc("withdraw"), g1(proof.pi_a), g2(proof.pi_b), g1(proof.pi_c),
          u64le(withdrawnValue), be32(stateRoot), be32(nullifierHash), be32(newCommitment), u64le(fee),
        ]),
      });

      const before = await connection.getBalance(recipient);
      await send(withCU(wIx));
      expect(await connection.getBalance(recipient)).to.equal(before + Number(withdrawnValue));
      expect(await connection.getAccountInfo(nullifierPda(nullifierHash))).to.not.be.null;

      // Replay rejected (nullifier PDA already exists).
      const replay = await sendExpectFail(withCU(wIx));
      expect(replay).to.include("already in use");
    },
  );
});

function be64(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
}
