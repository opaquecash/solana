/**
 * Conditional-disclosure program tests (spec/conditional-disclosure.md) on the Anchor
 * local validator. Validates policy registration (group-key + quorum checks), and —
 * when the circuit artifacts are present — a full deposit → fresh disclosure proof →
 * BIP-340 quorum signature → disclose flow with replay and bad-signature rejection.
 * The quorum signature is produced single-signer with @noble/curves schnorr (a FROST
 * aggregate is byte-identical; the real M-of-N ceremony is the Phase 7.5 acceptance).
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
import { schnorr } from "@noble/curves/secp256k1";
// @ts-expect-error untyped
import * as snarkjs from "snarkjs";

import { connection, disc, payer, pda, programData, send, sendExpectFail, u64le } from "./helpers";

const PROGRAM = new PublicKey("7sDCTbMDwjzYA3KHhNPZUVa8Swvj6adJTgSkJqmsn6V7");
const POOL_PROGRAM = new PublicKey("5NjweHM4z7NrG4NLVUyJ8rtX8jLM3xtBWAR1wSJZ7vjY");
const SYS = SystemProgram.programId;
const LEVELS = 20;
const CIRCUITS = path.join(__dirname, "..", "..", "circuits");
const WASM = path.join(CIRCUITS, "v2", "build", "conditional_disclosure_js", "conditional_disclosure.wasm");
const ZKEY = path.join(CIRCUITS, "v2", "build", "conditional_disclosure_final.zkey");
const canProve = existsSync(WASM) && existsSync(ZKEY);

// keccak256("opaque/disclosure/v1") mod r — spec §7.
const DOMAIN_DISCLOSURE =
  2892858644728810973983554811705195156385130922452064297470708309156017996001n;
const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

const be32 = (x: bigint) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");
const poolPda = pda(POOL_PROGRAM, [Buffer.from("pool")]);
const policyPda = (groupKeyX: Buffer) => pda(PROGRAM, [Buffer.from("policy"), groupKeyX]);
const nullifierPda = (nh: bigint) => pda(PROGRAM, [Buffer.from("nullifier"), be32(nh)]);

const withCU = (ix: TransactionInstruction) => [
  ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }),
  ix,
];

/** lift_x: even-Y point for x (p ≡ 3 mod 4 → sqrt = ^((p+1)/4)). */
function liftY(x: bigint): bigint {
  const modpow = (b: bigint, e: bigint, m: bigint) => {
    let r = 1n;
    b %= m;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  };
  const y = modpow((x * x * x + 7n) % SECP_P, (SECP_P + 1n) / 4n, SECP_P);
  return y % 2n === 0n ? y : SECP_P - y;
}

const custodianSecret = new Uint8Array(32).fill(7);
const groupKeyX = Buffer.from(schnorr.getPublicKey(custodianSecret));

function signContext(context: Buffer): { rx: Buffer; ry: Buffer; s: Buffer } {
  const sig = schnorr.sign(context, custodianSecret);
  const rx = BigInt("0x" + Buffer.from(sig.slice(0, 32)).toString("hex"));
  return {
    rx: be32(rx),
    ry: be32(liftY(rx)),
    s: Buffer.from(sig.slice(32)),
  };
}

describe("conditional-disclosure", () => {
  let H: (xs: bigint[]) => bigint;
  let zeros: bigint[];
  let scope: bigint;

  before(async () => {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    H = (xs) => F.toObject(poseidon(xs)) as bigint;
    zeros = [0n];
    for (let i = 1; i <= LEVELS; i++) zeros.push(H([zeros[i - 1], zeros[i - 1]]));

    // The pool must exist (this file sorts before privacy-pool.ts).
    if (!(await connection.getAccountInfo(poolPda))) {
      await send([
        new TransactionInstruction({
          programId: POOL_PROGRAM,
          keys: [
            { pubkey: poolPda, isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: POOL_PROGRAM, isSigner: false, isWritable: false },
            { pubkey: programData(POOL_PROGRAM), isSigner: false, isWritable: false },
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

  const registerPolicyIx = (gkx: Buffer, threshold: bigint, m: number, n: number) =>
    new TransactionInstruction({
      programId: PROGRAM,
      keys: [
        { pubkey: policyPda(gkx), isSigner: false, isWritable: true },
        { pubkey: poolPda, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SYS, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        disc("register_policy"),
        gkx,
        u64le(threshold),
        Buffer.from([m, n]),
      ]),
    });

  it("register_policy rejects a zero group key and a bad quorum", async () => {
    expect(await sendExpectFail([registerPolicyIx(Buffer.alloc(32), 1n, 2, 3)])).to.include(
      "InvalidGroupKey",
    );
    const otherKey = Buffer.from(schnorr.getPublicKey(new Uint8Array(32).fill(9)));
    expect(await sendExpectFail([registerPolicyIx(otherKey, 1n, 3, 2)])).to.include(
      "InvalidQuorum",
    );
  });

  it("register_policy stores the policy PDA", async () => {
    if (!(await connection.getAccountInfo(policyPda(groupKeyX)))) {
      await send([registerPolicyIx(groupKeyX, 10_000_000n, 2, 3)]);
    }
    const acct = (await connection.getAccountInfo(policyPda(groupKeyX)))!;
    expect(acct.owner.equals(PROGRAM)).to.equal(true);
    // pool(32) at offset 8; group_key_x(32) at 40; threshold u64le at 72.
    expect(acct.data.subarray(8, 40).equals(poolPda.toBuffer())).to.equal(true);
    expect(acct.data.subarray(40, 72).equals(groupKeyX)).to.equal(true);
    expect(acct.data.readBigUInt64LE(72)).to.equal(10_000_000n);
  });

  (canProve ? it : it.skip)(
    "quorum-authorized disclosure: proof + BIP-340 sig disclose a qualifying note",
    async function () {
      this.timeout(120_000);
      // Deposit a qualifying note (value 20M > threshold 10M).
      const acct0 = (await connection.getAccountInfo(poolPda))!;
      const leafIndex = acct0.data.readUInt32LE(104);
      const value = 20_000_000n;
      const nullifier =
        BigInt("0x" + createHash("sha256").update("cd-n" + Date.now()).digest("hex")) >> 8n;
      const secret =
        BigInt("0x" + createHash("sha256").update("cd-s" + Date.now()).digest("hex")) >> 8n;
      const label = H([scope, BigInt(leafIndex)]);

      await send(
        withCU(
          new TransactionInstruction({
            programId: POOL_PROGRAM,
            keys: [
              { pubkey: poolPda, isSigner: false, isWritable: true },
              { pubkey: payer.publicKey, isSigner: true, isWritable: true },
              { pubkey: SYS, isSigner: false, isWritable: false },
            ],
            data: Buffer.concat([disc("deposit"), be32(H([nullifier, secret])), u64le(value)]),
          }),
        ),
      );

      // Rightmost-leaf Merkle path from the cached filled_subtrees.
      const after = (await connection.getAccountInfo(poolPda))!;
      const ri = after.data.readUInt32LE(108);
      const FILLED_OFF = 8 + 32 + 32 + 32 + 4 + 4;
      const off = FILLED_OFF + 32 * LEVELS;
      const stateRoot = BigInt(
        "0x" + after.data.subarray(off + ri * 32, off + ri * 32 + 32).toString("hex"),
      );
      const filled = (i: number) =>
        BigInt("0x" + after.data.subarray(FILLED_OFF + i * 32, FILLED_OFF + i * 32 + 32).toString("hex"));
      const stateSiblings: bigint[] = [];
      const stateIndex: number[] = [];
      for (let i = 0; i < LEVELS; i++) {
        const bit = (leafIndex >> i) & 1;
        stateSiblings.push(bit === 1 ? filled(i) : zeros[i]);
        stateIndex.push(bit);
      }

      // context = keccak(policy ‖ case_id ‖ requester), top 3 bits cleared.
      const caseId = Buffer.alloc(32);
      caseId.write("case-7.3b");
      const requester = payer.publicKey;
      const ctxHash = Buffer.from(
        keccak_256(
          Buffer.concat([policyPda(groupKeyX).toBuffer(), caseId, requester.toBuffer()]),
        ),
      );
      ctxHash[0] &= 0x1f;
      const context = BigInt("0x" + ctxHash.toString("hex"));
      const threshold = 10_000_000n;
      const disclosureNullifier = H([nullifier, context, DOMAIN_DISCLOSURE]);

      const { proof } = await snarkjs.groth16.fullProve(
        {
          nullifier: nullifier.toString(),
          secret: secret.toString(),
          state_siblings: stateSiblings.map(String),
          state_index: stateIndex.map(String),
          value: value.toString(),
          label: label.toString(),
          threshold: threshold.toString(),
          state_root: stateRoot.toString(),
          disclosure_nullifier: disclosureNullifier.toString(),
          context: context.toString(),
        },
        WASM,
        ZKEY,
      );
      const g1 = (p: string[]) => Buffer.concat([be32(BigInt(p[0])), be32(BigInt(p[1]))]);
      const g2 = (p: string[][]) =>
        Buffer.concat([
          be32(BigInt(p[0][1])), be32(BigInt(p[0][0])),
          be32(BigInt(p[1][1])), be32(BigInt(p[1][0])),
        ]);

      const sig = signContext(ctxHash);
      const discloseIx = (s: Buffer) =>
        new TransactionInstruction({
          programId: PROGRAM,
          keys: [
            { pubkey: policyPda(groupKeyX), isSigner: false, isWritable: false },
            { pubkey: poolPda, isSigner: false, isWritable: false },
            { pubkey: nullifierPda(disclosureNullifier), isSigner: false, isWritable: true },
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([
            disc("disclose"),
            g1(proof.pi_a), g2(proof.pi_b), g1(proof.pi_c),
            u64le(value), be32(label), be32(stateRoot), be32(disclosureNullifier),
            caseId, sig.rx, sig.ry, s,
          ]),
        });

      // Tampered quorum signature → InvalidQuorumSignature (before any proof work).
      const badS = Buffer.from(sig.s);
      badS[31] ^= 1;
      expect(await sendExpectFail(withCU(discloseIx(badS)))).to.include(
        "InvalidQuorumSignature",
      );

      // Happy path: nullifier PDA created.
      await send(withCU(discloseIx(sig.s)));
      expect(await connection.getAccountInfo(nullifierPda(disclosureNullifier))).to.not.be.null;

      // Replay → nullifier PDA already exists. (Different CU limit so the replay tx
      // has a distinct signature; an identical tx would be deduped, not executed.)
      expect(
        await sendExpectFail([
          ComputeBudgetProgram.setComputeUnitLimit({ units: 999_999 }),
          discloseIx(sig.s),
        ]),
      ).to.include("already in use");
    },
  );
});
