import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

export const PROGRAMS = {
  stealthRegistry: new PublicKey("E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno"),
  stealthAnnouncer: new PublicKey("HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf"),
  groth16Verifier: new PublicKey("6mFaKyp7F4NqNeoiBLEWSqy5wJSk7rWf1EYumVXgHvhQ"),
  reputationVerifier: new PublicKey("BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM"),
  schemaRegistry: new PublicKey("FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB"),
  attestationEngineV2: new PublicKey("4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM"),
  uabReceiver: new PublicKey("7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM"),
};

export const WORMHOLE_CORE = new PublicKey("3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5");

/** Anchor sets these when running `anchor test`. */
export const connection = new Connection(
  process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899",
  "confirmed",
);
export const payer = Keypair.fromSecretKey(
  Uint8Array.from(
    JSON.parse(
      readFileSync(
        process.env.ANCHOR_WALLET ?? `${process.env.HOME}/.config/solana/id.json`,
        "utf8",
      ),
    ),
  ),
);

/** Anchor global instruction discriminator. */
export const disc = (name: string): Buffer =>
  createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);

export const pda = (program: PublicKey, seeds: Array<Buffer | Uint8Array>): PublicKey =>
  PublicKey.findProgramAddressSync(seeds.map(Buffer.from), program)[0];

export const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);
/** The ProgramData account of an upgradeable program (holds its upgrade authority). */
export const programData = (program: PublicKey): PublicKey =>
  PublicKey.findProgramAddressSync([program.toBuffer()], BPF_LOADER_UPGRADEABLE)[0];

export const u32le = (n: number): Buffer => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
export const u64le = (n: number | bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};
export const u16le = (n: number): Buffer => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
};
/** Borsh Vec<u8>. */
export const vec = (bytes: Uint8Array): Buffer =>
  Buffer.concat([u32le(bytes.length), Buffer.from(bytes)]);
/** Borsh String. */
export const str = (s: string): Buffer => vec(Buffer.from(s, "utf8"));
/** Decimal field element → 32-byte big-endian. */
export const be32 = (dec: string | bigint): Buffer => {
  let n = BigInt(dec);
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

export async function send(
  ixs: TransactionInstruction[],
  signers: Keypair[] = [],
): Promise<string> {
  const tx = new Transaction().add(...ixs);
  return sendAndConfirmTransaction(connection, tx, [payer, ...signers], {
    commitment: "confirmed",
  });
}

/** Send and expect failure; returns the error string for log assertions. */
export async function sendExpectFail(
  ixs: TransactionInstruction[],
  signers: Keypair[] = [],
): Promise<string> {
  try {
    await send(ixs, signers);
  } catch (e) {
    return String((e as Error & { logs?: string[] })?.logs?.join("\n") ?? e);
  }
  throw new Error("transaction unexpectedly succeeded");
}

export function loadV2Fixture(): {
  proofA: Buffer;
  proofB: Buffer;
  proofC: Buffer;
  publicSignals: string[];
} {
  const dir = `${__dirname}/../circuits/test/fixtures/v2`;
  const load = (f: string) => JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
  const proof = load("proof.json");
  const publicSignals: string[] = load("public.json");
  const g1 = (p: string[]) => Buffer.concat([be32(p[0]), be32(p[1])]);
  const g2 = (p: string[][]) =>
    Buffer.concat([be32(p[0][1]), be32(p[0][0]), be32(p[1][1]), be32(p[1][0])]);
  return {
    proofA: g1(proof.pi_a),
    proofB: g2(proof.pi_b),
    proofC: g1(proof.pi_c),
    publicSignals,
  };
}

// ---------------------------------------------------------------------------
// DKSAP scanner math (Phase 3.1 cross-chain ownership assertions)
// ---------------------------------------------------------------------------

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

export const hexBytes = (s: string): Uint8Array =>
  Uint8Array.from(Buffer.from(s.replace(/^0x/, ""), "hex"));

/** The canonical CSAP DKSAP test vector (cross-validated scanner/SDK/circuits data). */
export function loadDksapVector(): {
  viewing_private_key: string;
  spending_public_key: string;
  ephemeral_public_key: string;
  stealth_address: string;
  view_tag: number;
  scheme_id: number;
} {
  return JSON.parse(
    readFileSync(`${__dirname}/../circuits/test/test_vectors.json`, "utf8"),
  ).dksap[0];
}

/**
 * Receiver-side DKSAP derivation (CSAP 2.3): shared = view_priv * EphPub;
 * s_h = keccak256(shared); stealth = SpendPub + s_h * G; address =
 * keccak256(uncompressed(stealth))[12..32]. This IS the scanner ownership check.
 */
export function deriveStealthAddress(
  viewPriv: Uint8Array,
  spendPub: Uint8Array,
  ephPub: Uint8Array,
): { address: Uint8Array; viewTag: number } {
  const shared = secp256k1.getSharedSecret(viewPriv, ephPub, true);
  const sH = keccak_256(shared);
  const viewTag = sH[0];
  const sHScalar = BigInt(`0x${Buffer.from(sH).toString("hex")}`) % secp256k1.CURVE.n;
  const stealthPoint = secp256k1.ProjectivePoint.fromHex(
    Buffer.from(spendPub).toString("hex"),
  ).add(secp256k1.ProjectivePoint.BASE.multiply(sHScalar));
  const uncompressed = stealthPoint.toRawBytes(false);
  return { address: keccak_256(uncompressed.slice(1)).slice(12), viewTag };
}
