/**
 * Generate tests/fixtures/posted-vaa.json: a Wormhole posted-VAA account carrying a
 * canonical 96-byte UAB payload for the CSAP test-vector recipient, as the core
 * bridge would store it after verifying guardian signatures.
 *
 * The local validator loads it at genesis ([[test.validator.account]] in
 * Anchor.toml), giving the integration tests a deterministic POSITIVE
 * `receive_announcement` path: Ethereum-origin announcement -> posted VAA ->
 * uab-receiver re-emit -> scanner ownership. Guardian signature verification is the
 * core bridge's job and is bypassed by construction (the account is genesis-loaded
 * with the core bridge as owner); everything Opaque-owned is real.
 *
 *   node scripts/generate-vaa-fixture.mjs
 *
 * Deterministic: same vectors -> same bytes. Commit the output.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair } from "@solana/web3.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORMHOLE_CORE = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";

// Must match the uab-receiver config initialized by tests/integration.ts.
const SOURCE_CHAIN_ETHEREUM = 2;
const SOURCE_EMITTER = Buffer.alloc(32, 9);
const SEQUENCE = 7n;

// Posted-VAA layout offsets (programs/uab-receiver/src/lib.rs).
const OFF_SEQUENCE = 49;
const OFF_EMITTER_CHAIN = 57;
const OFF_EMITTER_ADDRESS = 59;
const OFF_PAYLOAD_LEN = 91;
const OFF_PAYLOAD = 95;
const UAB_PAYLOAD_LEN = 96;

const vectors = JSON.parse(
  readFileSync(join(ROOT, "circuits", "test", "test_vectors.json"), "utf8"),
).dksap[0];
const hex = (s) => Buffer.from(s.replace(/^0x/, ""), "hex");
const ephemeralPubKey = hex(vectors.ephemeral_public_key); // 33 bytes
const stealthAddress = hex(vectors.stealth_address); // 20 bytes
const viewTag = Number(vectors.view_tag);

// Canonical 96-byte UAB payload (spec/payload-format.md), Ethereum-origin.
const payload = Buffer.alloc(UAB_PAYLOAD_LEN);
payload[0] = viewTag;
ephemeralPubKey.copy(payload, 1);
stealthAddress.copy(payload, 66 - stealthAddress.length); // left-pad into [34..66)
payload.writeUInt16BE(SOURCE_CHAIN_ETHEREUM, 66);
payload.writeUInt32BE(Number(vectors.scheme_id), 68);
// metadata tail [72..96) stays zero (view tag is not repeated).

const data = Buffer.alloc(OFF_PAYLOAD + UAB_PAYLOAD_LEN);
data.write("vaa", 0, "ascii");
data.writeBigUInt64LE(SEQUENCE, OFF_SEQUENCE);
data.writeUInt16LE(SOURCE_CHAIN_ETHEREUM, OFF_EMITTER_CHAIN);
SOURCE_EMITTER.copy(data, OFF_EMITTER_ADDRESS);
data.writeUInt32LE(UAB_PAYLOAD_LEN, OFF_PAYLOAD_LEN);
payload.copy(data, OFF_PAYLOAD);

// Deterministic account address (no private key needed; derived from a fixed seed).
const seed = createHash("sha256").update("opaque-uab-posted-vaa-fixture").digest();
const address = Keypair.fromSeed(seed).publicKey.toBase58();

const fixture = {
  pubkey: address,
  account: {
    lamports: 10_000_000,
    data: [data.toString("base64"), "base64"],
    owner: WORMHOLE_CORE,
    executable: false,
    rentEpoch: 0,
  },
};

mkdirSync(join(ROOT, "tests", "fixtures"), { recursive: true });
writeFileSync(
  join(ROOT, "tests", "fixtures", "posted-vaa.json"),
  JSON.stringify(fixture, null, 2) + "\n",
);
console.log(`posted-vaa fixture at ${address}`);
console.log(`  payload: viewTag=${viewTag} stealth=0x${stealthAddress.toString("hex")} seq=${SEQUENCE}`);
