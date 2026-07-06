/**
 * Generate the ONS genesis fixtures under tests/fixtures/:
 *
 *  - ons-vaa-upsert.json / ons-vaa-revoke.json / ons-vaa-stale.json — Wormhole
 *    posted-VAA accounts carrying 164-byte ONS mirror payloads (spec/ONS.md 5.1)
 *    from the canonical Ethereum registry emitter, as the core bridge would store
 *    them after guardian verification (which is Wormhole's code, bypassed by
 *    construction: the accounts are genesis-loaded with the core bridge as owner).
 *  - ons-claim-*.json — ons-registration ProvisionalClaim PDAs in each reconcile
 *    state (confirmed / lost / expired / pending).
 *  - ons-mirror-*.json — ons-mirror OnsRecord PDAs backing the confirmed and lost
 *    reconcile outcomes.
 *
 * Loaded at genesis via [[test.validator.account]] in Anchor.toml so tests/ons.ts
 * has deterministic positive paths on localnet (no core bridge, no relay).
 *
 *   node scripts/generate-ons-fixtures.mjs
 *
 * Deterministic: same inputs -> same bytes. Commit the output.
 */
import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Keypair, PublicKey } from "@solana/web3.js";
import { keccak_256 } from "@noble/hashes/sha3";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORMHOLE_CORE = "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5";
const ONS_MIRROR = new PublicKey("D7EXuwcsGrUAYC6k69jrKvsKethsKYgR1pokkTcFvWsk");
const ONS_REGISTRATION = new PublicKey("5gfK9J8FJi3FpsQD33Hkrfwq8KqN4yadB2PDF9REnwMT");

// Must match the ons-mirror config initialized by tests/ons.ts.
const SOURCE_CHAIN_ETHEREUM = 2;
const ONS_EMITTER = Buffer.alloc(32, 7);
const PARENT_NAME = "opqtest.eth";

// Posted-VAA layout offsets (programs/ons-mirror/src/lib.rs).
const OFF_SEQUENCE = 49;
const OFF_EMITTER_CHAIN = 57;
const OFF_EMITTER_ADDRESS = 59;
const OFF_PAYLOAD_LEN = 91;
const OFF_PAYLOAD = 95;
const ONS_PAYLOAD_LEN = 164;

const SPEND = Buffer.concat([Buffer.from([2]), Buffer.alloc(32, 0x11)]);
const VIEW = Buffer.concat([Buffer.from([3]), Buffer.alloc(32, 0x22)]);
const ETH_OWNER = Buffer.alloc(20, 0x33);

// Deterministic claimer for the reconcile fixtures (tests refund rent to it).
const claimer = Keypair.fromSeed(createHash("sha256").update("opaque-ons-claimer").digest());
const otherAuthority = Keypair.fromSeed(
  createHash("sha256").update("opaque-ons-other-authority").digest(),
);

const nameHash = (label) => Buffer.from(keccak_256(`${label}.${PARENT_NAME}`));
const discAccount = (name) =>
  createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);
const fixtureAddress = (tag) =>
  Keypair.fromSeed(createHash("sha256").update(tag).digest()).publicKey.toBase58();

const fixtures = [];
const account = (pubkey, owner, data) => ({
  pubkey,
  account: {
    lamports: 10_000_000,
    data: [data.toString("base64"), "base64"],
    owner,
    executable: false,
    rentEpoch: 0,
  },
});

// ---------------------------------------------------------------- posted VAAs

function onsMirrorPayload(action, label, solAuthority = Buffer.alloc(32)) {
  const p = Buffer.alloc(ONS_PAYLOAD_LEN);
  p[0] = 1; // version
  p[1] = action;
  nameHash(label).copy(p, 2);
  if (action === 1) {
    SPEND.copy(p, 34);
    VIEW.copy(p, 67);
  }
  ETH_OWNER.copy(p, 112); // low 20 bytes of the padded 32-byte word [100..132)
  solAuthority.copy(p, 132);
  return p;
}

function postedVaa(sequence, payload) {
  const data = Buffer.alloc(OFF_PAYLOAD + payload.length);
  data.write("vaa", 0, "ascii");
  data.writeBigUInt64LE(BigInt(sequence), OFF_SEQUENCE);
  data.writeUInt16LE(SOURCE_CHAIN_ETHEREUM, OFF_EMITTER_CHAIN);
  ONS_EMITTER.copy(data, OFF_EMITTER_ADDRESS);
  data.writeUInt32LE(payload.length, OFF_PAYLOAD_LEN);
  payload.copy(data, OFF_PAYLOAD);
  return data;
}

fixtures.push([
  "ons-vaa-upsert",
  account(fixtureAddress("opaque-ons-vaa-upsert"), WORMHOLE_CORE, postedVaa(11, onsMirrorPayload(1, "alice"))),
]);
fixtures.push([
  "ons-vaa-revoke",
  account(fixtureAddress("opaque-ons-vaa-revoke"), WORMHOLE_CORE, postedVaa(12, onsMirrorPayload(2, "alice"))),
]);
// Older sequence than the upsert: must be rejected as stale once 11 is applied.
fixtures.push([
  "ons-vaa-stale",
  account(fixtureAddress("opaque-ons-vaa-stale"), WORMHOLE_CORE, postedVaa(5, onsMirrorPayload(1, "alice"))),
]);

// ------------------------------------------------- reconcile-state fixtures

function provisionalClaim(label, createdAt) {
  const hash = nameHash(label);
  const [pdaAddr, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("ons_claim"), hash],
    ONS_REGISTRATION,
  );
  const data = Buffer.alloc(8 + 32 + 32 + 8 + 1);
  discAccount("ProvisionalClaim").copy(data, 0);
  claimer.publicKey.toBuffer().copy(data, 8);
  hash.copy(data, 40);
  data.writeBigInt64LE(BigInt(createdAt), 72);
  data[80] = bump;
  return account(pdaAddr.toBase58(), ONS_REGISTRATION.toBase58(), data);
}

function mirrorRecord(label, solAuthority) {
  const hash = nameHash(label);
  const [pdaAddr, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("ons_mirror"), hash],
    ONS_MIRROR,
  );
  const data = Buffer.alloc(8 + 32 + 33 + 33 + 20 + 32 + 8 + 8 + 1 + 1);
  discAccount("OnsRecord").copy(data, 0);
  hash.copy(data, 8);
  SPEND.copy(data, 40);
  VIEW.copy(data, 73);
  ETH_OWNER.copy(data, 106);
  solAuthority.copy(data, 126);
  data.writeBigUInt64LE(20n, 158); // wormhole_sequence
  data.writeBigInt64LE(1_700_000_000n, 166); // updated_at
  data[174] = bump;
  // data[175] = revoked (0 = live record)
  return account(pdaAddr.toBase58(), ONS_MIRROR.toBase58(), data);
}

// Confirmed: mirror record exists with the claimer as sol_authority.
fixtures.push(["ons-claim-confirmed", provisionalClaim("bob-confirmed", 1_700_000_000)]);
fixtures.push(["ons-mirror-confirmed", mirrorRecord("bob-confirmed", claimer.publicKey.toBuffer())]);

// Lost: mirror record exists for a different owner (canonical chain won).
fixtures.push(["ons-claim-lost", provisionalClaim("bob-lost", 1_700_000_000)]);
fixtures.push(["ons-mirror-lost", mirrorRecord("bob-lost", otherAuthority.publicKey.toBuffer())]);

// Expired: no mirror record, created_at far in the past (pending window elapsed).
fixtures.push(["ons-claim-expired", provisionalClaim("bob-expired", 0)]);

// Pending: no mirror record, created_at far in the future of any test run.
fixtures.push(["ons-claim-pending", provisionalClaim("bob-pending", 99_999_999_999)]);

// ----------------------------------------------------------------- write out

mkdirSync(join(ROOT, "tests", "fixtures"), { recursive: true });
for (const [name, fixture] of fixtures) {
  writeFileSync(
    join(ROOT, "tests", "fixtures", `${name}.json`),
    JSON.stringify(fixture, null, 2) + "\n",
  );
  console.log(`${name}.json -> ${fixture.pubkey}`);
}
console.log(`claimer: ${claimer.publicKey.toBase58()}`);
