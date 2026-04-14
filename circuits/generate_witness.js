/**
 * Witness generator for the Stealth Attestation circuit.
 *
 * Builds a sample Merkle tree from announcement data, generates an
 * inclusion proof, and writes the input.json needed by the circuit WASM.
 *
 * Usage: node generate_witness.js [--attestation-id <id>] [--external-nullifier <n>]
 */

import { buildPoseidon } from "circomlibjs";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const TREE_DEPTH = 20;

function randomField(poseidon) {
  const F = poseidon.F;
  const buf = crypto.randomBytes(32);
  return F.e(BigInt("0x" + buf.toString("hex")) % F.p);
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const args = process.argv.slice(2);
  const attestationIdIdx = args.indexOf("--attestation-id");
  const nullifierIdx = args.indexOf("--external-nullifier");

  const attestationId = attestationIdIdx !== -1
    ? BigInt(args[attestationIdIdx + 1])
    : BigInt(42);
  const externalNullifier = nullifierIdx !== -1
    ? BigInt(args[nullifierIdx + 1])
    : BigInt(1001);

  // BabyJubJub base point
  const BASE_X = BigInt("5299619240641551281634865583518297030282874472190772894086521144482721001553");
  const BASE_Y = BigInt("16950150798460657717958625567821834550301663161624707787222815936182638968203");

  // Generate a stealth private key (field element)
  const stealthPrivKey = BigInt("0x" + crypto.randomBytes(31).toString("hex")) % F.p;

  // Derive stealth public key (P = privKey * G on BabyJubJub)
  // For witness generation we use the eddsa module from circomlibjs
  const { buildBabyjub } = await import("circomlibjs");
  const babyjub = await buildBabyjub();
  const stealthPubKey = babyjub.mulPointEscalar(babyjub.Base8, stealthPrivKey);
  const stealthPubKeyX = F.toObject(stealthPubKey[0]);
  const stealthPubKeyY = F.toObject(stealthPubKey[1]);

  // Generate ephemeral key pair
  const ephemeralPrivKey = BigInt("0x" + crypto.randomBytes(31).toString("hex")) % F.p;
  const ephemeralPubKey = babyjub.mulPointEscalar(babyjub.Base8, ephemeralPrivKey);
  const ephemeralPubX = F.toObject(ephemeralPubKey[0]);
  const ephemeralPubY = F.toObject(ephemeralPubKey[1]);

  // Compute shared secret: S = stealth_priv * ephemeral_pub
  const sharedSecret = babyjub.mulPointEscalar(ephemeralPubKey, stealthPrivKey);
  const sharedX = F.toObject(sharedSecret[0]);
  const sharedY = F.toObject(sharedSecret[1]);

  // Stealth address commitment = Poseidon(shared_x, shared_y, pub_x, pub_y)
  const addressCommitment = poseidon([sharedX, sharedY, stealthPubKeyX, stealthPubKeyY]);
  const addressCommitmentVal = F.toObject(addressCommitment);

  // Announcement leaf = Poseidon(addressCommitment, attestationId)
  const leaf = poseidon([addressCommitmentVal, attestationId]);
  const leafVal = F.toObject(leaf);

  // Build the Merkle tree with the target leaf at index 0
  const numLeaves = 1 << TREE_DEPTH;
  const zeroVal = F.toObject(poseidon([BigInt(0), BigInt(0)]));
  let currentLevel = new Array(numLeaves);
  currentLevel[0] = leafVal;
  for (let i = 1; i < numLeaves; i++) {
    currentLevel[i] = zeroVal;
  }

  const pathElements = [];
  const pathIndices = [];
  let targetIdx = 0;

  for (let depth = 0; depth < TREE_DEPTH; depth++) {
    const nextLevel = [];
    const siblingIdx = targetIdx % 2 === 0 ? targetIdx + 1 : targetIdx - 1;
    pathElements.push(currentLevel[siblingIdx].toString());
    pathIndices.push(targetIdx % 2 === 0 ? 0 : 1);

    for (let i = 0; i < currentLevel.length; i += 2) {
      const h = poseidon([currentLevel[i], currentLevel[i + 1]]);
      nextLevel.push(F.toObject(h));
    }
    currentLevel = nextLevel;
    targetIdx = Math.floor(targetIdx / 2);
  }

  const merkleRoot = currentLevel[0];

  // Compute expected nullifier = Poseidon(stealth_priv, external_nullifier)
  const expectedNullifier = F.toObject(poseidon([stealthPrivKey, externalNullifier]));

  const input = {
    merkle_root: merkleRoot.toString(),
    attestation_id: attestationId.toString(),
    external_nullifier: externalNullifier.toString(),
    stealth_private_key: stealthPrivKey.toString(),
    ephemeral_pubkey: [ephemeralPubX.toString(), ephemeralPubY.toString()],
    announcement_attestation_id: attestationId.toString(),
    merkle_path_elements: pathElements,
    merkle_path_indices: pathIndices,
  };

  const outDir = path.join(import.meta.dirname, "build");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "input.json"), JSON.stringify(input, null, 2));

  console.log("Witness input written to build/input.json");
  console.log(`  Attestation ID:     ${attestationId}`);
  console.log(`  External Nullifier: ${externalNullifier}`);
  console.log(`  Merkle Root:        ${merkleRoot}`);
  console.log(`  Expected Nullifier: ${expectedNullifier}`);
  console.log(`  Stealth PubKey:     (${stealthPubKeyX}, ${stealthPubKeyY})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
