/**
 * Modular program config for Opaque Protocol frontend.
 * Uses program IDs from deployedAddresses.ts and Anchor IDLs.
 */

import { PublicKey } from "@solana/web3.js";
import { deployedAddresses } from "./deployedAddresses";

export type OpaqueProgramName =
  | "StealthAnnouncer"
  | "StealthRegistry"
  | "Groth16Verifier"
  | "ReputationVerifier"
  | "SchemaRegistry"
  | "AttestationEngineV2";

const programIds: Record<OpaqueProgramName, PublicKey> = {
  StealthAnnouncer: new PublicKey(deployedAddresses.stealthAnnouncer),
  StealthRegistry: new PublicKey(deployedAddresses.stealthRegistry),
  Groth16Verifier: new PublicKey(deployedAddresses.groth16Verifier),
  ReputationVerifier: new PublicKey(deployedAddresses.reputationVerifier),
  SchemaRegistry: new PublicKey(deployedAddresses.schemaRegistry),
  AttestationEngineV2: new PublicKey(deployedAddresses.attestationEngineV2),
};

export function getProgramId(name: OpaqueProgramName): PublicKey {
  return programIds[name];
}

export { deployedAddresses };
