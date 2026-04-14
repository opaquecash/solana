/**
 * Reputation / Groth16 program IDs (must match `deployedAddresses` on-chain targets).
 * Replace after deploy; strings must be valid Solana base58.
 */

import { deployedAddresses } from "./deployedAddresses";

export const reputationAddresses = {
  cluster: deployedAddresses.cluster,
  groth16Verifier: deployedAddresses.groth16Verifier,
  reputationVerifier: deployedAddresses.reputationVerifier,
  admin: "" as const,
} as const;

export type ReputationAddresses = typeof reputationAddresses;
