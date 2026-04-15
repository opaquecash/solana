/**
 * Program IDs used by the frontend (devnet defaults).
 * Replace with real `anchor deploy` output when you deploy your own programs.
 * Placeholders must be valid base58 (no `0`, `O`, `I`, `l` — those are rejected by PublicKey).
 */

export const deployedAddresses = {
  cluster: "devnet" as const,
  stealthRegistry: "E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno" as const,
  stealthAnnouncer: "HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf" as const,
  groth16Verifier: "6mFaKyp7F4NqNeoiBLEWSqy5wJSk7rWf1EYumVXgHvhQ" as const,
  reputationVerifier: "BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM" as const,
  schemaRegistry: "FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB" as const,
  attestationEngineV2: "4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM" as const,
} as const;

export type DeployedAddresses = typeof deployedAddresses;
