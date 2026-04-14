/**
 * Centralized Solana program configuration.
 * Maps cluster to program IDs.
 */

import { PublicKey } from "@solana/web3.js";
import type { SolanaCluster } from "../lib/chain";
import { deployedAddresses } from "./deployedAddresses";

export type ClusterProgramConfig = {
  registryProgram: PublicKey;
  announcerProgram: PublicKey;
  groth16Program: PublicKey;
  reputationProgram: PublicKey;
};

const STATIC_CONFIG: Partial<Record<SolanaCluster, ClusterProgramConfig>> = {
  devnet: {
    registryProgram: new PublicKey(deployedAddresses.stealthRegistry),
    announcerProgram: new PublicKey(deployedAddresses.stealthAnnouncer),
    groth16Program: new PublicKey(deployedAddresses.groth16Verifier),
    reputationProgram: new PublicKey(deployedAddresses.reputationVerifier),
  },
};

export const CLUSTER_CONFIG: Partial<Record<SolanaCluster, ClusterProgramConfig>> = {
  ...STATIC_CONFIG,
};

export function getConfigForCluster(
  cluster: SolanaCluster | null | undefined
): ClusterProgramConfig | null {
  if (cluster == null) return null;
  return CLUSTER_CONFIG[cluster] ?? null;
}

export const SUPPORTED_CLUSTERS: readonly SolanaCluster[] = ["devnet"];

export function isClusterSupported(cluster: SolanaCluster | null | undefined): boolean {
  return cluster != null && SUPPORTED_CLUSTERS.includes(cluster);
}
