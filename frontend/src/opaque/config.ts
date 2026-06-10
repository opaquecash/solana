/**
 * Configuration for the `@opaquecash/opaque` SDK session. Solana stays the primary chain
 * (cluster + RPC come from `lib/chain`); the Ethereum (Sepolia) values enable the multichain
 * paths — EVM send, UAB relay, EVM PSR, and cross-chain scan — when an ETH wallet is connected.
 */

import { getCluster, getRpcUrl } from "../lib/chain";

/** Sepolia chain id (the only EVM chain Opaque is deployed to today). */
export const SEPOLIA_CHAIN_ID = 11155111;

/** Sepolia JSON-RPC for EVM reads/writes. Override with `VITE_SEPOLIA_RPC_URL`. */
export const SEPOLIA_RPC_URL =
  (import.meta.env.VITE_SEPOLIA_RPC_URL as string | undefined)?.trim() ||
  "https://ethereum-sepolia.publicnode.com";

/** Solana cluster + RPC, resolved from the existing `lib/chain` env conventions. */
export const SOLANA_CLUSTER = getCluster();
export const SOLANA_RPC_URL = getRpcUrl();

/**
 * Dynamic-import URL for the wasm-pack `cryptography.js`. Defaults to the hosted artifact;
 * override with `VITE_WASM_URL` (e.g. a copied local `/pkg/cryptography.js`).
 */
export const WASM_MODULE_SPECIFIER =
  (import.meta.env.VITE_WASM_URL as string | undefined)?.trim() ||
  "https://www.opaque.cash/pkg/cryptography.js";

/**
 * Placeholder EVM address used when no Ethereum wallet is connected. The stealth identity is
 * derived from the Solana wallet signature, so Solana-only flows (scan, send, sweep) work with
 * this placeholder; EVM writes require a real connected address (the session recreates the
 * client when one connects).
 */
export const PLACEHOLDER_EVM_ADDRESS =
  "0x0000000000000000000000000000000000000000" as const;
