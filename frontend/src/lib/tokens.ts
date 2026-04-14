/**
 * Token configuration for Solana. Native SOL only.
 */

export type TokenInfo = {
  symbol: string;
  name: string;
  decimals: number;
  mint: null;
};

const NATIVE_SOL: TokenInfo = {
  symbol: "SOL",
  name: "Solana",
  decimals: 9,
  mint: null,
};

/**
 * All selectable assets: native SOL only.
 */
export function getSelectableAssets(): TokenInfo[] {
  return [NATIVE_SOL];
}

/**
 * Get the native SOL token info.
 */
export function getNativeToken(): TokenInfo {
  return NATIVE_SOL;
}
