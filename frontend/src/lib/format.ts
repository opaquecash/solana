/**
 * UI-only display + encoding helpers. No protocol crypto — these moved out of the (now removed)
 * `lib/stealth.ts` so components can format SOL and hex without importing the SDK internals.
 */

const LAMPORTS_PER_SOL = 1_000_000_000n;

/** Format lamports as a trimmed SOL string (e.g. `1.5`, `0.001`). */
export function formatSol(lamports: bigint): string {
  const negative = lamports < 0n;
  const abs = negative ? -lamports : lamports;
  const whole = abs / LAMPORTS_PER_SOL;
  const frac = abs % LAMPORTS_PER_SOL;
  let fracStr = frac.toString().padStart(9, "0").replace(/0+$/, "");
  const out = fracStr.length > 0 ? `${whole}.${fracStr}` : `${whole}`;
  return negative ? `-${out}` : out;
}

/** Parse hex (with or without `0x`) into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Lowercase `0x`-prefixed hex for a byte array. */
export function bytesToHex(b: Uint8Array): string {
  return "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Shorten an address/hash for display: `abcd…wxyz`. */
export function shortenAddress(value: string, lead = 6, tail = 4): string {
  if (value.length <= lead + tail + 1) return value;
  return `${value.slice(0, lead)}…${value.slice(-tail)}`;
}
