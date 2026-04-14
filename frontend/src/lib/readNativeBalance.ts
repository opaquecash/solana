import { Connection, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";

/**
 * Reads native SOL balance for an address.
 */
export async function readNativeBalance(
  address: string,
  connection: Connection,
): Promise<bigint> {
  const pubkey = new PublicKey(address);
  const balance = await connection.getBalance(pubkey);
  return BigInt(balance);
}

/**
 * Format lamports to human-readable SOL string.
 */
export function lamportsToSol(lamports: bigint): string {
  const sol = Number(lamports) / LAMPORTS_PER_SOL;
  return sol.toFixed(9).replace(/\.?0+$/, "");
}
