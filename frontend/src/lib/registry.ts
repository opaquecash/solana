/**
 * StealthMetaAddressRegistry — resolve meta-address by Solana pubkey and check registration.
 * Uses the on-chain registry program PDA.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { REGISTRY_PROGRAM_ID, SCHEME_ID_SECP256K1 } from "./contracts";
import { getRpcUrl } from "./chain";
import type { Hex } from "./stealth";
import { bytesToHex } from "./stealth";

/** Account discriminator for RegistryEntry (first 8 bytes of sha256("account:RegistryEntry")) */
const REGISTRY_ENTRY_DISCRIMINATOR_SIZE = 8;

/**
 * Derive the PDA for a registrant's stealth meta-address.
 */
export function getRegistryEntryPda(
  registrant: PublicKey,
  schemeId: bigint = SCHEME_ID_SECP256K1
): PublicKey {
  const schemeIdBytes = Buffer.alloc(8);
  schemeIdBytes.writeBigUInt64LE(schemeId);
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("stealth_meta"), registrant.toBuffer(), schemeIdBytes],
    REGISTRY_PROGRAM_ID
  );
  return pda;
}

/**
 * Resolves a Solana public key to its 66-byte stealth meta-address via the Registry.
 *
 * @param address - Solana public key (base58)
 * @returns The 66-byte stealth meta-address as hex, or null if not registered
 */
export async function resolveMetaAddress(
  address: string,
): Promise<Hex | null> {
  const rpcUrl = getRpcUrl();
  const connection = new Connection(rpcUrl, "confirmed");
  const registrant = new PublicKey(address);
  const pda = getRegistryEntryPda(registrant);

  try {
    const accountInfo = await connection.getAccountInfo(pda);
    if (!accountInfo || !accountInfo.data) return null;

    const data = accountInfo.data;
    // Skip: 8 (discriminator) + 32 (registrant) + 8 (scheme_id) + 4 (vec len prefix)
    const offset = REGISTRY_ENTRY_DISCRIMINATOR_SIZE + 32 + 8 + 4;
    if (data.length < offset + 66) return null;

    const metaAddress = data.slice(offset, offset + 66);
    return ("0x" + bytesToHex(metaAddress)) as Hex;
  } catch {
    return null;
  }
}

/**
 * Returns whether the given address has a stealth meta-address registered.
 */
export async function isRegistered(address: string): Promise<boolean> {
  const meta = await resolveMetaAddress(address);
  return meta != null && meta.length === 2 + 66 * 2;
}

/**
 * Registry program ID for building registration transactions.
 */
export function getRegistryProgramId(): PublicKey {
  return REGISTRY_PROGRAM_ID;
}
