/**
 * Solana program instruction helpers for Opaque Protocol (Stealth Announcer).
 */

import {
  PublicKey,
  TransactionInstruction,
  SystemProgram,
} from "@solana/web3.js";
import { deployedAddresses } from "../contracts/deployedAddresses";

export const ANNOUNCER_PROGRAM_ID = new PublicKey(deployedAddresses.stealthAnnouncer);
export const REGISTRY_PROGRAM_ID = new PublicKey(deployedAddresses.stealthRegistry);

/** Stealth scheme ID for secp256k1 with view tags */
export const SCHEME_ID_SECP256K1 = 1n;

/**
 * Build an `announce` instruction for the Stealth Announcer program.
 *
 * @param caller - The signer's public key (wallet that calls announce)
 * @param schemeId - Stealth scheme (1 = secp256k1)
 * @param stealthAddress - The one-time stealth address bytes
 * @param ephemeralPubKey - 33-byte compressed secp256k1 ephemeral public key
 * @param metadata - First byte = view tag; rest is optional
 */
export function buildAnnounceInstruction(
  caller: PublicKey,
  schemeId: bigint,
  stealthAddress: Uint8Array,
  ephemeralPubKey: Uint8Array,
  metadata: Uint8Array
): TransactionInstruction {
  // Anchor discriminator for `announce` instruction
  const discriminator = Buffer.from([0x07, 0x1e, 0x64, 0xfa, 0x6e, 0xfd, 0x03, 0x95]);

  const schemeIdBuf = Buffer.alloc(8);
  schemeIdBuf.writeBigUInt64LE(schemeId);

  const stealthAddrLenBuf = Buffer.alloc(4);
  stealthAddrLenBuf.writeUInt32LE(stealthAddress.length);

  const ephKeyLenBuf = Buffer.alloc(4);
  ephKeyLenBuf.writeUInt32LE(ephemeralPubKey.length);

  const metaLenBuf = Buffer.alloc(4);
  metaLenBuf.writeUInt32LE(metadata.length);

  const data = Buffer.concat([
    discriminator,
    schemeIdBuf,
    stealthAddrLenBuf,
    Buffer.from(stealthAddress),
    ephKeyLenBuf,
    Buffer.from(ephemeralPubKey),
    metaLenBuf,
    Buffer.from(metadata),
  ]);

  return new TransactionInstruction({
    keys: [
      { pubkey: caller, isSigner: true, isWritable: true },
    ],
    programId: ANNOUNCER_PROGRAM_ID,
    data,
  });
}

/**
 * Build a `register_keys` instruction for the Stealth Registry program.
 */
export function buildRegisterKeysInstruction(
  registrant: PublicKey,
  schemeId: bigint,
  stealthMetaAddress: Uint8Array
): TransactionInstruction {
  const discriminator = Buffer.from([0x29, 0x44, 0x64, 0x7d, 0x76, 0x2e, 0xfc, 0x84]);

  const schemeIdBuf = Buffer.alloc(8);
  schemeIdBuf.writeBigUInt64LE(schemeId);

  const metaLenBuf = Buffer.alloc(4);
  metaLenBuf.writeUInt32LE(stealthMetaAddress.length);

  const data = Buffer.concat([
    discriminator,
    schemeIdBuf,
    metaLenBuf,
    Buffer.from(stealthMetaAddress),
  ]);

  // Derive the registry entry PDA
  const schemeIdBytes = Buffer.alloc(8);
  schemeIdBytes.writeBigUInt64LE(schemeId);
  const [registryEntryPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("stealth_meta"), registrant.toBuffer(), schemeIdBytes],
    REGISTRY_PROGRAM_ID
  );

  return new TransactionInstruction({
    keys: [
      { pubkey: registryEntryPda, isSigner: false, isWritable: true },
      { pubkey: registrant, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: REGISTRY_PROGRAM_ID,
    data,
  });
}
