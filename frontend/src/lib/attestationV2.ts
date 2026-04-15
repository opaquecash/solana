/**
 * Attestation Engine V2 — client-side interaction layer
 *
 * Types and builder functions for the attestation_engine_v2 Anchor program.
 * Handles attest and revoke instruction construction, and client-side
 * attestation account deserialization.
 */

import { PublicKey } from "@solana/web3.js";
import { z } from "zod";
import { ATTESTATION_ENGINE_V2_PROGRAM_ID } from "./schema";

// =============================================================================
// Types
// =============================================================================

export interface AttestationV2 {
  /** On-chain PDA address */
  address: string;
  /** SHA256(schema_id || issuer || stealth_address_hash || slot) as hex */
  uid: string;
  /** SchemaPDA address */
  schemaPda: string;
  /** schema_id as hex (cached from schema for efficient verification) */
  schemaId: string;
  /** Issuer wallet pubkey (base58) */
  issuer: string;
  /** Privacy-preserving stealth address hash as hex */
  stealthAddressHash: string;
  /** ABI-encoded attestation data as hex */
  dataHex: string;
  /** Slot when the attestation was created */
  createdAt: number;
  /** 0 = no expiry */
  expirationSlot: number;
  /** 0 = not revoked; non-zero = revocation slot */
  revocationSlot: number;
  /** Optional reference UID as hex (zeros = none) */
  refUid: string;
  /** Derived: is the attestation currently valid? */
  isValid: boolean;
}

export interface AttestationFormData {
  schemaId: string;
  schemaPda: string;
  stealthAddressHash: string;
  /** Encoded field values in order matching schema.fieldDefinitions */
  fieldValues: Record<string, string>;
  expirationSlot: number;
  refUid: string;
}

// =============================================================================
// PDA derivation
// =============================================================================

/** Derives the AttestationPDA address */
export async function deriveAttestationPDA(
  schemaId: Uint8Array,
  issuer: PublicKey,
  stealthAddressHash: Uint8Array
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("attestation_v2"),
      Buffer.from(schemaId),
      issuer.toBuffer(),
      Buffer.from(stealthAddressHash),
    ],
    ATTESTATION_ENGINE_V2_PROGRAM_ID
  );
}

// =============================================================================
// Data encoding
// =============================================================================

/** ABI-encodes field values for storage in the attestation data field */
export function encodeAttestationData(
  fieldValues: Record<string, string>,
  fieldDefs: { name: string; type: string }[]
): Uint8Array {
  // Simple length-prefixed encoding: for each field in order,
  // encode value as UTF-8 bytes with a 4-byte little-endian length prefix.
  const parts: Uint8Array[] = [];
  const enc = new TextEncoder();

  for (const field of fieldDefs) {
    const value = fieldValues[field.name] ?? "";
    const encoded = enc.encode(value);
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, encoded.length, true);
    parts.push(lenBuf);
    parts.push(encoded);
  }

  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** Decodes attestation data back to a field-value map given the schema field_definitions */
export function decodeAttestationData(
  dataHex: string,
  fieldDefs: { name: string; type: string }[]
): Record<string, string> {
  const bytes = hexToBytes(dataHex);
  const dec = new TextDecoder();
  const result: Record<string, string> = {};
  let offset = 0;

  for (const field of fieldDefs) {
    if (offset + 4 > bytes.length) break;
    const len = new DataView(bytes.buffer, offset, 4).getUint32(0, true);
    offset += 4;
    if (offset + len > bytes.length) break;
    result[field.name] = dec.decode(bytes.slice(offset, offset + len));
    offset += len;
  }

  return result;
}

// =============================================================================
// Zod schemas
// =============================================================================

export const AttestationV2Schema = z.object({
  address: z.string(),
  uid: z.string(),
  schemaPda: z.string(),
  schemaId: z.string(),
  issuer: z.string(),
  stealthAddressHash: z.string(),
  dataHex: z.string(),
  createdAt: z.number(),
  expirationSlot: z.number(),
  revocationSlot: z.number(),
  refUid: z.string(),
  isValid: z.boolean(),
});

export const AttestationV2ArraySchema = z.array(AttestationV2Schema);

// =============================================================================
// Helpers
// =============================================================================

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Returns true if an attestation UID is a zero-value (no reference) */
export function isZeroUid(uid: string): boolean {
  return uid.replace(/^0x/, "").replace(/0/g, "") === "";
}

/** Formats a slot number as a human-readable distance from now (approximate) */
export function formatSlotDistance(slot: number, currentSlot: number): string {
  if (slot === 0) return "Never";
  const diff = slot - currentSlot;
  if (diff <= 0) return "Expired";
  // ~400ms per slot on Solana
  const seconds = diff * 0.4;
  if (seconds < 60) return `~${Math.round(seconds)}s`;
  if (seconds < 3600) return `~${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `~${Math.round(seconds / 3600)}h`;
  return `~${Math.round(seconds / 86400)}d`;
}
