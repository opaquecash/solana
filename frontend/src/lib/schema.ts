/**
 * Schema Registry — V2 Stealth Reputation Protocol
 *
 * Types and client-side utilities for interacting with the schema_registry
 * Anchor program. Schemas define the template for attestation classes and
 * control who is authorized to issue them.
 */

import { PublicKey } from "@solana/web3.js";
import { z } from "zod";

// =============================================================================
// Program ID
// =============================================================================

export const SCHEMA_REGISTRY_PROGRAM_ID = new PublicKey(
  "FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB"
);

export const ATTESTATION_ENGINE_V2_PROGRAM_ID = new PublicKey(
  "4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM"
);

// =============================================================================
// Types
// =============================================================================

export type FieldType = "bool" | "u8" | "u16" | "u32" | "u64" | "string" | "pubkey";

export interface FieldDef {
  id: string;
  name: string;
  type: FieldType;
}

export interface SchemaV2 {
  /** On-chain PDA address */
  address: string;
  /** SHA256(authority || name || version) as hex */
  schemaId: string;
  /** Wallet that created the schema */
  authority: string;
  /** Optional resolver program (empty string = no resolver) */
  resolver: string;
  /** Whether attestations can be revoked */
  revocable: boolean;
  /** Display name */
  name: string;
  /** ABI-style field definitions string, e.g. "bool passed, u64 score" */
  fieldDefinitions: string;
  /** Always 1 currently */
  version: number;
  /** Authorized delegate pubkeys */
  delegates: string[];
  /** Slot when the schema was registered */
  createdAt: number;
  /** 0 = no expiry */
  schemaExpirySlot: number;
  /** Whether the schema has been deprecated */
  deprecated: boolean;
}

/** Parsed field definition list from a fieldDefinitions string */
export function parseFieldDefs(fieldDefs: string): FieldDef[] {
  if (!fieldDefs.trim()) return [];
  return fieldDefs.split(",").map((part, i) => {
    const trimmed = part.trim();
    const spaceIdx = trimmed.indexOf(" ");
    const type = (spaceIdx === -1 ? "string" : trimmed.slice(0, spaceIdx)) as FieldType;
    const name = spaceIdx === -1 ? trimmed : trimmed.slice(spaceIdx + 1);
    return { id: String(i), name: name.trim(), type: type.trim() as FieldType };
  });
}

/** Converts a FieldDef array to the canonical ABI string */
export function fieldDefsToString(fields: FieldDef[]): string {
  return fields
    .filter((f) => f.name.trim())
    .map((f) => `${f.type} ${f.name.trim()}`)
    .join(", ");
}

// =============================================================================
// PDA derivation (mirrors on-chain seeds)
// =============================================================================

/** Derives the SchemaPDA address for a given authority + schema_id */
export async function deriveSchemaPDA(
  authority: PublicKey,
  schemaId: Uint8Array
): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("schema"), authority.toBuffer(), Buffer.from(schemaId)],
    SCHEMA_REGISTRY_PROGRAM_ID
  );
}

/** Computes schema_id = SHA256(authority_bytes || name_utf8 || version_byte) */
export async function computeSchemaId(
  authority: PublicKey,
  name: string,
  version: number = 1
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const authorityBytes = authority.toBytes();
  const nameBytes = encoder.encode(name);
  const versionByte = new Uint8Array([version]);

  const combined = new Uint8Array(
    authorityBytes.length + nameBytes.length + versionByte.length
  );
  combined.set(authorityBytes, 0);
  combined.set(nameBytes, authorityBytes.length);
  combined.set(versionByte, authorityBytes.length + nameBytes.length);

  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(hashBuffer);
}

// =============================================================================
// Schema cost estimation
// =============================================================================

/** Estimated SOL cost to register a schema (rent for SchemaPDA ~490 bytes) */
export const SCHEMA_RENT_LAMPORTS = 4_088_640; // ~0.0041 SOL at current rent rate

// =============================================================================
// Zod validation schemas
// =============================================================================

export const SchemaV2Schema = z.object({
  address: z.string(),
  schemaId: z.string(),
  authority: z.string(),
  resolver: z.string(),
  revocable: z.boolean(),
  name: z.string().max(64),
  fieldDefinitions: z.string().max(256),
  version: z.number(),
  delegates: z.array(z.string()),
  createdAt: z.number(),
  schemaExpirySlot: z.number(),
  deprecated: z.boolean(),
});

export const SchemaV2ArraySchema = z.array(SchemaV2Schema);

// =============================================================================
// Instruction preparation helpers (PDA derivation + schema ID computation)
// =============================================================================

/**
 * Prepares register_schema data: computes the schema_id and derives the PDA.
 * The actual instruction is built by programs.ts buildRegisterSchemaInstruction.
 */
export async function prepareRegisterSchema(
  authority: PublicKey,
  name: string
): Promise<{ schemaId: Uint8Array; schemaPda: PublicKey }> {
  const schemaId = await computeSchemaId(authority, name, 1);
  const [schemaPda] = await deriveSchemaPDA(authority, schemaId);
  return { schemaId, schemaPda };
}

/**
 * Prepares add_delegate data: derives the schema PDA from authority + schemaId.
 */
export async function prepareAddDelegate(
  authority: PublicKey,
  schemaId: Uint8Array,
  delegate: PublicKey
): Promise<{ schemaPda: PublicKey; delegate: PublicKey }> {
  const [schemaPda] = await deriveSchemaPDA(authority, schemaId);
  return { schemaPda, delegate };
}

// =============================================================================
// Helper: pack schema_id bytes into a BN254 field element decimal string
// (for ZK circuit compatibility)
// =============================================================================

export function packSchemaIdToField(schemaId: Uint8Array): string {
  // Return as hex — Circom 2.x accepts 0x-prefixed hex for field inputs
  return "0x" + Array.from(schemaId).map((b) => b.toString(16).padStart(2, "0")).join("");
}
