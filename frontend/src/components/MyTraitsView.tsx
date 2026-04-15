/**
 * My Traits — V2 User Self-Service UI
 *
 * Displays the user's discovered V2 traits (schema-bound attestations detected
 * by the WASM scanner). Each trait shows the schema name, issuer, status
 * (active / revoked / expired), and a button to generate a ZK proof.
 *
 * V1 legacy traits (no schema) are shown in a separate section with a
 * migration notice.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useWallet } from "../hooks/useWallet";
import { getCluster } from "../lib/chain";
import { useSchemaStore, type V2DiscoveredTrait } from "../store/schemaStore";
import { useOpaqueWasm } from "../hooks/useOpaqueWasm";
import { useKeys } from "../context/KeysContext";
import { useScanner } from "../hooks/useScanner";
import { getConfigForCluster } from "../contracts/contract-config";
import { getAnnouncementsForCluster } from "../lib/opaqueCache";
import type { Tab } from "./Layout";
import {
  fetchAllSchemas,
  fetchAllAttestations,
  bytesToHex,
  hexToBytes,
  hexPubkeyToBase58,
} from "../lib/programs";
import { keccak_256 } from "@noble/hashes/sha3";
import { useGhostAddressStore } from "../store/ghostAddressStore";
import { useVaultStore } from "../store/vaultStore";
import { useWatchlistStore } from "../hooks/useWatchlist";
import { ProofGeneratorModal } from "./ProofGeneratorModal";

// =============================================================================
// Status badge
// =============================================================================

function normalizeStealthAddressHex(addr: string): string {
  const t = addr.trim().toLowerCase();
  return t.startsWith("0x") ? t : `0x${t}`;
}

/** keccak256(20-byte stealth), lowercase 0x-prefixed hex — must match AttestationManager + on-chain account. */
function stealthHashHexFromAddress(stealthHex: string): string | null {
  try {
    const norm = normalizeStealthAddressHex(stealthHex);
    const b = hexToBytes(norm);
    if (b.length !== 20) return null;
    return bytesToHex(keccak_256(b)).toLowerCase();
  } catch {
    return null;
  }
}

function findOwnedStealthForHash(
  ownedNormalized: Set<string>,
  stealthAddressHash: Uint8Array
): string | null {
  const want = bytesToHex(stealthAddressHash).toLowerCase();
  for (const stealthNorm of ownedNormalized) {
    const calculated = stealthHashHexFromAddress(stealthNorm);
    if (calculated === want) {
      return stealthNorm;
    }
  }
  return null;
}

function StatusBadge({ isValid, isLegacy }: { isValid: boolean; isLegacy?: boolean }) {
  if (isLegacy) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-yellow-500/30 bg-yellow-500/10 px-2.5 py-1 text-xs font-medium text-yellow-400">
        <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0" />
        Legacy V1
      </span>
    );
  }
  if (isValid) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-green-500/30 bg-green-500/10 px-2.5 py-1 text-xs font-medium text-green-400">
        <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
        Active
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400">
      <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
      Revoked
    </span>
  );
}

// =============================================================================
// Trait card
// =============================================================================

function TraitCard({
  trait,
  onProve,
}: {
  trait: V2DiscoveredTrait;
  onProve: (trait: V2DiscoveredTrait) => void;
}) {
  const issuerBase58 = hexPubkeyToBase58(trait.issuer);
  const issuerShort = `${issuerBase58.slice(0, 6)}…${issuerBase58.slice(-4)}`;
  const schemaIdShort = `${trait.schemaId.slice(0, 10)}…${trait.schemaId.slice(-6)}`;

  return (
    <div
      className={`rounded-xl border bg-ink-900 px-5 py-4 space-y-3 ${
        trait.isValid && trait.issuerAuthorized
          ? "border-ink-700 hover:border-ink-600"
          : "border-ink-800 opacity-75"
      } transition-colors`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold text-white text-sm truncate">
            {trait.schemaName ?? "Unknown Schema"}
          </p>
          <p className="text-xs text-mist mt-0.5 font-mono truncate">{schemaIdShort}</p>
        </div>
        <StatusBadge isValid={trait.isValid && trait.issuerAuthorized} isLegacy={!trait.isV2} />
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <div>
          <span className="text-ink-500">Issued by</span>
          <p className="text-white font-mono truncate">{issuerShort}</p>
        </div>
        <div>
          <span className="text-ink-500">Slot</span>
          <p className="text-white">{trait.slot.toLocaleString()}</p>
        </div>
        {!trait.issuerAuthorized && (
          <div className="col-span-2">
            <span className="text-yellow-400 text-xs">
              Warning: issuer is not an authorized delegate for this schema.
            </span>
          </div>
        )}
      </div>

      {trait.isV2 && trait.isValid && trait.issuerAuthorized && !trait.chainDiscoveryOnly && (
        <button
          type="button"
          onClick={() => onProve(trait)}
          className="w-full rounded-xl bg-sol-purple/10 border border-sol-purple/30 py-2 text-xs font-semibold text-sol-purple hover:bg-sol-purple/20 transition-colors"
        >
          Generate ZK Proof ▶
        </button>
      )}
      {trait.isV2 && trait.chainDiscoveryOnly && (
        <p className="text-xs text-mist">
          Proof generation needs a V2 announcement (metadata marker 0xB2) that carries the leaf
          nonce. This attestation was found on-chain for a stealth address you own.
        </p>
      )}
    </div>
  );
}

// =============================================================================
// Main view
// =============================================================================

interface MyTraitsViewProps {
  onNavigate?: (tab: Tab) => void;
}

export function MyTraitsView({ onNavigate }: MyTraitsViewProps = {}) {
  const discoveredTraitsMap = useSchemaStore((s) => s.discoveredTraits);
  const setDiscoveredTraits = useSchemaStore((s) => s.setDiscoveredTraits);
  const isScanning = useSchemaStore((s) => s.isScanning);
  const setIsScanning = useSchemaStore((s) => s.setIsScanning);
  const lastScannedSlot = useSchemaStore((s) => s.lastScannedSlot);
  const setLastScannedSlot = useSchemaStore((s) => s.setLastScannedSlot);
  const { connection } = useWallet();
  const { wasm, isReady: wasmReady } = useOpaqueWasm();
  const { isSetup, getMasterKeys } = useKeys();
  const cluster = getCluster();
  const currentConfig = getConfigForCluster(cluster);
  const scanner = useScanner({
    cluster,
    publicClient: connection,
    announcerAddress: currentConfig?.announcerProgram.toBase58() ?? null,
    enabled: Boolean(cluster && currentConfig),
  });
  const { refresh: refreshScanner } = scanner;
  const hasAutoScannedRef = useRef(false);

  const [activeProofTrait, setActiveProofTrait] = useState<V2DiscoveredTrait | null>(null);
  const [filter, setFilter] = useState<"all" | "active" | "revoked">("all");

  const allTraits = useMemo(
    () => Object.values(discoveredTraitsMap),
    [discoveredTraitsMap]
  );

  const v2Traits = useMemo(() => allTraits.filter((t) => t.isV2), [allTraits]);
  const v1Traits = useMemo(() => allTraits.filter((t) => !t.isV2), [allTraits]);

  const filteredV2 = useMemo(
    () =>
      v2Traits.filter((t) => {
        if (filter === "active") return t.isValid && t.issuerAuthorized;
        if (filter === "revoked") return !t.isValid;
        return true;
      }),
    [v2Traits, filter]
  );

  const rescan = useCallback(async () => {
    if (!cluster) {
      return;
    }

    try {
      setIsScanning(true);
      await refreshScanner();

      const [currentSlot, announcements] = await Promise.all([
        connection.getSlot("confirmed"),
        getAnnouncementsForCluster(cluster),
      ]);
      const [schemaRows, attestationRows] = await Promise.all([
        fetchAllSchemas(connection),
        fetchAllAttestations(connection),
      ]);

      const ownedStealthNormalized = new Set<string>();
      for (const e of useGhostAddressStore.getState().getForCluster(cluster)) {
        const h = stealthHashHexFromAddress(e.stealthAddress);
        if (h) ownedStealthNormalized.add(normalizeStealthAddressHex(e.stealthAddress));
      }
      for (const e of useWatchlistStore.getState().getEntriesForCluster(cluster)) {
        const h = stealthHashHexFromAddress(e.address);
        if (h) ownedStealthNormalized.add(normalizeStealthAddressHex(e.address));
      }
      for (const e of useVaultStore.getState().entries) {
        if (stealthHashHexFromAddress(e.stealthAddress)) {
          ownedStealthNormalized.add(normalizeStealthAddressHex(e.stealthAddress));
        }
      }

      let mapped: V2DiscoveredTrait[] = [];
      if (isSetup && wasmReady && wasm) {
        const masterKeys = getMasterKeys();
        const announcementsPayload = announcements.map((a) => ({
          stealthAddress: a.args?.stealthAddress ?? "",
          viewTag: parseInt((a.args?.metadata ?? "0x00").slice(2, 4), 16),
          ephemeralPubKey: a.args?.ephemeralPubKey ?? "0x",
          metadata: a.args?.metadata ?? "0x",
          txHash: a.transactionSignature,
          blockNumber: a.slot,
        }));

        const schemasPayload = schemaRows.map(({ schema }) => ({
          schema_id: Array.from(schema.schemaId),
          authority: Array.from(schema.authority.toBytes()),
          delegates: schema.delegates.map((d) => Array.from(d.toBytes())),
          deprecated: schema.deprecated,
          schema_expiry_slot: Number(schema.schemaExpirySlot),
          name: schema.name,
        }));

        const resultJson = wasm.scan_attestations_v2_wasm(
          JSON.stringify(announcementsPayload),
          JSON.stringify(schemasPayload),
          masterKeys.viewPrivKey,
          masterKeys.spendPubKey,
          BigInt(currentSlot),
          "[]"
        );

        const parsed = JSON.parse(resultJson) as Array<{
          stealth_address: string;
          schema_id: string;
          schema_name?: string | null;
          issuer: string;
          attestation_uid: string;
          data_hex: string;
          nonce: string;
          merkle_leaf_preimage: {
            stealth_pk_field: string;
            schema_id_field: string;
            issuer_pk_x: string;
            trait_data_hash: string;
            nonce_field: string;
          };
          tx_hash: string;
          slot: number;
          is_valid: boolean;
          issuer_authorized: boolean;
        }>;

        mapped = parsed.map((att) => ({
          stealthAddress: att.stealth_address,
          schemaId: att.schema_id.startsWith("0x") ? att.schema_id : `0x${att.schema_id}`,
          schemaName: att.schema_name ?? "Unknown Schema",
          issuer: att.issuer.startsWith("0x") ? att.issuer : `0x${att.issuer}`,
          attestationUid: att.attestation_uid.startsWith("0x")
            ? att.attestation_uid
            : `0x${att.attestation_uid}`,
          dataHex: att.data_hex,
          nonce: att.nonce.startsWith("0x") ? att.nonce : `0x${att.nonce}`,
          merkleLeafPreimage: {
            stealthPkField: att.merkle_leaf_preimage.stealth_pk_field,
            schemaIdField: att.merkle_leaf_preimage.schema_id_field,
            issuerPkX: att.merkle_leaf_preimage.issuer_pk_x,
            traitDataHash: att.merkle_leaf_preimage.trait_data_hash,
            nonceField: att.merkle_leaf_preimage.nonce_field,
          },
          txHash: att.tx_hash,
          slot: att.slot,
          isValid: att.is_valid,
          issuerAuthorized: att.issuer_authorized,
          isV2: true,
        }));

        for (const t of mapped) {
          const h = stealthHashHexFromAddress(t.stealthAddress);
          if (h) ownedStealthNormalized.add(normalizeStealthAddressHex(t.stealthAddress));
        }
      }

      const schemaByIdBytes = new Map<string, (typeof schemaRows)[0]["schema"]>();
      for (const row of schemaRows) {
        schemaByIdBytes.set(Buffer.from(row.schema.schemaId).toString("hex"), row.schema);
      }

      const chainTraits: V2DiscoveredTrait[] = [];
      const slotBn = BigInt(currentSlot);
      for (const { attestation } of attestationRows) {
        const stealthHex = findOwnedStealthForHash(
          ownedStealthNormalized,
          attestation.stealthAddressHash
        );
        if (!stealthHex) continue;

        const schema =
          schemaByIdBytes.get(Buffer.from(attestation.schemaId).toString("hex")) ?? null;
        const issuerAuthorized =
          schema != null &&
          (schema.authority.equals(attestation.issuer) ||
            schema.delegates.some((d) => d.equals(attestation.issuer)));

        const isValid =
          attestation.revocationSlot === 0n &&
          (attestation.expirationSlot === 0n || slotBn < attestation.expirationSlot);

        chainTraits.push({
          stealthAddress: stealthHex,
          schemaId: bytesToHex(attestation.schemaId),
          schemaName: schema?.name ?? "Unknown Schema",
          issuer: attestation.issuer.toBase58(),
          attestationUid: bytesToHex(attestation.uid),
          dataHex: bytesToHex(attestation.data),
          nonce: bytesToHex(attestation.refUid),
          merkleLeafPreimage: {
            stealthPkField: "0",
            schemaIdField: "0",
            issuerPkX: "0",
            traitDataHash: "0",
            nonceField: "0",
          },
          txHash: "",
          slot: Number(attestation.createdAt),
          isValid,
          issuerAuthorized,
          isV2: true,
          chainDiscoveryOnly: true,
        });
      }

      const mergedByUid = new Map<string, V2DiscoveredTrait>();
      for (const t of mapped) {
        mergedByUid.set(t.attestationUid.toLowerCase(), t);
      }
      for (const t of chainTraits) {
        const k = t.attestationUid.toLowerCase();
        if (!mergedByUid.has(k)) mergedByUid.set(k, t);
      }

      setDiscoveredTraits(Array.from(mergedByUid.values()));
      setLastScannedSlot(currentSlot);
    } catch (err) {
      console.error("[MyTraitsView] Failed to rescan V2 traits:", err);
    } finally {
      setIsScanning(false);
    }
  }, [
    cluster,
    isSetup,
    wasmReady,
    wasm,
    refreshScanner,
    setDiscoveredTraits,
    setLastScannedSlot,
    setIsScanning,
    connection,
    getMasterKeys,
  ]);

  useEffect(() => {
    if (!cluster || !isSetup || !wasmReady || !wasm) return;
    if (hasAutoScannedRef.current) return;
    hasAutoScannedRef.current = true;
    void rescan();
  }, [cluster, isSetup, wasmReady, wasm, rescan]);

  return (
    <div className="max-w-2xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">My Traits</h1>
          {lastScannedSlot > 0 && (
            <p className="text-xs text-mist mt-1">
              Last scanned at slot {lastScannedSlot.toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate("attest")}
              className="rounded-xl bg-sol-purple px-4 py-2 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors"
            >
              Issue Attestation
            </button>
          )}
          <button
            type="button"
            onClick={() => void rescan()}
            disabled={isScanning}
            className="rounded-xl border border-ink-700 bg-ink-900 px-4 py-2 text-xs font-medium text-white hover:bg-ink-800 disabled:opacity-50 transition-colors"
          >
            {isScanning ? (
              <span className="flex items-center gap-1.5">
                <span className="h-3 w-3 animate-spin rounded-full border border-ink-600 border-t-white" />
                Scanning…
              </span>
            ) : (
              "Rescan"
            )}
          </button>
        </div>
      </div>

      {/* Filter tabs */}
      {v2Traits.length > 0 && (
        <div className="flex gap-2">
          {(["all", "active", "revoked"] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors capitalize ${
                filter === f
                  ? "bg-sol-purple text-white"
                  : "bg-ink-900 border border-ink-700 text-mist hover:text-white"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      )}

      {/* V2 traits */}
      {filteredV2.length > 0 ? (
        <div className="space-y-3">
          {filteredV2.map((trait) => (
            <TraitCard key={trait.attestationUid} trait={trait} onProve={setActiveProofTrait} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-ink-800 bg-ink-900/50 px-6 py-10 text-center space-y-3">
          <div className="w-10 h-10 rounded-full bg-ink-800 flex items-center justify-center mx-auto">
            <svg className="w-5 h-5 text-ink-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <p className="text-white font-medium">No V2 traits found</p>
          <p className="text-sm text-mist max-w-xs mx-auto">
            {filter !== "all"
              ? `No ${filter} traits. Try switching to "all".`
              : "Run a scan to discover attestations issued to your stealth addresses."}
          </p>
        </div>
      )}

      {/* V1 legacy section */}
      {v1Traits.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-medium text-white">Legacy V1 Traits</h2>
            <span className="rounded-full bg-yellow-500/10 border border-yellow-500/20 px-2 py-0.5 text-xs text-yellow-400">
              {v1Traits.length}
            </span>
          </div>
          <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 px-4 py-3 text-xs text-yellow-400 space-y-1">
            <p className="font-medium">V1 traits use the old circuit</p>
            <p className="text-yellow-400/70">
              These traits were issued before the V2 upgrade and cannot generate V2 proofs.
              They remain valid for V1 verifiers during the migration window.
            </p>
          </div>
          <div className="space-y-3">
            {v1Traits.map((trait) => (
              <TraitCard key={trait.attestationUid} trait={trait} onProve={() => {}} />
            ))}
          </div>
        </section>
      )}

      {/* Proof generator modal */}
      {activeProofTrait && (
        <ProofGeneratorModal
          trait={activeProofTrait}
          onClose={() => setActiveProofTrait(null)}
        />
      )}
    </div>
  );
}
