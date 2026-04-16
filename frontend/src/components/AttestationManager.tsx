/**
 * Attestation Manager — V2 Issue Attestation UI
 *
 * Allows schema authorities and delegates to issue attestations under
 * a registered schema. The issuer selects a schema, enters the recipient's
 * stealth address hash, fills in the schema-defined fields, and submits.
 */

import { useEffect, useMemo, useState, useId } from "react";
import { PublicKey, Transaction } from "@solana/web3.js";
import type { Tab } from "./Layout";
import { keccak_256 } from "@noble/hashes/sha3";
import { useWallet } from "../hooks/useWallet";
import { useSchemaStore } from "../store/schemaStore";
import { useTxHistoryStore } from "../store/txHistoryStore";
import { getCluster } from "../lib/chain";
import { parseFieldDefs, SCHEMA_REGISTRY_PROGRAM_ID } from "../lib/schema";
import { encodeAttestationData } from "../lib/attestationV2";
import { computeStealthAddressAndViewTag } from "../lib/stealth";
import {
  buildAttestInstruction,
  buildAnnounceInstruction,
  bytesToHex,
  fetchAllSchemas,
  hexToBytes,
  fetchAttestationPDA,
} from "../lib/programs";
import { deriveAttestationPDA } from "../lib/attestationV2";

// =============================================================================
// Component
// =============================================================================

interface AttestationManagerProps {
  onNavigate?: (tab: Tab) => void;
}

export function AttestationManager({ onNavigate }: AttestationManagerProps = {}) {
  const { address: walletAddress, publicKey, sendTransaction, connection } = useWallet();
  const setSchemas = useSchemaStore((s) => s.setSchemas);
  const pushTx = useTxHistoryStore((s) => s.push);
  const cluster = getCluster();
  const setIsFetchingSchemas = useSchemaStore((s) => s.setIsFetchingSchemas);
  const isFetchingSchemas = useSchemaStore((s) => s.isFetchingSchemas);
  const schemaMap = useSchemaStore((s) => s.schemas);
  const schemas = useMemo(() => {
    if (!walletAddress) return [];
    return Object.values(schemaMap).filter(
      (s) =>
        !s.deprecated &&
        (s.authority === walletAddress || s.delegates.includes(walletAddress))
    );
  }, [schemaMap, walletAddress]);

  const [selectedSchemaId, setSelectedSchemaId] = useState<string>("");
  const [recipientInput, setRecipientInput] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [expiryDateTime, setExpiryDateTime] = useState("");
  const [hasExpiry, setHasExpiry] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [txSig, setTxSig] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resolvedStealthAddress, setResolvedStealthAddress] = useState<string | null>(null);

  const uid = useId();

  useEffect(() => {
    if (!walletAddress) return;

    let cancelled = false;
    (async () => {
      try {
        setIsFetchingSchemas(true);
        const onChainSchemas = await fetchAllSchemas(connection);
        if (cancelled) return;

        setSchemas(
          onChainSchemas.map(({ address, schema }) => ({
            address: address.toBase58(),
            schemaId: bytesToHex(schema.schemaId),
            authority: schema.authority.toBase58(),
            resolver:
              schema.resolver.equals(PublicKey.default) ? "" : schema.resolver.toBase58(),
            revocable: schema.revocable,
            name: schema.name,
            fieldDefinitions: schema.fieldDefinitions,
            version: schema.version,
            delegates: schema.delegates.map((d) => d.toBase58()),
            createdAt: Number(schema.createdAt),
            schemaExpirySlot: Number(schema.schemaExpirySlot),
            deprecated: schema.deprecated,
          }))
        );
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load schemas from chain");
        }
      } finally {
        if (!cancelled) {
          setIsFetchingSchemas(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [walletAddress, connection, setSchemas, setIsFetchingSchemas]);

  useEffect(() => {
    if (!selectedSchemaId) return;
    if (!schemas.some((s) => s.schemaId === selectedSchemaId)) {
      setSelectedSchemaId("");
      setFieldValues({});
    }
  }, [schemas, selectedSchemaId]);

  const selectedSchema = schemas.find((s) => s.schemaId === selectedSchemaId);
  const parsedFields = selectedSchema ? parseFieldDefs(selectedSchema.fieldDefinitions) : [];

  const canSubmit =
    walletAddress != null &&
    publicKey != null &&
    selectedSchemaId !== "" &&
    recipientInput.trim().length > 0 &&
    !isSubmitting;

  const handleFieldChange = (name: string, value: string) => {
    setFieldValues((prev) => ({ ...prev, [name]: value }));
  };

  const resolveStealthAddressHash = (
    input: string
  ): {
    stealthHashBytes: Uint8Array;
    stealthAddressHex?: string;
    ephemeralPubKey?: Uint8Array;
    viewTag?: number;
  } => {
    const trimmed = input.trim();
    const normalized = trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
    const bytes = hexToBytes(normalized);

    // Meta-address (66 bytes): derive stealth address and keep ephemeral key for announcement.
    if (bytes.length === 66) {
      const { stealthAddress, ephemeralPubKey, viewTag } = computeStealthAddressAndViewTag(normalized as `0x${string}`);
      const stealthAddressBytes = hexToBytes(stealthAddress);
      const stealthHashBytes = keccak_256(stealthAddressBytes);
      return { stealthHashBytes, stealthAddressHex: stealthAddress, ephemeralPubKey, viewTag };
    }

    // Stealth address (20 bytes): hash directly. No ephemeral key available.
    if (bytes.length === 20) {
      const stealthHashBytes = keccak_256(bytes);
      return { stealthHashBytes, stealthAddressHex: normalized };
    }

    // Backward compatibility: allow already-hashed 32-byte input.
    if (bytes.length === 32) {
      return { stealthHashBytes: bytes };
    }

    throw new Error(
      "Recipient must be a 66-byte meta-address, 20-byte stealth address, or 32-byte precomputed hash."
    );
  };

  const handleSubmit = async () => {
    if (!canSubmit || !selectedSchema || !publicKey) return;
    setIsSubmitting(true);
    setError(null);

    try {
      const issuer = publicKey;

      const schemaIdBytes = hexToBytes(selectedSchema.schemaId);

      // Derive the SchemaPDA address from authority + schemaId
      const schemaAuthority = new PublicKey(selectedSchema.authority);
      const [schemaPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("schema"),
          schemaAuthority.toBuffer(),
          Buffer.from(schemaIdBytes),
        ],
        SCHEMA_REGISTRY_PROGRAM_ID
      );

      const { stealthHashBytes, stealthAddressHex, ephemeralPubKey, viewTag } = resolveStealthAddressHash(recipientInput);
      setResolvedStealthAddress(stealthAddressHex ?? null);

      const attestationData = encodeAttestationData(
        fieldValues,
        parsedFields.map((f) => ({ name: f.name, type: f.type }))
      );

      let expirySlotNum = 0;
      if (hasExpiry) {
        if (!expiryDateTime) {
          throw new Error("Please select an expiration date and time.");
        }
        const targetMs = Date.parse(expiryDateTime);
        if (!Number.isFinite(targetMs)) {
          throw new Error("Invalid expiration date/time.");
        }
        const nowMs = Date.now();
        if (targetMs <= nowMs) {
          throw new Error("Expiration date/time must be in the future.");
        }
        const currentSlot = await connection.getSlot("confirmed");
        const slotsUntilExpiry = Math.ceil((targetMs - nowMs) / 400); // ~400ms per slot
        expirySlotNum = currentSlot + Math.max(1, slotsUntilExpiry);
      }
      const refUid = new Uint8Array(32);

      const [attestationPda] = await deriveAttestationPDA(
        schemaIdBytes,
        issuer,
        stealthHashBytes
      );

      const resolverStr = selectedSchema.resolver;
      const resolverPk =
        resolverStr && resolverStr !== "" && resolverStr !== PublicKey.default.toBase58()
          ? new PublicKey(resolverStr)
          : undefined;

      const ix = buildAttestInstruction(
        issuer,
        schemaPda,
        attestationPda,
        stealthHashBytes,
        attestationData,
        expirySlotNum,
        refUid,
        resolverPk
      );

      const tx = new Transaction().add(ix);
      tx.feePayer = issuer;
      const latest = await connection.getLatestBlockhash("confirmed");
      tx.recentBlockhash = latest.blockhash;

      const sim = await connection.simulateTransaction(tx);
      if (sim.value.err) {
        const logs = sim.value.logs?.join("\n") ?? "No simulation logs";
        throw new Error(`Attestation simulation failed: ${JSON.stringify(sim.value.err)}\n${logs}`);
      }

      const signature = await sendTransaction(tx, connection);
      await connection.confirmTransaction(signature, "confirmed");

      // If we derived the stealth address from a meta-address, we have the ephemeral key
      // and can create an announcement so the recipient's scanner can discover this attestation.
      if (ephemeralPubKey && stealthAddressHex && viewTag !== undefined) {
        try {
          // Fetch the confirmed attestation PDA to get the on-chain UID.
          const confirmedAttestation = await fetchAttestationPDA(connection, attestationPda);
          if (confirmedAttestation) {
            // Build V2 metadata: viewTag || 0xB2 || schemaId(32) || issuer(32) || uid(32) || nonce(32)
            const schemaId32 = new Uint8Array(32);
            schemaId32.set(schemaIdBytes.slice(0, Math.min(32, schemaIdBytes.length)));

            const issuerBytes = issuer.toBytes(); // 32-byte Ed25519 pubkey
            const nonce = crypto.getRandomValues(new Uint8Array(32));

            const v2Metadata = new Uint8Array(130);
            v2Metadata[0] = viewTag;
            v2Metadata[1] = 0xB2; // V2 attestation marker
            v2Metadata.set(schemaId32, 2);
            v2Metadata.set(issuerBytes, 34);
            v2Metadata.set(confirmedAttestation.uid, 66);
            v2Metadata.set(nonce, 98);

            const stealthAddressBytes = hexToBytes(stealthAddressHex);
            const announceIx = buildAnnounceInstruction(
              issuer,
              1, // schemeId: 1 = secp256k1 with view tags
              stealthAddressBytes,
              ephemeralPubKey,
              v2Metadata
            );

            const announceTx = new Transaction().add(announceIx);
            announceTx.feePayer = issuer;
            const latestForAnnounce = await connection.getLatestBlockhash("confirmed");
            announceTx.recentBlockhash = latestForAnnounce.blockhash;

            const announceSig = await sendTransaction(announceTx, connection);
            await connection.confirmTransaction(announceSig, "confirmed");
          }
        } catch (announceErr) {
          // Announcement failure is non-fatal — attestation is still on-chain.
          // The recipient can still discover it if they have the stealth address stored.
          console.warn("[AttestationManager] Announcement failed (non-fatal):", announceErr);
        }
      }

      setTxSig(signature);

      // Log attestation issuance to transaction history
      if (cluster) {
        pushTx({
          cluster,
          kind: "trait",
          counterparty: recipientInput.trim(),
          amountLamports: "0",
          tokenSymbol: "SOL",
          tokenAddress: null,
          amount: "0",
          txHash: signature,
        });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to issue attestation";
      setError(msg);
      console.error("[AttestationManager] Issue attestation failed:", e);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (txSig) {
    return (
      <div className="flex flex-col items-center justify-center gap-6 py-12 px-4 text-center">
        <div className="w-12 h-12 rounded-full bg-green-500/10 flex items-center justify-center">
          <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <div>
          <p className="text-white font-semibold text-lg">Attestation issued</p>
          <p className="text-mist text-sm mt-1">
            The recipient's scanner will detect this attestation on the next scan.
          </p>
          <a
            href={`https://explorer.solana.com/tx/${txSig}?cluster=devnet`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-sol-purple hover:underline mt-2 inline-block font-mono"
          >
            {txSig.slice(0, 20)}… ↗
          </a>
        </div>
        <button
          type="button"
          onClick={() => {
            setTxSig(null);
            setRecipientInput("");
            setResolvedStealthAddress(null);
            setFieldValues({});
            setHasExpiry(false);
            setExpiryDateTime("");
          }}
          className="rounded-xl bg-ink-800 px-6 py-2.5 text-sm font-medium text-white hover:bg-ink-700 transition-colors"
        >
          Issue another attestation
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto px-4 py-8 space-y-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Issue Attestation</h1>
          <p className="text-mist text-sm mt-1">
            Issue a schema-bound credential to a stealth address.
          </p>
        </div>
        {onNavigate && (
          <button
            type="button"
            onClick={() => onNavigate("schemas")}
            className="shrink-0 rounded-xl border border-ink-700 bg-ink-900 px-4 py-2 text-xs font-medium text-white hover:bg-ink-800 transition-colors"
          >
            Create New Schema
          </button>
        )}
      </div>

      {/* Schema selector */}
      <section className="space-y-2">
        <label htmlFor={`${uid}-schema`} className="block text-sm font-medium text-white">
          Schema <span className="text-red-400">*</span>
        </label>
        {isFetchingSchemas ? (
          <div className="rounded-xl border border-ink-700 bg-ink-900 px-4 py-4 text-sm text-mist">
            Loading schemas from chain...
          </div>
        ) : schemas.length === 0 ? (
          <div className="rounded-xl border border-ink-700 bg-ink-900 px-4 py-4 text-sm text-mist flex items-center justify-between gap-4">
            <span>You have no schemas you can attest under.</span>
            {onNavigate ? (
              <button
                type="button"
                onClick={() => onNavigate("schemas")}
                className="shrink-0 rounded-lg bg-sol-purple px-3 py-1.5 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors"
              >
                Create New Schema
              </button>
            ) : (
              <strong className="text-white shrink-0">Schema Studio</strong>
            )}
          </div>
        ) : (
          <select
            id={`${uid}-schema`}
            value={selectedSchemaId}
            onChange={(e) => {
              setSelectedSchemaId(e.target.value);
              setFieldValues({});
            }}
            className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-3 text-white focus:outline-none focus:border-sol-purple text-sm"
          >
            <option value="">Select a schema…</option>
            {schemas.map((s) => (
              <option key={s.schemaId} value={s.schemaId}>
                {s.name}{" "}
                {s.authority === walletAddress ? "(authority)" : "(delegate)"}
              </option>
            ))}
          </select>
        )}
        {selectedSchema && (
          <p className="text-xs text-mist font-mono bg-ink-900/50 rounded-lg px-3 py-2 border border-ink-800">
            Fields: <span className="text-sol-purple">{selectedSchema.fieldDefinitions}</span>
          </p>
        )}
      </section>

      {/* Recipient meta-address / stealth address */}
      <section className="space-y-2">
        <label htmlFor={`${uid}-hash`} className="block text-sm font-medium text-white">
          Recipient (Meta-Address or Stealth Address) <span className="text-red-400">*</span>
        </label>
        <input
          id={`${uid}-hash`}
          type="text"
          placeholder="0x… (66-byte meta-address or 20-byte stealth address)"
          value={recipientInput}
          onChange={(e) => setRecipientInput(e.target.value)}
          className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-3 text-white placeholder-ink-500 focus:outline-none focus:border-sol-purple text-sm font-mono"
        />
        <p className="text-xs text-mist">
          If you provide a meta-address, a stealth address is derived first. The attestation stores
          only keccak256(stealthAddress) on-chain.
        </p>
        {resolvedStealthAddress && (
          <p className="text-xs text-mist font-mono bg-ink-900/50 rounded-lg px-3 py-2 border border-ink-800">
            Resolved stealth address:{" "}
            <span className="text-sol-purple">{resolvedStealthAddress}</span>
          </p>
        )}
      </section>

      {/* Dynamic field inputs */}
      {parsedFields.length > 0 && (
        <section className="space-y-4">
          <h2 className="text-sm font-medium text-white">Attestation Data</h2>
          <div className="space-y-3">
            {parsedFields.map((field) => (
              <div key={field.id} className="space-y-1">
                <label className="block text-xs font-medium text-mist">
                  {field.name}{" "}
                  <span className="text-ink-500">({field.type})</span>
                </label>
                {field.type === "bool" ? (
                  <select
                    value={fieldValues[field.name] ?? "true"}
                    onChange={(e) => handleFieldChange(field.name, e.target.value)}
                    className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-2.5 text-white focus:outline-none focus:border-sol-purple text-sm"
                  >
                    <option value="true">true</option>
                    <option value="false">false</option>
                  </select>
                ) : (
                  <input
                    type={field.type.startsWith("u") ? "number" : "text"}
                    min={0}
                    placeholder={`${field.name} (${field.type})`}
                    value={fieldValues[field.name] ?? ""}
                    onChange={(e) => handleFieldChange(field.name, e.target.value)}
                    className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-2.5 text-white placeholder-ink-500 focus:outline-none focus:border-sol-purple text-sm"
                  />
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Expiration */}
      <section className="space-y-3">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={hasExpiry}
            onChange={(e) => setHasExpiry(e.target.checked)}
            className="h-4 w-4 accent-sol-purple"
          />
          <span className="text-sm text-white">Set expiration date & time</span>
        </label>
        {hasExpiry && (
          <div className="space-y-2">
            <input
              type="datetime-local"
              value={expiryDateTime}
              min={new Date().toISOString().slice(0, 16)}
              onChange={(e) => setExpiryDateTime(e.target.value)}
              className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-3 text-white focus:outline-none focus:border-sol-purple text-sm"
            />
            <p className="text-xs text-mist">
              This is converted to a Solana slot at submit time using ~400ms per slot.
            </p>
          </div>
        )}
      </section>

      {error && (
        <p className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </p>
      )}

      <button
        type="button"
        onClick={handleSubmit}
        disabled={!canSubmit}
        className="w-full rounded-xl bg-sol-purple py-3 text-sm font-semibold text-white hover:bg-sol-purple/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        {isSubmitting ? (
          <span className="flex items-center justify-center gap-2">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
            Issuing…
          </span>
        ) : (
          "Issue Attestation"
        )}
      </button>
    </div>
  );
}
