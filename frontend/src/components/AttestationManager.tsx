/**
 * Attestation Manager — V2 Issue Attestation UI
 *
 * Schema authorities and delegates issue attestations under a registered schema. The issuer picks
 * a schema, enters the recipient (meta-address / stealth address / hash), fills the schema fields,
 * and submits via `OpaqueClient.issueAttestation`, which resolves the recipient, encodes the data,
 * attests, and publishes the V2 discovery announcement — on Solana or Ethereum.
 */

import { useEffect, useMemo, useState, useId } from "react";
import type { Tab } from "./Layout";
import { parseFieldDefs, type SchemaV2 } from "@opaquecash/opaque";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import { useTxHistoryStore } from "../store/txHistoryStore";
import { getCluster } from "../lib/chain";
import { PsrChainToggle, type PsrChain } from "./PsrChainToggle";

interface AttestationManagerProps {
  onNavigate?: (tab: Tab) => void;
}

export function AttestationManager({ onNavigate }: AttestationManagerProps = {}) {
  const { client, isSetup, solanaAddress, ethereumAddress } = useOpaqueSession();
  const pushTx = useTxHistoryStore((s) => s.push);
  const cluster = getCluster();

  const [psrChain, setPsrChain] = useState<PsrChain>("solana");
  const [schemas, setSchemas] = useState<SchemaV2[]>([]);
  const [isFetchingSchemas, setIsFetchingSchemas] = useState(false);
  const [selectedSchemaId, setSelectedSchemaId] = useState<string>("");
  const [recipientInput, setRecipientInput] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [expiryDateTime, setExpiryDateTime] = useState("");
  const [hasExpiry, setHasExpiry] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [txSig, setTxSig] = useState<string | null>(null);
  const [resultHash, setResultHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const uid = useId();
  const myAddress = psrChain === "solana" ? solanaAddress : ethereumAddress;

  // Schemas the wallet can issue under (authority or delegate), excluding deprecated.
  useEffect(() => {
    if (!client) return;
    let cancelled = false;
    (async () => {
      try {
        setIsFetchingSchemas(true);
        const mine = await client.getMySchemas(psrChain);
        if (!cancelled) setSchemas(mine.filter((s) => !s.deprecated));
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load schemas");
      } finally {
        if (!cancelled) setIsFetchingSchemas(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, psrChain]);

  useEffect(() => {
    if (selectedSchemaId && !schemas.some((s) => s.schemaId === selectedSchemaId)) {
      setSelectedSchemaId("");
      setFieldValues({});
    }
  }, [schemas, selectedSchemaId]);

  const selectedSchema = schemas.find((s) => s.schemaId === selectedSchemaId);
  const parsedFields = useMemo(
    () => (selectedSchema ? parseFieldDefs(selectedSchema.fieldDefinitions) : []),
    [selectedSchema],
  );

  const canSubmit =
    client != null &&
    isSetup &&
    selectedSchemaId !== "" &&
    recipientInput.trim().length > 0 &&
    !isSubmitting;

  const handleFieldChange = (name: string, value: string) => {
    setFieldValues((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async () => {
    if (!client || !canSubmit || !selectedSchema) return;
    setIsSubmitting(true);
    setError(null);
    try {
      if (hasExpiry && !expiryDateTime) {
        throw new Error("Please select an expiration date and time.");
      }
      // Resolves the recipient (meta/stealth/hash), encodes the fields per the schema, attests,
      // and (for a meta-address) publishes the V2 discovery announcement.
      const res = await client.issueAttestation(psrChain, {
        schemaId: selectedSchema.schemaId,
        recipient: recipientInput.trim(),
        fieldValues,
        expiration: hasExpiry ? { dateTime: expiryDateTime } : undefined,
        announce: true,
      });
      setTxSig(res.txHash);
      setResultHash(res.stealthAddressHash);
      if (cluster) {
        pushTx({
          cluster,
          kind: "trait",
          counterparty: recipientInput.trim(),
          amountLamports: "0",
          tokenSymbol: "SOL",
          tokenAddress: null,
          amount: "0",
          txHash: res.txHash,
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
          {resultHash && (
            <p className="text-xs text-mist font-mono mt-1 break-all">
              Recipient hash: {resultHash.slice(0, 18)}…
            </p>
          )}
          <a
            href={
              psrChain === "solana"
                ? `https://explorer.solana.com/tx/${txSig}?cluster=devnet`
                : `https://sepolia.etherscan.io/tx/${txSig}`
            }
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
            setResultHash(null);
            setRecipientInput("");
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
        <div className="flex flex-col items-end gap-2">
          <PsrChainToggle value={psrChain} onChange={setPsrChain} ethConnected={ethereumAddress != null} />
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
                {s.name} {s.authority === myAddress ? "(authority)" : "(delegate)"}
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
      </section>

      {/* Dynamic field inputs */}
      {parsedFields.length > 0 && (
        <section className="space-y-4">
          <h2 className="text-sm font-medium text-white">Attestation Data</h2>
          <div className="space-y-3">
            {parsedFields.map((field) => (
              <div key={field.name} className="space-y-1">
                <label className="block text-xs font-medium text-mist">
                  {field.name} <span className="text-ink-500">({field.type})</span>
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
          <input
            type="datetime-local"
            value={expiryDateTime}
            min={new Date().toISOString().slice(0, 16)}
            onChange={(e) => setExpiryDateTime(e.target.value)}
            className="w-full rounded-xl border border-ink-700 bg-ink-900 px-4 py-3 text-white focus:outline-none focus:border-sol-purple text-sm"
          />
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
