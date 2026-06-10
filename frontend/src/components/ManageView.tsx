/**
 * ManageView — Schema & Attestation Management
 *
 * Lists schemas the connected wallet has authority/delegate rights over and attestations it has
 * issued, with management actions (deprecate schema, add/remove delegates) via OpaqueClient on
 * Solana or Ethereum. Reads come from client.getMySchemas / client.getMyIssuedAttestations.
 */

import { useEffect, useMemo, useState, useCallback, useId } from "react";
import type { OpaqueClient, SchemaV2, AttestationV2 } from "@opaquecash/opaque";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import type { Tab } from "./Layout";
import { ModalShell } from "./ModalShell";
import { PsrChainToggle, type PsrChain } from "./PsrChainToggle";

const ITEMS_PER_PAGE = 10;

interface ManagedAttestation {
  uidHex: string;
  schemaIdHex: string;
  schemaName: string;
  stealthAddressHashHex: string;
  createdAt: number;
  expirationSlot: number;
  revocationSlot: number;
  isRevoked: boolean;
}

function shortAddr(addr: string): string {
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function shortHex(hex: string): string {
  const clean = hex.startsWith("0x") ? hex : `0x${hex}`;
  return `${clean.slice(0, 10)}…${clean.slice(-6)}`;
}

function StatusBadge({ label, variant }: { label: string; variant: "green" | "red" | "yellow" | "gray" }) {
  const cls = {
    green: "border-green-500/30 bg-green-500/10 text-green-400",
    red: "border-red-500/30 bg-red-500/10 text-red-400",
    yellow: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
    gray: "border-ink-600 bg-ink-800 text-mist",
  }[variant];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${variant === "green" ? "bg-green-400" : variant === "red" ? "bg-red-400" : variant === "yellow" ? "bg-yellow-400" : "bg-mist/40"}`} />
      {label}
    </span>
  );
}

function PaginationControls({ page, totalPages, onPrev, onNext }: { page: number; totalPages: number; onPrev: () => void; onNext: () => void; }) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-center gap-3 pt-2">
      <button type="button" onClick={onPrev} disabled={page === 1} className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-ink-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">← Prev</button>
      <span className="text-xs text-mist">Page {page} of {totalPages}</span>
      <button type="button" onClick={onNext} disabled={page === totalPages} className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-ink-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">Next →</button>
    </div>
  );
}

interface SchemaCardProps {
  schema: SchemaV2;
  client: OpaqueClient;
  psrChain: PsrChain;
  onAction: (msg: string, isError?: boolean) => void;
  onRefresh: () => void;
}

function SchemaCard({ schema, client, psrChain, onAction, onRefresh }: SchemaCardProps) {
  const uid = useId();
  const [delegateInput, setDelegateInput] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmDeprecateOpen, setConfirmDeprecateOpen] = useState(false);

  const runTx = useCallback(
    async (label: string, action: () => Promise<unknown>) => {
      setBusy(label);
      try {
        await action();
        onAction(`${label} successful`);
        onRefresh();
      } catch (e) {
        onAction(e instanceof Error ? e.message : `${label} failed`, true);
      } finally {
        setBusy(null);
        setDelegateInput("");
      }
    },
    [onAction, onRefresh],
  );

  const handleDeprecate = () =>
    runTx("Deprecate", () => client.deprecateSchema(psrChain, schema.schemaId));

  const handleAddDelegate = () => {
    if (!delegateInput.trim()) return;
    runTx("Add delegate", () => client.addSchemaDelegate(psrChain, schema.schemaId, delegateInput.trim()));
  };

  const handleRemoveDelegate = (delegate: string) =>
    runTx("Remove delegate", () => client.removeSchemaDelegate(psrChain, schema.schemaId, delegate));

  const isBusy = busy !== null;

  return (
    <>
      <div className={`rounded-xl border bg-ink-900 px-5 py-4 space-y-4 ${schema.deprecated ? "border-ink-800 opacity-70" : "border-ink-700"}`}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-semibold text-white text-sm truncate">{schema.name}</p>
            <p className="text-xs text-mist font-mono mt-0.5 truncate">{shortHex(schema.schemaId)}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {schema.deprecated ? <StatusBadge label="Deprecated" variant="gray" /> : <StatusBadge label="Active" variant="green" />}
            {schema.revocable && <StatusBadge label="Revocable" variant="yellow" />}
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-xs text-ink-500 uppercase tracking-widest font-semibold">Delegates</p>
          {schema.delegates.length === 0 ? (
            <p className="text-xs text-mist italic">No delegates</p>
          ) : (
            <div className="space-y-1">
              {schema.delegates.map((d) => (
                <div key={d} className="flex items-center justify-between gap-2 rounded-lg bg-ink-800 px-3 py-1.5">
                  <span className="text-xs font-mono text-white">{shortAddr(d)}</span>
                  <button type="button" disabled={isBusy || schema.deprecated} onClick={() => handleRemoveDelegate(d)} className="text-xs text-red-400 hover:text-red-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                    {busy === "Remove delegate" ? "…" : "Remove"}
                  </button>
                </div>
              ))}
            </div>
          )}
          {!schema.deprecated && (
            <div className="flex gap-2 pt-1">
              <input id={`${uid}-delegate`} type="text" placeholder="Delegate wallet address" value={delegateInput} onChange={(e) => setDelegateInput(e.target.value)} disabled={isBusy} className="flex-1 rounded-lg border border-ink-700 bg-ink-800 px-3 py-1.5 text-xs text-white placeholder-ink-500 focus:outline-none focus:border-sol-purple transition-colors disabled:opacity-50" />
              <button type="button" onClick={handleAddDelegate} disabled={isBusy || !delegateInput.trim()} className="rounded-lg bg-ink-700 hover:bg-ink-600 px-3 py-1.5 text-xs font-medium text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                {busy === "Add delegate" ? "…" : "Add"}
              </button>
            </div>
          )}
        </div>

        {!schema.deprecated && (
          <div className="pt-1 border-t border-ink-800">
            <button type="button" onClick={() => setConfirmDeprecateOpen(true)} disabled={isBusy} className="w-full rounded-lg border border-red-500/30 bg-red-500/5 hover:bg-red-500/10 px-4 py-2 text-xs font-medium text-red-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
              {busy === "Deprecate" ? "Deprecating…" : "Deprecate Schema"}
            </button>
            <p className="text-[11px] text-ink-500 mt-1.5 text-center">
              Deprecation is irreversible — no new attestations can be issued under this schema.
            </p>
          </div>
        )}
      </div>

      <ModalShell open={confirmDeprecateOpen} title="Deprecate Schema" description="This action is permanent and cannot be undone." onClose={() => setConfirmDeprecateOpen(false)} closeOnBackdrop={!isBusy} maxWidthClassName="max-w-sm">
        <div className="space-y-4">
          <p className="text-sm text-mist">
            Deprecating <span className="text-white font-medium">{schema.name}</span> will permanently prevent any new attestations from being issued under this schema. Existing attestations will remain valid.
          </p>
          <div className="flex gap-3">
            <button type="button" onClick={() => setConfirmDeprecateOpen(false)} disabled={isBusy} className="flex-1 rounded-lg border border-ink-700 bg-ink-800 px-4 py-2 text-sm font-medium text-white hover:bg-ink-700 disabled:opacity-40 transition-colors">Cancel</button>
            <button type="button" onClick={() => { setConfirmDeprecateOpen(false); void handleDeprecate(); }} disabled={isBusy} className="flex-1 rounded-lg border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 px-4 py-2 text-sm font-medium text-red-400 disabled:opacity-40 transition-colors">
              {busy === "Deprecate" ? "Deprecating…" : "Confirm Deprecate"}
            </button>
          </div>
        </div>
      </ModalShell>
    </>
  );
}

function AttestationCard({ att }: { att: ManagedAttestation }) {
  const statusBadge = att.isRevoked ? <StatusBadge label="Revoked" variant="red" /> : <StatusBadge label="Active" variant="green" />;
  return (
    <div className={`rounded-xl border bg-ink-900 px-5 py-4 space-y-3 ${att.isRevoked ? "border-ink-800 opacity-70" : "border-ink-700"}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold text-white text-sm truncate">{att.schemaName}</p>
          <p className="text-xs text-mist font-mono mt-0.5">UID: {shortHex(att.uidHex)}</p>
        </div>
        {statusBadge}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        <div>
          <p className="text-ink-500">Recipient hash</p>
          <p className="font-mono text-white truncate">{shortHex(att.stealthAddressHashHex)}</p>
        </div>
        <div>
          <p className="text-ink-500">Created slot</p>
          <p className="text-white">{att.createdAt.toLocaleString()}</p>
        </div>
        {att.expirationSlot > 0 && (
          <div>
            <p className="text-ink-500">Expires</p>
            <p className="text-white">Slot {att.expirationSlot.toLocaleString()}</p>
          </div>
        )}
      </div>
    </div>
  );
}

interface ManageViewProps {
  onNavigate?: (tab: Tab) => void;
}

export function ManageView({ onNavigate }: ManageViewProps = {}) {
  const { client, isSetup, ethereumAddress } = useOpaqueSession();
  const [psrChain, setPsrChain] = useState<PsrChain>("solana");
  const [schemas, setSchemas] = useState<SchemaV2[]>([]);
  const [attestations, setAttestations] = useState<ManagedAttestation[]>([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState<{ msg: string; isError: boolean } | null>(null);
  const [section, setSection] = useState<"schemas" | "attestations">("schemas");
  const [recipientSearch, setRecipientSearch] = useState("");
  const [attestationPage, setAttestationPage] = useState(1);
  const [schemaPage, setSchemaPage] = useState(1);

  const mySchemas = useMemo(
    () => [...schemas].sort((a, b) => b.createdAt - a.createdAt),
    [schemas],
  );

  const showToast = useCallback((msg: string, isError = false) => {
    setToast({ msg, isError });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const filteredAttestations = useMemo(() => {
    const q = recipientSearch.trim().toLowerCase().replace(/^0x/, "");
    if (!q) return attestations;
    return attestations.filter((att) => att.stealthAddressHashHex.toLowerCase().includes(q));
  }, [attestations, recipientSearch]);

  const pagedAttestations = useMemo(() => {
    const start = (attestationPage - 1) * ITEMS_PER_PAGE;
    return filteredAttestations.slice(start, start + ITEMS_PER_PAGE);
  }, [filteredAttestations, attestationPage]);
  const totalAttestationPages = Math.max(1, Math.ceil(filteredAttestations.length / ITEMS_PER_PAGE));

  const pagedSchemas = useMemo(() => {
    const start = (schemaPage - 1) * ITEMS_PER_PAGE;
    return mySchemas.slice(start, start + ITEMS_PER_PAGE);
  }, [mySchemas, schemaPage]);
  const totalSchemaPages = Math.max(1, Math.ceil(mySchemas.length / ITEMS_PER_PAGE));

  const load = useCallback(async () => {
    if (!client) return;
    setLoading(true);
    try {
      const [schemaRows, attestationRows] = await Promise.all([
        client.getMySchemas(psrChain),
        client.getMyIssuedAttestations(psrChain),
      ]);
      setSchemas(schemaRows);
      const nameBySchemaId = new Map(schemaRows.map((s) => [s.schemaId.toLowerCase(), s.name]));
      const mine: ManagedAttestation[] = attestationRows
        .map((a: AttestationV2) => ({
          uidHex: a.uid,
          schemaIdHex: a.schemaId,
          schemaName: nameBySchemaId.get(a.schemaId.toLowerCase()) ?? "Unknown Schema",
          stealthAddressHashHex: a.stealthAddressHash,
          createdAt: a.createdAt,
          expirationSlot: a.expirationSlot,
          revocationSlot: a.revocationSlot,
          isRevoked: a.revocationSlot > 0,
        }))
        .sort((x, y) => y.createdAt - x.createdAt);
      setAttestations(mine);
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Failed to load data", true);
    } finally {
      setLoading(false);
    }
  }, [client, psrChain, showToast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setAttestationPage(1);
  }, [recipientSearch]);

  if (!isSetup || !client) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        <p className="text-mist">Complete key setup to manage schemas and attestations.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Manage</h1>
          <p className="text-sm text-mist mt-1">Schemas you own and attestations you issued.</p>
        </div>
        <div className="flex items-center gap-2">
          <PsrChainToggle value={psrChain} onChange={setPsrChain} ethConnected={ethereumAddress != null} />
          {onNavigate && (
            <button type="button" onClick={() => onNavigate("attest")} className="rounded-xl bg-sol-purple px-4 py-2 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors">Issue Attestation</button>
          )}
          <button type="button" onClick={() => void load()} disabled={loading} className="rounded-xl border border-ink-700 bg-ink-900 px-4 py-2 text-xs font-medium text-white hover:bg-ink-800 disabled:opacity-50 transition-colors">
            {loading ? <span className="flex items-center gap-1.5"><span className="h-3 w-3 animate-spin rounded-full border border-ink-600 border-t-white" />Loading…</span> : "Refresh"}
          </button>
        </div>
      </div>

      <div className="flex gap-2">
        {(["schemas", "attestations"] as const).map((s) => (
          <button key={s} type="button" onClick={() => setSection(s)} className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors capitalize flex items-center gap-1.5 ${section === s ? "bg-sol-purple text-white" : "bg-ink-900 border border-ink-700 text-mist hover:text-white"}`}>
            {s === "schemas" ? "My Schemas" : "Attestations Issued"}
            <span className={`rounded-full px-1.5 py-0.5 text-[10px] ${section === s ? "bg-white/20" : "bg-ink-700"}`}>
              {s === "schemas" ? mySchemas.length : attestations.length}
            </span>
          </button>
        ))}
      </div>

      {section === "schemas" && (
        <>
          {loading && mySchemas.length === 0 ? (
            <div className="flex justify-center py-12"><span className="h-7 w-7 animate-spin rounded-full border-2 border-ink-600 border-t-sol-purple" /></div>
          ) : mySchemas.length === 0 ? (
            <div className="rounded-xl border border-ink-800 bg-ink-900/50 px-6 py-10 text-center space-y-3">
              <p className="text-white font-medium">No schemas yet</p>
              <p className="text-sm text-mist max-w-xs mx-auto">You haven't created any schemas. Create one in Schema Studio.</p>
              {onNavigate && (
                <button type="button" onClick={() => onNavigate("schemas")} className="mt-2 rounded-xl bg-sol-purple px-4 py-2 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors">Create New Schema</button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {pagedSchemas.map((schema) => (
                  <SchemaCard key={schema.schemaId} schema={schema} client={client} psrChain={psrChain} onAction={showToast} onRefresh={() => void load()} />
                ))}
              </div>
              <PaginationControls page={schemaPage} totalPages={totalSchemaPages} onPrev={() => setSchemaPage((p) => Math.max(1, p - 1))} onNext={() => setSchemaPage((p) => Math.min(totalSchemaPages, p + 1))} />
            </div>
          )}
        </>
      )}

      {section === "attestations" && (
        <>
          {attestations.length > 0 && (
            <div className="relative">
              <input type="text" placeholder="Search by recipient stealth address hash (0x…)" value={recipientSearch} onChange={(e) => setRecipientSearch(e.target.value)} className="w-full rounded-xl border border-ink-700 bg-ink-900 pl-4 pr-4 py-2.5 text-sm text-white placeholder-ink-500 focus:outline-none focus:border-sol-purple transition-colors" />
            </div>
          )}
          {loading && attestations.length === 0 ? (
            <div className="flex justify-center py-12"><span className="h-7 w-7 animate-spin rounded-full border-2 border-ink-600 border-t-sol-purple" /></div>
          ) : attestations.length === 0 ? (
            <div className="rounded-xl border border-ink-800 bg-ink-900/50 px-6 py-10 text-center space-y-3">
              <p className="text-white font-medium">No attestations issued</p>
              <p className="text-sm text-mist max-w-xs mx-auto">You haven't issued any attestations yet.</p>
              {onNavigate && (
                <button type="button" onClick={() => onNavigate("attest")} className="mt-2 rounded-xl bg-sol-purple px-4 py-2 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors">Issue Attestation</button>
              )}
            </div>
          ) : filteredAttestations.length === 0 ? (
            <div className="rounded-xl border border-ink-800 bg-ink-900/50 px-6 py-8 text-center space-y-2">
              <p className="text-white font-medium">No matching attestations</p>
              <button type="button" onClick={() => setRecipientSearch("")} className="text-xs text-sol-purple hover:underline">Clear search</button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {pagedAttestations.map((att) => (
                  <AttestationCard key={att.uidHex} att={att} />
                ))}
              </div>
              <PaginationControls page={attestationPage} totalPages={totalAttestationPages} onPrev={() => setAttestationPage((p) => Math.max(1, p - 1))} onNext={() => setAttestationPage((p) => Math.min(totalAttestationPages, p + 1))} />
            </div>
          )}
        </>
      )}

      {toast && (
        <div className={`fixed bottom-24 md:bottom-6 left-4 right-4 md:left-auto md:right-6 z-50 max-w-sm md:ml-auto rounded-xl border px-4 py-3 text-sm shadow-2xl backdrop-blur-lg transition-all ${toast.isError ? "border-red-500/30 bg-red-950/80 text-red-300" : "border-green-500/30 bg-green-950/80 text-green-300"}`}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}
