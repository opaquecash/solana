/**
 * My Traits — reputation attestations discovered for the user's stealth addresses.
 *
 * Discovery and key reconstruction run through OpaqueClient (client.discoverTraits over the cached
 * announcement rows); useScanner stays only as the IndexedDB fetch/cache layer. Each trait can be
 * proven with a browser-side ZK proof via ProofGeneratorModal.
 */

import { useEffect, useMemo, useState } from "react";
import type { DiscoveredTrait, IndexerAnnouncement } from "@opaquecash/opaque";
import { useWallet } from "../hooks/useWallet";
import { getCluster } from "../lib/chain";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import { useScanner } from "../hooks/useScanner";
import { getConfigForCluster } from "../contracts/contract-config";
import type { CachedAnnouncement } from "../lib/opaqueCache";
import { shortenAddress } from "../lib/format";
import type { Tab } from "./Layout";
import { ProofGeneratorModal } from "./ProofGeneratorModal";

/** Map a cached Solana announcement into the indexer row shape client.discoverTraits expects. */
function cachedToRow(c: CachedAnnouncement): IndexerAnnouncement {
  return {
    blockNumber: String(c.slot),
    etherealPublicKey: (c.args?.ephemeralPubKey ?? "0x") as `0x${string}`,
    logIndex: c.logIndex,
    metadata: (c.args?.metadata ?? "0x") as `0x${string}`,
    stealthAddress: (c.args?.stealthAddress ?? "0x") as `0x${string}`,
    transactionHash: c.transactionSignature as `0x${string}`,
    viewTag: parseInt((c.args?.metadata ?? "0x00").slice(2, 4), 16),
  };
}

function TraitCard({ trait, onProve }: { trait: DiscoveredTrait; onProve: (t: DiscoveredTrait) => void }) {
  return (
    <div className="rounded-xl border border-ink-700 bg-ink-900 px-5 py-4 space-y-3 hover:border-ink-600 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold text-white text-sm truncate">Trait #{trait.attestationId}</p>
          <p className="text-xs text-mist mt-0.5 font-mono truncate">{shortenAddress(trait.stealthAddress, 10, 6)}</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-green-500/30 bg-green-500/10 px-2.5 py-1 text-xs font-medium text-green-400">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
          Discovered
        </span>
      </div>
      <button
        type="button"
        onClick={() => onProve(trait)}
        className="w-full rounded-xl bg-sol-purple/10 border border-sol-purple/30 py-2 text-xs font-semibold text-sol-purple hover:bg-sol-purple/20 transition-colors"
      >
        Generate ZK Proof ▶
      </button>
    </div>
  );
}

interface MyTraitsViewProps {
  onNavigate?: (tab: Tab) => void;
}

export function MyTraitsView({ onNavigate }: MyTraitsViewProps = {}) {
  const { client, isSetup } = useOpaqueSession();
  const { connection } = useWallet();
  const cluster = getCluster();
  const currentConfig = getConfigForCluster(cluster);
  const scanner = useScanner({
    cluster,
    publicClient: connection,
    announcerAddress: currentConfig?.announcerProgram.toBase58() ?? null,
    enabled: Boolean(cluster && currentConfig),
  });
  const { refresh: refreshScanner, announcements } = scanner;

  const [traits, setTraits] = useState<DiscoveredTrait[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [activeProofTrait, setActiveProofTrait] = useState<DiscoveredTrait | null>(null);

  const rows = useMemo(() => announcements.map(cachedToRow), [announcements]);

  useEffect(() => {
    if (!client || !isSetup || rows.length === 0) {
      setTraits([]);
      return;
    }
    let cancelled = false;
    setDiscovering(true);
    (async () => {
      try {
        const discovered = await client.discoverTraits(rows);
        if (!cancelled) setTraits(discovered);
      } catch (err) {
        if (!cancelled) console.error("[MyTraitsView] discoverTraits failed:", err);
      } finally {
        if (!cancelled) setDiscovering(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, isSetup, rows]);

  const scanning = discovering || scanner.progress.phase === "syncing" || scanner.progress.phase === "backfilling";

  return (
    <div className="max-w-2xl mx-auto px-4 py-8 space-y-8">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">My Traits</h1>
          <p className="text-xs text-mist mt-1">Reputation attestations issued to your stealth addresses.</p>
        </div>
        <div className="flex items-center gap-2">
          {onNavigate && (
            <button type="button" onClick={() => onNavigate("attest")} className="rounded-xl bg-sol-purple px-4 py-2 text-xs font-semibold text-white hover:bg-sol-purple/90 transition-colors">Issue Attestation</button>
          )}
          <button type="button" onClick={() => void refreshScanner()} disabled={scanning} className="rounded-xl border border-ink-700 bg-ink-900 px-4 py-2 text-xs font-medium text-white hover:bg-ink-800 disabled:opacity-50 transition-colors">
            {scanning ? <span className="flex items-center gap-1.5"><span className="h-3 w-3 animate-spin rounded-full border border-ink-600 border-t-white" />Scanning…</span> : "Rescan"}
          </button>
        </div>
      </div>

      {traits.length > 0 ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {traits.map((trait) => (
            <TraitCard key={`${trait.attestationId}-${trait.txHash}`} trait={trait} onProve={setActiveProofTrait} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-ink-800 bg-ink-900/50 px-6 py-10 text-center space-y-3">
          <p className="text-white font-medium">No traits found</p>
          <p className="text-sm text-mist max-w-xs mx-auto">
            {scanning ? "Scanning for attestations issued to your stealth addresses…" : "Run a scan to discover attestations issued to you."}
          </p>
        </div>
      )}

      {activeProofTrait && (
        <ProofGeneratorModal trait={activeProofTrait} onClose={() => setActiveProofTrait(null)} />
      )}
    </div>
  );
}
