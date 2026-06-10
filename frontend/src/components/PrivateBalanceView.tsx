import { useState, useEffect, useCallback, useMemo } from "react";
import { Connection, PublicKey } from "@solana/web3.js";
import type { Hex } from "viem";
import {
  ephemeralPrivateKeyToCompressedPublicKey,
  type UnifiedOwnedOutput,
} from "@opaquecash/opaque";
import { formatSol, hexToBytes, bytesToHex, shortenAddress } from "../lib/format";
import { getRpcUrl, getCluster } from "../lib/chain";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import { useWallet } from "../hooks/useWallet";
import type { ProtocolStep } from "./ProtocolStepper";
import { ClaimModal } from "./ClaimModal";
import { useProtocolLog } from "../context/ProtocolLogContext";
import { useTxHistoryStore } from "../store/txHistoryStore";
import { useGhostAddressStore } from "../store/ghostAddressStore";
import { useWatchlist, useWatchlistStore } from "../hooks/useWatchlist";
import { useToast } from "../context/ToastContext";
import { getNativeToken } from "../lib/tokens";
import type { TokenInfo } from "../lib/tokens";
import { ExplorerLink } from "./ExplorerLink";
import { ModalShell } from "./ModalShell";

function isAddress(a: string): boolean {
  const t = a.trim();
  if (t.startsWith("0x") && t.length === 42) return /^0x[0-9a-fA-F]{40}$/i.test(t);
  try {
    new PublicKey(t);
    return true;
  } catch {
    return false;
  }
}

export type FoundTx = {
  id: string;
  /** Scanner stealth address (0x EVM-style) — used for display + matching. */
  address: string;
  /** Actual Solana account holding the funds. */
  solanaAddress?: string;
  balance: bigint;
  /** 33-byte compressed ephemeral pubkey (hex) the SDK sweeps from. */
  ephemeralPublicKey?: string;
  txHash: string;
  blockNumber: number;
  isSpent?: boolean;
  source: "announcement" | "manual" | "watch";
};

/** Build a UnifiedOwnedOutput-shaped record for a ghost's stored ephemeral key (Solana). */
function ghostOutput(stealthAddress: string, ephemeralPrivKeyHex: string): UnifiedOwnedOutput {
  const ephemeralPublicKey = bytesToHex(
    ephemeralPrivateKeyToCompressedPublicKey(hexToBytes(ephemeralPrivKeyHex)),
  ) as Hex;
  return {
    stealthAddress: stealthAddress as `0x${string}`,
    transactionHash: "0x" as Hex,
    blockNumber: 0,
    logIndex: 0,
    viewTag: 0,
    ephemeralPublicKey,
    chain: "solana",
    chainId: 1,
    source: "native",
  };
}

export type PortfolioEntry = { tx: FoundTx; balanceRaw: bigint };

export function PrivateBalanceView() {
  const { client, isSetup } = useOpaqueSession();
  const { address: mainWalletAddress } = useWallet();
  const cluster = getCluster();
  const { push: logPush } = useProtocolLog();
  const pushTx = useTxHistoryStore((s) => s.push);
  const { showToast } = useToast();

  const [found, setFound] = useState<FoundTx[]>([]);
  const [ghostTxs, setGhostTxs] = useState<FoundTx[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [claimingId, setClaimingId] = useState<string | null>(null);
  const [claimError, setClaimError] = useState<string | null>(null);
  const [withdrawalSteps, setWithdrawalSteps] = useState<ProtocolStep[]>([]);
  const [destinationByTxId, setDestinationByTxId] = useState<Record<string, string>>({});
  const [claimModalTx, setClaimModalTx] = useState<FoundTx | null>(null);
  const [manualImportOpen, setManualImportOpen] = useState(false);
  const [manualImportAddress, setManualImportAddress] = useState("");
  const [manualImportError, setManualImportError] = useState<string | null>(null);

  const ghostStoreEntries = useGhostAddressStore((s) => s.entries);
  const watchlistAdd = useWatchlistStore((s) => s.add);
  const watchlistArchive = useWatchlistStore((s) => s.archive);
  const watchlistAddresses = useWatchlist(cluster);

  const publicClient = useMemo(() => new Connection(getRpcUrl(), "confirmed"), []);
  const nativeAsset: TokenInfo = getNativeToken();

  const ghostEntries = useMemo(
    () => ghostStoreEntries.filter((e) => e.cluster === cluster && !!e.ephemeralPrivKeyHex),
    [ghostStoreEntries, cluster],
  );

  // Discover announced owned outputs via the SDK (fetch + WASM match + balance, one path).
  useEffect(() => {
    if (!client || cluster == null) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const outputs = await client.scan({ chains: ["solana"], includeCrossChain: false });
        const balances = await client.getBalancesForOutputs(outputs);
        if (cancelled) return;
        const txs: FoundTx[] = outputs.map((o, i) => ({
          id: `${o.transactionHash}-${o.logIndex}`,
          address: o.stealthAddress,
          solanaAddress: balances[i]?.address,
          balance: balances[i]?.nativeRaw ?? 0n,
          ephemeralPublicKey: o.ephemeralPublicKey,
          txHash: o.transactionHash,
          blockNumber: o.blockNumber,
          source: "announcement",
        }));
        setFound(txs);
        logPush("wasm", `Matched ${txs.length} owned announcement(s)`);
      } catch (err) {
        if (!cancelled) console.warn("[Opaque] scan error", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, cluster, refreshKey, logPush]);

  // Manual ghost balances (not announced): derive the Solana account + balance from stored keys.
  useEffect(() => {
    if (!client || cluster == null) {
      setGhostTxs([]);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const outputs = ghostEntries.map((g) =>
          ghostOutput(g.stealthAddress, g.ephemeralPrivKeyHex as string),
        );
        const keyed = await client.getBalancesForOutputs(outputs);
        // View-only watchlist addresses (no stored key): direct balance read.
        const viewOnly = watchlistAddresses.filter(
          (a) => !ghostEntries.some((g) => g.stealthAddress.toLowerCase() === a.toLowerCase()),
        );
        const viewBalances = await Promise.all(
          viewOnly.map(async (addr) => {
            try {
              return BigInt(await publicClient.getBalance(new PublicKey(addr)));
            } catch {
              return 0n;
            }
          }),
        );
        if (cancelled) return;
        const ghostFound: FoundTx[] = [];
        ghostEntries.forEach((g, i) => {
          const balance = keyed[i]?.nativeRaw ?? 0n;
          if (balance > 0n) {
            ghostFound.push({
              id: `ghost-${g.stealthAddress}`,
              address: g.stealthAddress,
              solanaAddress: keyed[i]?.address,
              balance,
              ephemeralPublicKey: outputs[i].ephemeralPublicKey,
              txHash: "",
              blockNumber: 0,
              source: "manual",
            });
          }
        });
        viewOnly.forEach((addr, i) => {
          const balance = viewBalances[i] ?? 0n;
          if (balance > 0n) {
            ghostFound.push({
              id: `watch-${addr}`,
              address: addr,
              balance,
              txHash: "",
              blockNumber: 0,
              source: "watch",
            });
          }
        });
        setGhostTxs(ghostFound);
      } catch (err) {
        if (!cancelled) console.warn("[Opaque] ghost balance error", err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, cluster, ghostEntries, watchlistAddresses, publicClient, refreshKey]);

  const portfolio = useMemo(() => {
    const activeTxs = [...found.filter((tx) => !tx.isSpent), ...ghostTxs];
    let totalRaw = 0n;
    const entries: PortfolioEntry[] = [];
    for (const tx of activeTxs) {
      if (tx.balance > 0n) {
        totalRaw += tx.balance;
        entries.push({ tx, balanceRaw: tx.balance });
      }
    }
    return { asset: nativeAsset, totalRaw, entries };
  }, [found, ghostTxs, nativeAsset]);

  const setDestination = useCallback((txId: string, value: string) => {
    setDestinationByTxId((prev) => ({ ...prev, [txId]: value }));
  }, []);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    setRefreshKey((k) => k + 1);
    // The effects re-run on refreshKey; clear the flag shortly after.
    setTimeout(() => setRefreshing(false), 800);
  }, []);

  const handleClaim = useCallback(
    async (tx: FoundTx, destination: string) => {
      const trimmed = destination.trim();
      if (!client) {
        setClaimError("Session not ready.");
        return;
      }
      if (tx.source === "watch" || !tx.ephemeralPublicKey) {
        setClaimError("This address has no stored key and cannot be withdrawn.");
        return;
      }
      if (tx.balance <= 0n) return;
      if (!trimmed || !isAddress(trimmed)) {
        setClaimError("Enter a valid destination address.");
        return;
      }

      setClaimingId(tx.id);
      setClaimError(null);
      setWithdrawalSteps([
        { id: "wd-1", status: "wait", label: "Reconstructing key + sweeping…" },
      ]);
      logPush("wasm", "Reconstructing stealth key and signing claim tx…");
      logPush("blockchain", `Claim: ${formatSol(tx.balance)} SOL → ${shortenAddress(trimmed)}`);

      try {
        const { tx: sig } = await client.sweep({
          output: { ephemeralPublicKey: tx.ephemeralPublicKey as Hex },
          chain: "solana",
          destination: trimmed,
        });
        setWithdrawalSteps([{ id: "wd-1", status: "done", label: "Swept to destination." }]);
        pushTx({
          cluster,
          kind: tx.source === "manual" ? "ghost" : "received",
          counterparty: tx.source === "manual" ? "Manual Ghost" : shortenAddress(tx.address, 10, 0),
          amountLamports: tx.balance.toString(),
          tokenSymbol: "SOL",
          tokenAddress: null,
          amount: formatSol(tx.balance),
          txHash: sig,
          stealthAddress: tx.address,
        });
        if (cluster != null) {
          showToast("Withdrawal successful", { explorerTx: { cluster, txSig: sig } });
        }
        if (tx.source === "manual") {
          setGhostTxs((prev) => prev.filter((t) => t.id !== tx.id));
        } else {
          setFound((prev) => prev.map((t) => (t.id === tx.id ? { ...t, isSpent: true } : t)));
        }
        setClaimModalTx((prev) => (prev?.id === tx.id ? null : prev));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setClaimError(msg);
        setWithdrawalSteps([{ id: "wd-1", status: "error", label: "Sweep failed", detail: msg }]);
      } finally {
        setClaimingId(null);
      }
    },
    [client, cluster, pushTx, showToast, logPush],
  );

  const allEntries = portfolio.entries;
  const totalSol = portfolio.totalRaw;

  if (!isSetup) {
    return (
      <div className="card max-w-lg mx-auto text-center text-neutral-500">
        Complete key setup first.
      </div>
    );
  }

  return (
    <div className="w-full flex flex-col">
      <div className="mb-8">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="font-display text-2xl font-bold text-white">Private balance</h2>
            <p className="mt-1 text-sm text-mist">
              SOL across your stealth addresses. Withdraw to any Solana address.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleRefresh}
              disabled={refreshing || loading}
              className="rounded-xl border border-ink-600 bg-ink-950/30 px-3.5 py-2 text-sm font-medium text-mist transition-colors hover:border-sol-purple/30 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {refreshing || loading ? "Scanning…" : "Refresh"}
            </button>
            <button
              type="button"
              onClick={() => {
                setManualImportOpen(true);
                setManualImportAddress("");
                setManualImportError(null);
              }}
              className="rounded-xl border border-ink-600 bg-ink-950/30 px-3.5 py-2 text-sm font-medium text-mist transition-colors hover:border-sol-purple/30 hover:text-white"
            >
              Import ghost
            </button>
          </div>
        </div>
      </div>

      {claimError && !claimModalTx && (
        <div className="mb-4 p-3 rounded-xl bg-error/10 border border-error/30 text-error text-sm">
          {claimError}
        </div>
      )}

      {loading ? (
        <div className="rounded-2xl border border-ink-700 bg-ink-900/25 p-6">
          <p className="text-mist text-sm">Deciphering payments…</p>
        </div>
      ) : totalSol === 0n && allEntries.length === 0 ? (
        <div className="rounded-2xl border border-ink-700 bg-ink-900/25 p-6">
          <p className="text-mist text-sm">No incoming payments found yet.</p>
          <p className="text-mist/70 text-xs mt-1">
            Payments sent to your stealth address will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="rounded-2xl border border-ink-700 bg-ink-900/30 p-6">
            <p className="text-mist text-sm">Total SOL</p>
            <p className="font-display text-2xl font-bold text-white mt-1">{formatSol(totalSol)}</p>
            <p className="text-mist/70 text-xs mt-1">
              {allEntries.length} address{allEntries.length !== 1 ? "es" : ""}
            </p>
          </div>

          <h3 className="font-display text-xl font-bold text-white">SOL — Stealth addresses</h3>
          <div className="space-y-3">
            {allEntries
              .filter((e) => e.balanceRaw > 0n)
              .map(({ tx, balanceRaw }) => {
                const amountStr = formatSol(balanceRaw);
                const canWithdraw = tx.source !== "watch" && !!tx.ephemeralPublicKey;
                return (
                  <div
                    key={tx.id}
                    className="rounded-2xl border border-ink-700 bg-ink-900/25 p-5 flex flex-wrap items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        {tx.source !== "announcement" && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40">
                            {tx.source === "manual" ? "Manual/Ghost Funds" : "Watch-only"}
                          </span>
                        )}
                        <ExplorerLink
                          cluster={cluster}
                          value={tx.solanaAddress ?? tx.address}
                          type="address"
                          className="text-mist text-xs"
                        />
                        {tx.txHash && (
                          <ExplorerLink
                            cluster={cluster}
                            value={tx.txHash}
                            type="tx"
                            className="text-mist/70 text-xs"
                            startChars={8}
                            endChars={6}
                          />
                        )}
                      </div>
                      <p className="text-success font-semibold mt-0.5">{amountStr} SOL</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {tx.source !== "announcement" && cluster != null && (
                        <button
                          type="button"
                          onClick={() => {
                            watchlistArchive(cluster, tx.address);
                            showToast("Address archived. It will no longer be polled for balances.");
                          }}
                          className="px-2 py-1 text-xs rounded-md border border-neutral-600 text-neutral-400 hover:bg-neutral-800 hover:text-neutral-300"
                        >
                          Archive
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={!canWithdraw || claimingId !== null}
                        onClick={() => setClaimModalTx(tx)}
                        className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-sol-gradient text-white disabled:opacity-40 disabled:cursor-not-allowed hover:enabled:opacity-90"
                      >
                        {claimingId === tx.id ? "Withdrawing…" : canWithdraw ? "Withdraw" : "No key"}
                      </button>
                    </div>
                    {canWithdraw && (
                      <div className="w-full mt-2">
                        <input
                          type="text"
                          value={destinationByTxId[tx.id] ?? ""}
                          onChange={(e) => setDestination(tx.id, e.target.value)}
                          placeholder="Destination Solana address…"
                          className="input-field text-sm"
                        />
                        {mainWalletAddress && (
                          <button
                            type="button"
                            onClick={() => setDestination(tx.id, mainWalletAddress)}
                            className="mt-1.5 px-2 py-1 text-xs rounded-md btn-secondary"
                          >
                            Use connected wallet
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {claimModalTx && (
        <ClaimModal
          tx={claimModalTx}
          asset={nativeAsset}
          destination={destinationByTxId[claimModalTx.id] ?? ""}
          mainWalletAddress={mainWalletAddress ?? undefined}
          cluster={cluster}
          claiming={claimingId === claimModalTx.id}
          error={claimError}
          onDestinationChange={(value: string) => setDestination(claimModalTx.id, value)}
          onConfirm={() => handleClaim(claimModalTx, destinationByTxId[claimModalTx.id] ?? "")}
          onClose={() => {
            setClaimModalTx(null);
            setClaimError(null);
            setWithdrawalSteps([]);
          }}
          withdrawalSteps={withdrawalSteps}
        />
      )}

      {manualImportOpen && (
        <ModalShell
          open
          title="Import ghost address"
          description="Add a previously generated stealth address to tracking. Without its ephemeral key, you can view balance but cannot withdraw."
          onClose={() => setManualImportOpen(false)}
          maxWidthClassName="max-w-md"
        >
          <input
            type="text"
            value={manualImportAddress}
            onChange={(e) => {
              setManualImportAddress(e.target.value);
              setManualImportError(null);
            }}
            placeholder="0x… or Solana address"
            className="input-field w-full mb-2 font-mono text-sm"
          />
          {manualImportError && <p className="text-error text-xs mb-3">{manualImportError}</p>}
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={() => setManualImportOpen(false)}
              className="rounded-xl border border-ink-600 bg-ink-950/30 px-4 py-2 text-sm font-medium text-mist hover:border-sol-purple/30 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => {
                const trimmed = manualImportAddress.trim();
                if (!trimmed || !isAddress(trimmed)) {
                  setManualImportError("Invalid address.");
                  return;
                }
                if (cluster == null) {
                  setManualImportError("Connect to a network first.");
                  return;
                }
                const stored = useGhostAddressStore
                  .getState()
                  .entries.find((e) => e.stealthAddress.toLowerCase() === trimmed.toLowerCase());
                if (
                  ghostEntries.some((e) => e.stealthAddress.toLowerCase() === trimmed.toLowerCase()) ||
                  watchlistAddresses.some((a) => a.toLowerCase() === trimmed.toLowerCase())
                ) {
                  setManualImportError("Address is already in the tracking list.");
                  return;
                }
                if (stored?.ephemeralPrivKeyHex) {
                  useGhostAddressStore.getState().add({
                    cluster,
                    stealthAddress: trimmed,
                    ephemeralPrivKeyHex: stored.ephemeralPrivKeyHex,
                  });
                }
                watchlistAdd(cluster, trimmed);
                setManualImportOpen(false);
                showToast("Ghost address added. Checking for funds…");
                setRefreshKey((k) => k + 1);
              }}
              className="rounded-xl bg-sol-gradient px-4 py-2 text-sm font-semibold text-white hover:opacity-90"
            >
              Add & check
            </button>
          </div>
        </ModalShell>
      )}
    </div>
  );
}
