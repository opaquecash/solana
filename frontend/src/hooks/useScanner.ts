/**
 * useScanner — IndexedDB-backed announcement scanner.
 * - Primary: single GraphQL fetch to Subgraph (latest 1000 announcements). No getLogs in this path.
 * - Fallback: if Subgraph fetch fails, uses chunked RPC getLogs (adaptive range, halve on limit).
 * - Loads cached events first; incremental sync from lastScannedSlot when using RPC.
 * - Per-chain sync state; back-fill "Optimizing Vault... [%]" when cache empty (RPC path).
 * - WASM matching offloaded with requestIdleCallback; call markSyncComplete when done (indexer path).
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Connection, PublicKey } from "@solana/web3.js";
import type { SolanaCluster } from "../lib/chain";
import {
  getAnnouncementsForCluster,
  getSyncState,
  setSyncState,
  clearSyncState,
  putAnnouncements,
  clearClusterCache,
  type CachedAnnouncement,
} from "../lib/opaqueCache";
import {
  getUserFacingSyncMessage,
  logSyncError,
} from "../lib/syncErrorUtils";
import { getStoredGhostEntries } from "../store/ghostAddressStore";

type PublicClient = Connection;

export type ScanProgress = {
  phase: "idle" | "loading-cache" | "indexer-fetch" | "indexer-fetched" | "syncing" | "backfilling" | "matching" | "done" | "error";
  /** 0–100 for backfilling/syncing */
  percent: number;
  message: string;
  fromBlock: bigint;
  toBlock: bigint;
  currentBlock: bigint;
  error: string | null;
};

export type UseScannerOptions = {
  cluster: SolanaCluster | null;
  publicClient: PublicClient | null;
  announcerAddress: string | null;
  enabled: boolean;
  ghostAddresses?: string[];
  watchlistAddresses?: string[];
};

export type WatchlistBalances = {
  eth: Record<string, bigint>;
  tokens: Record<string, Record<string, bigint>>;
};

export type UseScannerResult = {
  /** All cached + newly synced announcements for the chain (raw, not yet matched with WASM) */
  announcements: CachedAnnouncement[];
  progress: ScanProgress;
  /** Native balance per ghost/watchlist address (manual scan). Use for displaying/claiming manual receives. */
  ghostBalances: Record<string, bigint>;
  /** Token balances per address (reserved for future use). */
  ghostTokenBalances: Record<string, Record<string, bigint>>;
  /** Whether we are in "back-fill" (cache was empty, scanning from START_BLOCK) */
  isBackfilling: boolean;
  /** Trigger a full rescan from deployment block (clears cache for this chain) */
  retrySync: () => Promise<void>;
  /** Re-run scan from lastScannedSlot+1 to latest (incremental) */
  refresh: () => Promise<void>;
  /** Call when WASM matching has finished (e.g. after indexer path) so progress can move to "done" */
  markSyncComplete: () => void;
};

function getStartBlock(_cluster: SolanaCluster): bigint {
  return 0n;
}

function getSubgraphUrl(_cluster: SolanaCluster): string | null {
  return null;
}

/** Subgraph / indexer path disabled for Solana build (no Apollo client). */
async function fetchFromSubgraph(
  _subgraphUrl: string,
  _cluster: SolanaCluster
): Promise<CachedAnnouncement[] | null> {
  return null;
}

async function fetchLogsAdaptive(
  publicClient: PublicClient,
  announcerAddress: string,
  fromBlock: bigint,
  toBlock: bigint,
  _cluster: SolanaCluster,
  onChunk: (from: bigint, to: bigint, logs: unknown[]) => Promise<void>
): Promise<void> {
  const programId = new PublicKey(announcerAddress);
  const signatures = await publicClient.getSignaturesForAddress(programId, { limit: 1000 }, "confirmed");
  const inRange = signatures
    .filter((s) => BigInt(s.slot) >= fromBlock && BigInt(s.slot) <= toBlock)
    .sort((a, b) => a.slot - b.slot);

  const batchSize = 100;
  for (let i = 0; i < inRange.length; i += batchSize) {
    const batch = inRange.slice(i, i + batchSize);
    const logsOut: Array<{
      transactionSignature: string;
      logIndex: number;
      slot: number;
      args: { stealthAddress?: string; ephemeralPubKey?: string; metadata?: string };
    }> = [];

    for (const sig of batch) {
      const tx = await publicClient.getTransaction(sig.signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      const logMessages = tx?.meta?.logMessages ?? [];
      let localLogIndex = 0;
      for (const log of logMessages) {
        if (!log.startsWith("Program data: ")) continue;
        try {
          const b64Data = log.slice("Program data: ".length);
          const eventData = Buffer.from(b64Data, "base64");
          if (eventData.length < 8) continue;
          let offset = 8;
          const schemeId = eventData.readBigUInt64LE(offset);
          offset += 8;
          if (schemeId !== 1n) continue;

          const stealthAddrLen = eventData.readUInt32LE(offset);
          offset += 4;
          const stealthAddrBytes = eventData.slice(offset, offset + stealthAddrLen);
          offset += stealthAddrLen;

          // caller pubkey
          offset += 32;

          const ephKeyLen = eventData.readUInt32LE(offset);
          offset += 4;
          const ephKeyBytes = eventData.slice(offset, offset + ephKeyLen);
          offset += ephKeyLen;

          const metaLen = eventData.readUInt32LE(offset);
          offset += 4;
          const metadataBytes = eventData.slice(offset, offset + metaLen);

          logsOut.push({
            transactionSignature: sig.signature,
            logIndex: localLogIndex++,
            slot: sig.slot,
            args: {
              stealthAddress: `0x${Buffer.from(stealthAddrBytes).toString("hex")}`,
              ephemeralPubKey: `0x${Buffer.from(ephKeyBytes).toString("hex")}`,
              metadata: `0x${Buffer.from(metadataBytes).toString("hex")}`,
            },
          });
        } catch {
          // ignore malformed event rows
        }
      }
    }

    const endSlot = batch.length > 0 ? BigInt(batch[batch.length - 1].slot) : fromBlock;
    await onChunk(fromBlock, endSlot, logsOut);
  }
}

async function checkWatchlistBalances(
  connection: Connection,
  watchlist: string[],
): Promise<WatchlistBalances> {
  const eth: Record<string, bigint> = {};
  const tokensOut: Record<string, Record<string, bigint>> = {};
  for (const addr of watchlist) {
    tokensOut[addr] = {};
    try {
      const pk = new PublicKey(addr);
      eth[addr] = BigInt(await connection.getBalance(pk));
    } catch {
      eth[addr] = 0n;
    }
  }
  return { eth, tokens: tokensOut };
}

/**
 * Process items in batches during idle time to avoid blocking the UI (e.g. WASM matching).
 * Export for use in PrivateBalanceView when matching many cached announcements.
 */
export function processInIdleBatches<T, R>(
  items: T[],
  batchSize: number,
  process: (batch: T[]) => R | Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  let offset = 0;

  return new Promise((resolve, reject) => {
    function runBatch() {
      if (offset >= items.length) {
        resolve(results);
        return;
      }
      const batch = items.slice(offset, offset + batchSize);
      offset += batchSize;
      Promise.resolve(process(batch))
        .then((r) => {
          results.push(r);
          if (typeof requestIdleCallback !== "undefined") {
            requestIdleCallback(runBatch, { timeout: 100 });
          } else {
            setTimeout(runBatch, 0);
          }
        })
        .catch(reject);
    }
    if (typeof requestIdleCallback !== "undefined") {
      requestIdleCallback(runBatch, { timeout: 100 });
    } else {
      setTimeout(runBatch, 0);
    }
  });
}

export function useScanner(opts: UseScannerOptions): UseScannerResult {
  const { cluster, publicClient, announcerAddress, enabled, ghostAddresses = [], watchlistAddresses = [] } = opts;
  const [announcements, setAnnouncements] = useState<CachedAnnouncement[]>([]);
  const [ghostBalances, setGhostBalances] = useState<Record<string, bigint>>({});
  const [ghostTokenBalances, setGhostTokenBalances] = useState<Record<string, Record<string, bigint>>>({});
  const [progress, setProgress] = useState<ScanProgress>({
    phase: "idle",
    percent: 0,
    message: "",
    fromBlock: 0n,
    toBlock: 0n,
    currentBlock: 0n,
    error: null,
  });
  const [isBackfilling, setIsBackfilling] = useState(false);
  const refreshKeyRef = useRef(0);

  const runChunkedRpcSync = useCallback(
    async (
      publicClient: NonNullable<typeof opts.publicClient>,
      announcerAddress: string,
      fromBlock: bigint,
      toBlock: bigint,
      cacheEmpty: boolean,
      startBlock: bigint
    ) => {
      await fetchLogsAdaptive(
        publicClient,
        announcerAddress,
        fromBlock,
        toBlock,
        cluster!,
        async (_from, end, logs) => {
          await putAnnouncements(cluster!, logs as Parameters<typeof putAnnouncements>[1]);
          await setSyncState(cluster!, Number(end));
          const totalBlocks = Number(toBlock - (cacheEmpty ? startBlock : fromBlock) + 1n);
          const doneBlocks = Number(end - (cacheEmpty ? startBlock : fromBlock) + 1n);
          const percent = totalBlocks > 0 ? Math.min(100, Math.round((doneBlocks / totalBlocks) * 100)) : 100;
          setProgress((p) => ({
            ...p,
            phase: cacheEmpty ? "backfilling" : "syncing",
            percent,
            message: cacheEmpty ? `Optimizing Vault… [${percent}%]` : `Syncing… ${percent}%`,
            currentBlock: end,
          }));
        }
      );
    },
    [cluster]
  );

  const runScan = useCallback(
    async (clearCache: boolean) => {
      console.log("runScan", cluster);
      console.log("publicClient", publicClient);
      console.log("announcerAddress", announcerAddress);
      console.log("enabled", enabled);
      if (cluster == null || !publicClient || !announcerAddress || !enabled) return;


      const startBlock = getStartBlock(cluster);
      const subgraphUrl = getSubgraphUrl(cluster);

      if (clearCache) {
        await clearClusterCache(cluster);
        setAnnouncements([]);
      }

      setProgress((p) => ({ ...p, phase: "loading-cache", message: "Loading cache…", error: null }));

      const cached = await getAnnouncementsForCluster(cluster);
      const sync = await getSyncState(cluster);
      const lastScanned = sync?.lastScannedSlot ?? null;
      const toBlock = BigInt(await publicClient.getSlot());
      const fromBlock =
        clearCache || lastScanned == null
          ? startBlock
          : BigInt(Math.max(lastScanned + 1, Number(startBlock)));
      const cacheEmpty = cached.length === 0 && lastScanned == null;

      if (subgraphUrl) {
        setProgress((p) => ({
          ...p,
          phase: "indexer-fetch",
          message: "Syncing with Indexer…",
          error: null,
        }));
        try {
          const list = await fetchFromSubgraph(subgraphUrl, cluster);
          if (list != null && list.length >= 0) {
            await clearClusterCache(cluster);
            await putAnnouncements(cluster, list.map((a) => ({
              transactionSignature: a.transactionSignature,
              logIndex: a.logIndex,
              slot: a.slot,
              args: a.args,
            })));
            const maxSlot = list.length > 0 ? Math.max(...list.map((a) => a.slot)) : 0;
            await setSyncState(cluster, maxSlot);
            // Pass announcements directly so WASM scanning loop runs immediately (no cache read).
            setAnnouncements(list);
            setProgress({
              phase: "indexer-fetched",
              percent: 100,
              message: "Scanning Vault…",
              fromBlock: startBlock,
              toBlock,
              currentBlock: toBlock,
              error: null,
            });
            setIsBackfilling(false);
            return;
          }
        } catch {
          // Fall through to chunked RPC fallback (safe mode)
        }
      }

      if (cacheEmpty && !clearCache) {
        setIsBackfilling(true);
        setProgress({
          phase: "backfilling",
          percent: 0,
          message: "Optimizing Vault… [0%]",
          fromBlock: startBlock,
          toBlock,
          currentBlock: startBlock,
          error: null,
        });
      } else {
        setAnnouncements(cached);
        if (fromBlock > toBlock) {
          setProgress({
            phase: "done",
            percent: 100,
            message: "Up to date",
            fromBlock,
            toBlock,
            currentBlock: toBlock,
            error: null,
          });
          setIsBackfilling(false);
          return;
        }
        setProgress((p) => ({
          ...p,
          phase: "syncing",
          percent: 0,
          message: "Syncing new blocks…",
          fromBlock,
          toBlock,
          currentBlock: fromBlock,
        }));
      }

      try {
        await runChunkedRpcSync(publicClient, announcerAddress, fromBlock, toBlock, cacheEmpty, startBlock);
        const updated = await getAnnouncementsForCluster(cluster);
        setAnnouncements(updated);
        setProgress({
          phase: "done",
          percent: 100,
          message: "Up to date",
          fromBlock,
          toBlock,
          currentBlock: toBlock,
          error: null,
        });
        setIsBackfilling(false);
      } catch (err) {
        const msg = getUserFacingSyncMessage(err);
        logSyncError(err, "Sync failed");
        setProgress((p) => ({
          ...p,
          phase: "error",
          error: msg,
          message: "Sync failed",
        }));
        setIsBackfilling(false);
      }
    },
    [cluster, publicClient, announcerAddress, enabled, runChunkedRpcSync]
  );

  useEffect(() => {
    if (!enabled || cluster == null || !publicClient || !announcerAddress) {
      console.log("[useScanner] effect skip (guard):", {
        cluster,
        enabled,
        hasPublicClient: !!publicClient,
        hasAnnouncerAddress: !!announcerAddress,
      });
      setProgress((p) => ({ ...p, phase: "idle" }));
      return;
    }

    // Resolve subgraph URL for the current supported chain
    // getSubgraphUrl(cluster);

    let cancelled = false;
    setProgress((p) => ({ ...p, phase: "loading-cache", message: "Loading cache…" }));

    (async () => {
      const cached = await getAnnouncementsForCluster(cluster);
      if (cancelled) return;
      setAnnouncements(cached);

      const sync = await getSyncState(cluster);
      const toBlock = BigInt(await publicClient.getSlot());
      const startBlock = getStartBlock(cluster);
      const lastScanned = sync?.lastScannedSlot ?? null;
      const fromBlock =
        lastScanned == null ? startBlock : BigInt(Math.max(lastScanned + 1, Number(startBlock)));

      if (fromBlock > toBlock) {
        // lastScannedSlot is ahead of chain head (corrupt or from wrong source); reset sync state and run scan from startBlock
        console.warn("[useScanner] lastScannedSlot ahead of chain head, resetting sync state:", {
          cluster,
          fromBlock: String(fromBlock),
          toBlock: String(toBlock),
        });
        await clearSyncState(cluster);
      }

      await runScan(false);
    })();

    return () => {
      cancelled = true;
    };
  }, [cluster, enabled, publicClient, announcerAddress]);

  const retrySync = useCallback(async () => {
    if (cluster == null) return;
    refreshKeyRef.current += 1;
    await runScan(true);
  }, [cluster, runScan]);

  const refresh = useCallback(async () => {
    await runScan(false);
  }, [runScan]);

  const markSyncComplete = useCallback(() => {
    setProgress((p) => {
      if (p.phase !== "indexer-fetched") return p;
      return { ...p, phase: "done", message: "Up to date" };
    });
  }, []);

  // State-polling: check watchlist + ghost addresses + opaque-ghost-addresses (current chain only)
  useEffect(() => {
    if (!publicClient || cluster == null) {
      setGhostBalances({});
      setGhostTokenBalances({});
      return;
    }
    // Only use stored entries for current chain
    const stored = getStoredGhostEntries().filter((e) => e.cluster === cluster);
    const storedAddresses = stored.map((e) => e.stealthAddress);
    const combined: string[] = [...watchlistAddresses, ...ghostAddresses, ...storedAddresses];
    const seen = new Set<string>();
    const addressesToPoll = combined.filter((addr) => {
      if (seen.has(addr)) return false;
      seen.add(addr);
      return true;
    });
    if (addressesToPoll.length === 0) {
      setGhostBalances({});
      setGhostTokenBalances({});
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        if (watchlistAddresses.length > 0 && cluster != null) {
          const { eth, tokens } = await checkWatchlistBalances(
            publicClient,
            addressesToPoll,
          );
          if (cancelled) return;
          setGhostBalances(eth);
          setGhostTokenBalances(tokens);
        } else {
          const conn = publicClient as Connection;
          const results = await Promise.all(
            addressesToPoll.map(async (addr) => {
              try {
                return BigInt(await conn.getBalance(new PublicKey(addr)));
              } catch {
                return 0n;
              }
            })
          );
          if (cancelled) return;
          const next: Record<string, bigint> = {};
          addressesToPoll.forEach((addr, i) => {
            next[addr] = results[i] ?? 0n;
          });
          setGhostBalances(next);
          setGhostTokenBalances({});
        }
      } catch {
        if (!cancelled) {
          setGhostBalances({});
          setGhostTokenBalances({});
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [publicClient, cluster, ghostAddresses.join(","), watchlistAddresses.join(",")]);

  return {
    announcements,
    progress,
    ghostBalances,
    ghostTokenBalances,
    isBackfilling,
    retrySync,
    refresh,
    markSyncComplete,
  };
}
