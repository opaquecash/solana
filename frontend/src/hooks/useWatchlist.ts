/**
 * Watchlist — addresses to poll for balances (state-polling fallback).
 * Manual imports and generated ghost addresses are added here so we can detect
 * direct transfers that don't appear in Announcement events.
 * Archived entries stay in the list but are excluded from RPC polling.
 */

import { useMemo } from "react";
import { create } from "zustand";
import { persist } from "zustand/middleware";

type Address = string;

export type WatchlistEntry = {
  cluster: string;
  address: Address;
  /** When true, we stop polling this address to keep RPC calls small. */
  archived: boolean;
  addedAt: number;
};

const STORAGE_KEY = "opaque-watchlist";

type WatchlistState = {
  entries: WatchlistEntry[];
  add: (cluster: string, address: Address) => void;
  archive: (cluster: string, address: string) => void;
  remove: (cluster: string, address: string) => void;
  unarchive: (cluster: string, address: string) => void;
  getActiveAddresses: (cluster: string) => Address[];
  getEntriesForCluster: (cluster: string) => WatchlistEntry[];
};

export const useWatchlistStore = create<WatchlistState>()(
  persist(
    (set, get) => ({
      entries: [],

      add: (cluster, address) =>
        set((state) => {
          const existing = state.entries.find(
            (e) => e.cluster === cluster && e.address === address
          );
          if (existing) {
            return {
              entries: state.entries.map((e) =>
                e === existing ? { ...e, archived: false } : e
              ),
            };
          }
          return {
            entries: [
              ...state.entries,
              { cluster, address, archived: false, addedAt: Date.now() },
            ],
          };
        }),

      archive: (cluster, address) =>
        set((state) => ({
          entries: state.entries.map((e) =>
            e.cluster === cluster && e.address === address
              ? { ...e, archived: true }
              : e
          ),
        })),

      remove: (cluster, address) =>
        set((state) => ({
          entries: state.entries.filter(
            (e) => !(e.cluster === cluster && e.address === address)
          ),
        })),

      unarchive: (cluster, address) =>
        set((state) => ({
          entries: state.entries.map((e) =>
            e.cluster === cluster && e.address === address
              ? { ...e, archived: false }
              : e
          ),
        })),

      getActiveAddresses: (cluster) =>
        get().entries
          .filter((e) => e.cluster === cluster && !e.archived)
          .map((e) => e.address),

      getEntriesForCluster: (cluster) =>
        get().entries.filter((e) => e.cluster === cluster),
    }),
    { name: STORAGE_KEY }
  )
);

/** Hook-friendly: returns active watchlist addresses for the given cluster. */
export function useWatchlist(cluster: string | null): Address[] {
  const entries = useWatchlistStore((state) => state.entries);
  return useMemo(() => {
    if (cluster == null) return [];
    return entries
      .filter((e) => e.cluster === cluster && !e.archived)
      .map((e) => e.address);
  }, [cluster, entries]);
}
