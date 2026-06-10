/**
 * Session store for the `@opaquecash/opaque` SDK. Holds the single `OpaqueClient` instance and
 * the derived meta-address. Replaces `KeysContext`'s in-memory master-key storage — the client
 * owns the viewing/spending keys internally; components read `client.getMetaAddressHex()` (mirrored
 * here as `metaAddress`) instead of raw keys.
 */

import { create } from "zustand";
import type { OpaqueClient } from "@opaquecash/opaque";
import type { Hex } from "viem";

interface OpaqueSessionState {
  client: OpaqueClient | null;
  metaAddress: Hex | null;
  /** Transient status text for the connect flow (signing, deriving, …). */
  status: string | null;
  setSession: (client: OpaqueClient, metaAddress: Hex) => void;
  clearSession: () => void;
  setStatus: (status: string | null) => void;
}

export const useOpaqueStore = create<OpaqueSessionState>((set) => ({
  client: null,
  metaAddress: null,
  status: null,
  setSession: (client, metaAddress) => set({ client, metaAddress, status: null }),
  clearSession: () => set({ client: null, metaAddress: null, status: null }),
  setStatus: (status) => set({ status }),
}));
