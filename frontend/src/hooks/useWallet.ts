import { useCallback, useLayoutEffect, useMemo, useRef } from "react";
import { flushSync } from "react-dom";
import { useWallet as useSolanaWallet, useConnection } from "@solana/wallet-adapter-react";
import { WalletReadyState } from "@solana/wallet-adapter-base";
import { PublicKey } from "@solana/web3.js";
import { getCluster } from "../lib/chain";

function pickDefaultWallet<T extends { readyState: WalletReadyState }>(wallets: T[]): T | undefined {
  if (wallets.length === 0) return undefined;
  const installed = wallets.find((w) => w.readyState === WalletReadyState.Installed);
  if (installed) return installed;
  const loadable = wallets.find((w) => w.readyState === WalletReadyState.Loadable);
  if (loadable) return loadable;
  return wallets[0];
}

type WalletState = {
  isConnected: boolean;
  address: string | null;
  publicKey: PublicKey | null;
  cluster: string | null;
  isConnecting: boolean;
  error: string | null;
};

export function useWallet() {
  const {
    publicKey,
    connected,
    connecting,
    disconnect: solanaDisconnect,
    select,
    wallets,
    connect: solanaConnect,
    wallet,
    signMessage,
    sendTransaction,
  } = useSolanaWallet();
  const { connection } = useConnection();

  const connectRef = useRef(solanaConnect);
  const publicKeyRef = useRef(publicKey);
  const signMessageRef = useRef(signMessage);

  useLayoutEffect(() => {
    connectRef.current = solanaConnect;
    publicKeyRef.current = publicKey;
    signMessageRef.current = signMessage;
  }, [solanaConnect, publicKey, signMessage]);

  const cluster = getCluster();

  const state: WalletState = useMemo(
    () => ({
      isConnected: connected,
      address: publicKey?.toBase58() ?? null,
      publicKey: publicKey ?? null,
      cluster,
      isConnecting: connecting,
      error: null,
    }),
    [connected, publicKey, cluster, connecting]
  );

  const connect = useCallback(async () => {
    if (wallets.length === 0) {
      console.warn("[useWallet] No wallets available. Please install Phantom or Solflare.");
      return;
    }
    if (!wallet) {
      const pick = pickDefaultWallet(wallets);
      if (!pick) return;
      // `select` updates React state; without a sync flush, `connect` still sees the old
      // null wallet in WalletProviderBase and throws WalletNotSelectedError before Phantom opens.
      flushSync(() => {
        select(pick.adapter.name);
      });
    }
    try {
      await connectRef.current();
    } catch (error) {
      console.error("[useWallet] Connect failed:", error);
      throw error;
    }
  }, [wallets, wallet, select]);

  const disconnect = useCallback(() => {
    solanaDisconnect();
  }, [solanaDisconnect]);

  return {
    ...state,
    /** Alias for `isConnected` (matches `@solana/wallet-adapter-react`). */
    connected,
    connect,
    disconnect,
    connection,
    signMessage,
    sendTransaction,
    wallets,
    wallet,
    select,
    /** Alias for `isConnecting` — matches `@solana/wallet-adapter-react` naming */
    connecting,
    /** Latest values for async flows (e.g. after `await connect()` closures are stale) */
    publicKeyRef,
    signMessageRef,
  };
}
