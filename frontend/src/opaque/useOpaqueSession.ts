/**
 * The single bridge between the wallet layer and the protocol. Builds one `OpaqueClient` from the
 * user's Solana-wallet signature over the canonical `SETUP_MESSAGE` (HKDF entropy for their keys)
 * and stores it. All protocol behaviour comes from `@opaquecash/opaque`.
 *
 * Solana-primary: the meta-address is derived from the Solana signature (matching the legacy
 * `KeysContext` flow byte-for-byte, so existing identities are preserved). An Ethereum wallet is
 * optional — when connected it is threaded in as the EVM write signer for multichain features.
 * The 30-minute encrypted signature cache (`lib/signatureSession`) is reused so users don't re-sign.
 */

import { useCallback } from "react";
import { useConnection, useWallet as useSolanaWallet } from "@solana/wallet-adapter-react";
import { useAccount, useWalletClient } from "wagmi";
import { OpaqueClient, SETUP_MESSAGE } from "@opaquecash/opaque";
import type { Address, Hex } from "viem";
import { useOpaqueStore } from "./store";
import {
  clearSignatureSession,
  getRememberSignaturePreference,
  loadSignatureSession,
  saveSignatureSession,
} from "../lib/signatureSession";
import {
  PLACEHOLDER_EVM_ADDRESS,
  SEPOLIA_CHAIN_ID,
  SEPOLIA_RPC_URL,
  SOLANA_CLUSTER,
  SOLANA_RPC_URL,
  WASM_MODULE_SPECIFIER,
} from "./config";

function sigBytesToHex(sigBytes: Uint8Array): Hex {
  return `0x${Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

export function useOpaqueSession() {
  const { connection } = useConnection();
  const { publicKey, signMessage, signTransaction } = useSolanaWallet();
  // Optional EVM signer for multichain (PSR/register/send/UAB on Ethereum).
  const { address: ethereumAddress } = useAccount();
  const { data: walletClient } = useWalletClient();

  const client = useOpaqueStore((s) => s.client);
  const metaAddress = useOpaqueStore((s) => s.metaAddress);
  const status = useOpaqueStore((s) => s.status);
  const setSession = useOpaqueStore((s) => s.setSession);
  const clearSession = useOpaqueStore((s) => s.clearSession);
  const setStatus = useOpaqueStore((s) => s.setStatus);

  const connect = useCallback(
    async (opts?: { remember?: boolean }): Promise<OpaqueClient> => {
      if (!publicKey || !signMessage || !signTransaction) {
        throw new Error("Connect a Solana wallet (Phantom / Solflare) first.");
      }
      const address = publicKey.toBase58();
      setStatus("Restoring session…");
      let sigHex = await loadSignatureSession({
        address,
        cluster: SOLANA_CLUSTER,
        message: SETUP_MESSAGE,
      });
      if (!sigHex) {
        setStatus("Requesting signature over SETUP_MESSAGE…");
        const sigBytes = await signMessage(new TextEncoder().encode(SETUP_MESSAGE));
        sigHex = sigBytesToHex(sigBytes);
        await saveSignatureSession({
          signatureHex: sigHex,
          address,
          cluster: SOLANA_CLUSTER,
          message: SETUP_MESSAGE,
          remember: opts?.remember ?? getRememberSignaturePreference(),
        });
      }
      setStatus("Deriving stealth keys + loading scanner…");
      // The app and the file:-linked SDK resolve separate copies of viem, so the structurally
      // identical WalletClient types are nominally distinct; cast across this one boundary.
      const ethereumWalletClient = (walletClient ?? undefined) as unknown as Parameters<
        typeof OpaqueClient.create
      >[0]["ethereumWalletClient"];
      const c = await OpaqueClient.create({
        chainId: SEPOLIA_CHAIN_ID,
        rpcUrl: SEPOLIA_RPC_URL,
        walletSignature: sigHex,
        ethereumAddress: (ethereumAddress ?? PLACEHOLDER_EVM_ADDRESS) as Address,
        wasmModuleSpecifier: WASM_MODULE_SPECIFIER,
        solana: { cluster: SOLANA_CLUSTER, rpcUrl: SOLANA_RPC_URL, connection },
        ethereumWalletClient,
        solanaWallet: { publicKey, signTransaction: (tx) => signTransaction(tx) },
      });
      setSession(c, c.getMetaAddressHex());
      setStatus(null);
      return c;
    },
    [
      publicKey,
      signMessage,
      signTransaction,
      walletClient,
      ethereumAddress,
      connection,
      setSession,
      setStatus,
    ],
  );

  const disconnect = useCallback(() => {
    clearSignatureSession();
    clearSession();
  }, [clearSession]);

  return {
    client,
    metaAddress,
    status,
    isSetup: client != null,
    solanaAddress: publicKey?.toBase58() ?? null,
    ethereumAddress: ethereumAddress ?? null,
    connect,
    disconnect,
  };
}
