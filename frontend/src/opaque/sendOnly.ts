/**
 * A send-only `OpaqueClient` for flows where the payer has no Opaque identity (the public
 * `/pay/:metaAddress` page). `sendStealthPayment` only uses the recipient's meta-address plus the
 * connected Solana wallet, so the client's own derived keys are irrelevant — we seed them from a
 * fixed placeholder signature and skip the WASM module (send is pure DKSAP + instruction building).
 */

import { OpaqueClient } from "@opaquecash/opaque";
import type { Address } from "viem";
import type { Connection, PublicKey, Transaction } from "@solana/web3.js";
import {
  PLACEHOLDER_EVM_ADDRESS,
  SEPOLIA_CHAIN_ID,
  SEPOLIA_RPC_URL,
  SOLANA_CLUSTER,
  SOLANA_RPC_URL,
} from "./config";

const SEND_ONLY_SIGNATURE = ("0x" + "11".repeat(65)) as Address;

export function createSendOnlyClient(params: {
  connection: Connection;
  solanaWallet: {
    publicKey: PublicKey;
    signTransaction: (tx: Transaction) => Promise<Transaction>;
  };
}): Promise<OpaqueClient> {
  return OpaqueClient.create({
    chainId: SEPOLIA_CHAIN_ID,
    rpcUrl: SEPOLIA_RPC_URL,
    walletSignature: SEND_ONLY_SIGNATURE,
    ethereumAddress: PLACEHOLDER_EVM_ADDRESS as Address,
    solana: { cluster: SOLANA_CLUSTER, rpcUrl: SOLANA_RPC_URL, connection: params.connection },
    solanaWallet: params.solanaWallet,
  });
}
