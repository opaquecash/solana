/**
 * Opaque Protocol: Stealth fund discovery and spending lifecycle (Solana).
 * - StealthScanner: historical sync + real-time log listener + WASM filter
 * - VaultStore: persistent owned stealth addresses
 * - Withdrawal via Solana transactions
 *
 * Security: Master private keys must be passed in at runtime; never stored in localStorage.
 */

import {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { useVaultStore } from "../store/vaultStore";
import { useGhostAddressStore, type GhostEntry } from "../store/ghostAddressStore";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  buildGhostAnnouncementPayload,
  deriveAnnouncerEphemeralKey,
  deriveStealthSolanaKeypairFromStealthPrivKey,
  formatSol,
  type Hex,
  bytesToHex,
  hexToBytes,
} from "./stealth";
import { ANNOUNCER_PROGRAM_ID, SCHEME_ID_SECP256K1, buildAnnounceInstruction } from "./contracts";

// -----------------------------------------------------------------------------
// WASM module type
// -----------------------------------------------------------------------------

export interface StealthLifecycleWasm {
  check_announcement_view_tag_wasm: (
    view_tag: number,
    view_privkey_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ) => string;
  check_announcement_wasm: (
    announcement_stealth_address: string,
    view_tag: number,
    view_privkey_bytes: Uint8Array,
    spend_pubkey_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ) => boolean;
  reconstruct_signing_key_wasm: (
    master_spend_priv_bytes: Uint8Array,
    master_view_priv_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ) => Uint8Array;
}

// -----------------------------------------------------------------------------
// Scanning progress
// -----------------------------------------------------------------------------

export type ScanStatus = "idle" | "syncing" | "watching" | "error";

export type ScanningProgress = {
  status: ScanStatus;
  fromSlot: bigint | null;
  toSlot: bigint | null;
  lastProcessedSlot: bigint | null;
  totalSlots: bigint | null;
  error: string | null;
};

type ProgressListener = (progress: ScanningProgress) => void;

// -----------------------------------------------------------------------------
// Keys supplier
// -----------------------------------------------------------------------------

export type MasterKeys = {
  viewPrivKey: Uint8Array;
  spendPrivKey: Uint8Array;
  spendPubKey: Uint8Array;
};

// -----------------------------------------------------------------------------
// StealthScanner (Solana)
// -----------------------------------------------------------------------------

const CHUNK_SIZE = 1000;
const RPC_DELAY_MS = 200;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class StealthScanner {
  private readonly connection: Connection;
  private readonly announcerProgramId: PublicKey;
  private readonly wasm: StealthLifecycleWasm;
  private readonly getKeys: () => MasterKeys;
  private subscriptionId: number | null = null;
  private progress: ScanningProgress = {
    status: "idle",
    fromSlot: null,
    toSlot: null,
    lastProcessedSlot: null,
    totalSlots: null,
    error: null,
  };
  private listeners = new Set<ProgressListener>();

  constructor(opts: {
    connection: Connection;
    announcerProgramId?: PublicKey;
    wasm: StealthLifecycleWasm;
    getKeys: () => MasterKeys;
  }) {
    this.connection = opts.connection;
    this.announcerProgramId = opts.announcerProgramId ?? ANNOUNCER_PROGRAM_ID;
    this.wasm = opts.wasm;
    this.getKeys = opts.getKeys;
    console.log("👁️ [Opaque] StealthScanner created (Solana)", {
      announcer: this.announcerProgramId.toBase58(),
    });
  }

  onProgress(listener: ProgressListener): () => void {
    this.listeners.add(listener);
    listener(this.progress);
    return () => this.listeners.delete(listener);
  }

  private setProgress(update: Partial<ScanningProgress>) {
    this.progress = { ...this.progress, ...update };
    this.listeners.forEach((l) => l(this.progress));
  }

  async updateVault(): Promise<void> {
    this.setProgress({ status: "syncing", error: null });

    const keys = this.getKeys();
    const viewPriv = keys.viewPrivKey;
    const spendPub = keys.spendPubKey;

    try {
      const signatures = await this.connection.getSignaturesForAddress(
        this.announcerProgramId,
        { limit: CHUNK_SIZE },
        "confirmed"
      );

      if (signatures.length > 0) {
        console.log("👁️ [Opaque] Found", signatures.length, "announcer transactions");
      }

      for (const sigInfo of signatures) {
        try {
          const tx = await this.connection.getTransaction(sigInfo.signature, {
            commitment: "confirmed",
            maxSupportedTransactionVersion: 0,
          });
          if (!tx?.meta?.logMessages) continue;

          this.parseAnnouncementLogs(
            tx.meta.logMessages,
            sigInfo.signature,
            BigInt(sigInfo.slot),
            viewPriv,
            spendPub
          );
        } catch {
          // Skip individual tx parse failures
        }
        await delay(RPC_DELAY_MS);
      }

      console.log("👁️ [Opaque] Historical sync done ✅");
      this.setProgress({ status: "watching", error: null });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("⚠️ [Opaque] updateVault error", { error: msg });
      this.setProgress({ status: "error", error: msg });
      throw err;
    }
  }

  startWatching(): void {
    if (this.subscriptionId !== null) {
      console.log("👁️ [Opaque] Already watching, skip");
      return;
    }

    console.log("👁️ [Opaque] Starting onLogs subscription");
    const keys = this.getKeys();
    const viewPriv = keys.viewPrivKey;
    const spendPub = keys.spendPubKey;

    this.subscriptionId = this.connection.onLogs(
      this.announcerProgramId,
      (logInfo) => {
        if (logInfo.err) return;
        this.parseAnnouncementLogs(
          logInfo.logs,
          logInfo.signature,
          0n,
          viewPriv,
          spendPub
        );
      },
      "confirmed"
    );

    this.setProgress({ status: "watching", error: null });
    console.log("👁️ [Opaque] Watching ✅");
  }

  stopWatching(): void {
    if (this.subscriptionId !== null) {
      this.connection.removeOnLogsListener(this.subscriptionId);
      this.subscriptionId = null;
      console.log("👁️ [Opaque] Stopped watching");
    }
    this.setProgress({ status: "idle" });
  }

  private parseAnnouncementLogs(
    logs: string[],
    txSignature: string,
    slot: bigint,
    viewPrivKey: Uint8Array,
    spendPubKey: Uint8Array
  ): void {
    for (const log of logs) {
      if (!log.startsWith("Program data: ")) continue;
      try {
        const b64Data = log.slice("Program data: ".length);
        const eventData = Buffer.from(b64Data, "base64");

        if (eventData.length < 8) continue;

        let offset = 8;

        // scheme_id (u64)
        const schemeId = eventData.readBigUInt64LE(offset);
        offset += 8;
        if (schemeId !== SCHEME_ID_SECP256K1) continue;

        // stealth_address (vec<u8>)
        const stealthAddrLen = eventData.readUInt32LE(offset);
        offset += 4;
        const stealthAddrBytes = eventData.slice(offset, offset + stealthAddrLen);
        offset += stealthAddrLen;

        // caller (pubkey, 32 bytes)
        offset += 32;

        // ephemeral_pub_key (vec<u8>)
        const ephKeyLen = eventData.readUInt32LE(offset);
        offset += 4;
        const ephemeralPubKey = eventData.slice(offset, offset + ephKeyLen);
        offset += ephKeyLen;

        // metadata (vec<u8>)
        const metaLen = eventData.readUInt32LE(offset);
        offset += 4;
        const metadata = eventData.slice(offset, offset + metaLen);

        if (ephemeralPubKey.length !== 33) continue;

        const viewTag = metadata.length > 0 ? metadata[0] : 0;
        const stealthAddress = "0x" + bytesToHex(stealthAddrBytes);

        const viewTagResult = this.wasm.check_announcement_view_tag_wasm(
          viewTag,
          viewPrivKey,
          new Uint8Array(ephemeralPubKey)
        );
        if (viewTagResult === "NoMatch") continue;

        const isOurs = this.wasm.check_announcement_wasm(
          stealthAddress,
          viewTag,
          viewPrivKey,
          spendPubKey,
          new Uint8Array(ephemeralPubKey)
        );
        if (!isOurs) continue;

        console.log("📥 [Opaque] Announcement is ours, upserting vault entry", {
          stealthAddress: stealthAddress.slice(0, 14) + "…",
          slot: slot.toString(),
          tx: txSignature.slice(0, 18) + "…",
        });

        useVaultStore.getState().upsertEntry({
          stealthAddress,
          ephemeralPubKeyHex: ("0x" + bytesToHex(new Uint8Array(ephemeralPubKey))) as Hex,
          blockNumber: slot,
          txHash: txSignature,
          amountWei: 0n,
          isSpent: false,
        });
      } catch {
        // Skip malformed log entries
      }
    }
  }
}

// -----------------------------------------------------------------------------
// refreshBalances: get SOL balance for all vault addresses
// -----------------------------------------------------------------------------

export async function refreshBalances(_connection: Connection): Promise<void> {
  const entries = useVaultStore.getState().entries;
  if (entries.length === 0) {
    console.log("💰 [Opaque] refreshBalances: no entries, skip");
    return;
  }
  console.log("💰 [Opaque] refreshBalances", { count: entries.length });
  console.log("💰 [Opaque] Balance refresh for Solana stealth addresses (secp256k1-derived)");
}

// -----------------------------------------------------------------------------
// Withdrawal helpers
// -----------------------------------------------------------------------------

export type WithdrawalStepTag = "CALC" | "SIGN" | "SEND" | "DONE";

export type WithdrawalStatus = {
  tag: WithdrawalStepTag;
  label: string;
  detail?: string;
};

export type WithdrawalStatusCallback = (status: WithdrawalStatus) => void;

/**
 * Derive the one-time stealth private key for a ghost entry.
 */
export function deriveStealthPrivateKeyFromGhostEntry(
  ghostEntry: GhostEntry,
  masterKeys: MasterKeys,
  wasm: StealthLifecycleWasm
): Hex {
  if (!ghostEntry.ephemeralPrivKeyHex) {
    throw new Error("Ghost entry has no ephemeral private key.");
  }
  const ephemeralPrivBytes = hexToBytes(ghostEntry.ephemeralPrivKeyHex);
  if (ephemeralPrivBytes.length !== 32) {
    throw new Error("Invalid ephemeral private key length.");
  }
  const ephemeralPubKey = secp256k1.getPublicKey(ephemeralPrivBytes, true);
  const stealthPrivKeyBytes = wasm.reconstruct_signing_key_wasm(
    masterKeys.spendPrivKey,
    masterKeys.viewPrivKey,
    ephemeralPubKey
  );
  const hexKey =
    "0x" +
    Array.from(stealthPrivKeyBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return hexKey as Hex;
}

/**
 * Deterministic "Announcer" stealth account.
 */
export function getAnnouncerAccount(
  wasm: StealthLifecycleWasm,
  masterKeys: MasterKeys,
  metaAddressHex: Hex | string
): { address: string; privateKey: Hex } {
  const ephemeralPriv = deriveAnnouncerEphemeralKey(metaAddressHex);
  const ephemeralPubKey = secp256k1.getPublicKey(ephemeralPriv, true);
  const announcerPrivKeyBytes = wasm.reconstruct_signing_key_wasm(
    masterKeys.spendPrivKey,
    masterKeys.viewPrivKey,
    ephemeralPubKey
  );
  const hexKey =
    ("0x" +
      Array.from(announcerPrivKeyBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")) as Hex;
  const keypair = Keypair.fromSeed(announcerPrivKeyBytes);
  return { address: keypair.publicKey.toBase58(), privateKey: hexKey };
}

export type GhostAnnouncementProgress = {
  id: string;
  label: string;
  status: "wait" | "ok" | "done" | "error";
  detail?: string;
};

/**
 * Publish a retroactive announcement for a manual ghost receive on Solana.
 */
export async function executeGhostOnchainAnnouncement(
  connection: Connection,
  wasm: StealthLifecycleWasm,
  getMasterKeys: () => MasterKeys,
  metaAddressHex: Hex | string,
  ghostStealthAddress: string,
  ephemeralPrivKeyHex: Hex | string,
  onProgress?: (e: GhostAnnouncementProgress) => void,
): Promise<{ announceSignature: string }> {
  const report = (id: string, label: string, status: GhostAnnouncementProgress["status"], detail?: string) => {
    onProgress?.({ id, label, status, detail });
  };

  report("verify", "Verifying ghost address and ephemeral key…", "wait");
  const payload = buildGhostAnnouncementPayload(metaAddressHex, ephemeralPrivKeyHex);
  report("verify", "Ghost address matches stored ephemeral key.", "ok");

  const masterKeys = getMasterKeys();
  const announcerAcc = getAnnouncerAccount(wasm, masterKeys, metaAddressHex);
  const announcerKeypair = Keypair.fromSeed(
    hexToBytes(announcerAcc.privateKey.slice(2))
  );

  report("announcer", "Announcer signer ready.", "ok", announcerAcc.address);

  const stealthAddrBytes = hexToBytes(
    ghostStealthAddress.startsWith("0x") ? ghostStealthAddress.slice(2) : ghostStealthAddress
  );

  const instruction = buildAnnounceInstruction(
    announcerKeypair.publicKey,
    SCHEME_ID_SECP256K1,
    stealthAddrBytes,
    payload.ephemeralPubKey,
    payload.metadata,
  );

  report("announce", "Publishing on-chain announcement…", "wait");

  const transaction = new Transaction().add(instruction);
  const announceSignature = await sendAndConfirmTransaction(
    connection,
    transaction,
    [announcerKeypair],
    { commitment: "confirmed" }
  );

  report("announce", "Announcement published — scanners can index this payment.", "done", announceSignature);

  return { announceSignature };
}

type NativeOrToken =
  | { type: "native" }
  | { type: "token"; tokenAddress: string };

export async function withdrawFromGhostAddress(
  ghostAddress: string,
  cluster: string,
  destination: string,
  asset: NativeOrToken,
  connection: Connection,
  getMasterKeys: () => MasterKeys,
  wasm: StealthLifecycleWasm,
  onStatus: WithdrawalStatusCallback,
): Promise<string> {
  if (asset.type !== "native") {
    throw new Error("Only native SOL ghost withdrawals are currently supported.");
  }

  const ghostEntry = useGhostAddressStore
    .getState()
    .entries.find(
      (e) =>
        e.cluster === cluster &&
        e.stealthAddress.toLowerCase() === ghostAddress.toLowerCase()
    );

  if (!ghostEntry) {
    throw new Error("Ghost address not found in local store.");
  }
  if (!ghostEntry.ephemeralPrivKeyHex) {
    throw new Error("Ghost address is missing its ephemeral key and cannot be withdrawn.");
  }

  onStatus({ tag: "CALC", label: "Reconstructing stealth key", detail: "Using stored ghost ephemeral key…" });
  const stealthPrivKeyHex = deriveStealthPrivateKeyFromGhostEntry(
    ghostEntry,
    getMasterKeys(),
    wasm
  );

  return executeStealthWithdrawal(
    stealthPrivKeyHex,
    destination,
    connection,
    onStatus
  );
}

export async function executeStealthWithdrawal(
  stealthPrivKeyHex: string,
  destination: string,
  connection: Connection,
  onStatus: WithdrawalStatusCallback,
): Promise<string> {
  const stealthPrivHex = stealthPrivKeyHex.startsWith("0x")
    ? stealthPrivKeyHex.slice(2)
    : stealthPrivKeyHex;
  const stealthPrivBytes = hexToBytes(stealthPrivHex);
  if (stealthPrivBytes.length !== 32) {
    throw new Error("Invalid stealth private key length (expected 32 bytes).");
  }

  let destinationPubkey: PublicKey;
  try {
    destinationPubkey = new PublicKey(destination.trim());
  } catch {
    throw new Error("Invalid destination Solana address.");
  }

  const stealthKeypair = deriveStealthSolanaKeypairFromStealthPrivKey(stealthPrivBytes);
  const fromPubkey = stealthKeypair.publicKey;

  onStatus({
    tag: "CALC",
    label: "Estimating network fee",
    detail: `Checking balance for ${fromPubkey.toBase58().slice(0, 8)}…`,
  });

  const balanceLamports = BigInt(await connection.getBalance(fromPubkey, "confirmed"));
  if (balanceLamports <= 0n) {
    throw new Error("Stealth address has zero balance.");
  }

  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");

  // Fee is based on signatures + message size, not transfer amount.
  const feeProbeTx = new Transaction({
    feePayer: fromPubkey,
    recentBlockhash: blockhash,
  }).add(
    SystemProgram.transfer({
      fromPubkey,
      toPubkey: destinationPubkey,
      lamports: 1,
    })
  );
  const feeResult = await connection.getFeeForMessage(feeProbeTx.compileMessage(), "confirmed");
  const feeLamports = BigInt(feeResult.value ?? 5000);

  if (balanceLamports <= feeLamports) {
    throw new Error(
      `Insufficient balance to cover network fee. Balance: ${formatSol(balanceLamports)} SOL, fee: ${formatSol(feeLamports)} SOL`
    );
  }

  const sendLamports = balanceLamports - feeLamports;
  if (sendLamports > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Sweep amount is too large to safely encode in JavaScript number lamports.");
  }
  onStatus({
    tag: "SIGN",
    label: "Signing sweep transaction",
    detail: `Sending ${formatSol(sendLamports)} SOL (fee ${formatSol(feeLamports)} SOL)`,
  });

  const tx = new Transaction({
    feePayer: fromPubkey,
    recentBlockhash: blockhash,
  }).add(
    SystemProgram.transfer({
      fromPubkey,
      toPubkey: destinationPubkey,
      lamports: Number(sendLamports),
    })
  );

  onStatus({ tag: "SEND", label: "Broadcasting sweep transaction" });
  const signature = await sendAndConfirmTransaction(
    connection,
    tx,
    [stealthKeypair],
    { commitment: "confirmed" }
  );

  onStatus({
    tag: "DONE",
    label: "Sweep complete",
    detail: `Sent ${formatSol(sendLamports)} SOL after ${formatSol(feeLamports)} SOL fee.`,
  });

  // Keep TypeScript happy by using lastValidBlockHeight var in meaningful context.
  if (!lastValidBlockHeight) {
    console.warn("⚠️ [Opaque] Missing lastValidBlockHeight from RPC response.");
  }

  return signature;
}

export { formatSol };
