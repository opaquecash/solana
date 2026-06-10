import { useState, useEffect, useMemo } from "react";
import { Connection, PublicKey } from "@solana/web3.js";
import { useWallet as useSolanaWallet } from "@solana/wallet-adapter-react";
import { formatSol, shortenAddress } from "../lib/format";
import { getRpcUrl, getCluster } from "../lib/chain";
import { getExplorerTxUrl } from "../lib/explorer";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import { getConfigForCluster } from "../contracts/contract-config";
import { ProtocolStepper } from "./ProtocolStepper";
import type { ProtocolStep } from "./ProtocolStepper";
import { useProtocolLog } from "../context/ProtocolLogContext";
import { useTxHistoryStore } from "../store/txHistoryStore";

const parseLamports = (val: string) => BigInt(Math.round(parseFloat(val) * 1e9));
const SOL_FEE_BUFFER = 10_000n;
const isMetaAddress = (value: string): boolean => {
  const normalized = value.startsWith("0x") ? value : `0x${value}`;
  return normalized.length === 2 + 66 * 2 && (normalized.startsWith("0x02") || normalized.startsWith("0x03"));
};

export function SendView() {
  const { client, isSetup, ethereumAddress } = useOpaqueSession();
  const { publicKey } = useSolanaWallet();
  const { push: logPush } = useProtocolLog();
  const pushTx = useTxHistoryStore((s) => s.push);
  const cluster = getCluster();
  const currentConfig = getConfigForCluster(cluster);
  const address = publicKey?.toBase58() ?? null;

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [relayCrossChain, setRelayCrossChain] = useState(false);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [steps, setSteps] = useState<ProtocolStep[]>([]);
  const [activeBalance, setActiveBalance] = useState<bigint | null>(null);
  const [balanceLoading, setBalanceLoading] = useState(false);

  useEffect(() => {
    if (!address) {
      setActiveBalance(null);
      return;
    }
    const connection = new Connection(getRpcUrl(), "confirmed");
    let cancelled = false;
    setBalanceLoading(true);
    (async () => {
      try {
        const owner = new PublicKey(address);
        const lamports = await connection.getBalance(owner);
        if (!cancelled) setActiveBalance(BigInt(lamports));
      } catch {
        if (!cancelled) setActiveBalance(null);
      } finally {
        if (!cancelled) setBalanceLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [address]);

  const maxSendableBalance = useMemo(() => {
    if (activeBalance == null) return null;
    return activeBalance > SOL_FEE_BUFFER ? activeBalance - SOL_FEE_BUFFER : 0n;
  }, [activeBalance]);

  const inputLamports = useMemo(() => {
    const raw = amount.trim();
    if (!raw) return null;
    try {
      return parseLamports(raw);
    } catch {
      return null;
    }
  }, [amount]);

  const isInsufficientBalance = Boolean(
    maxSendableBalance != null &&
      inputLamports != null &&
      inputLamports > 0n &&
      inputLamports > maxSendableBalance
  );

  const formattedMaxBalance =
    maxSendableBalance != null ? formatSol(maxSendableBalance) : null;

  const handleMaxAmount = () => {
    if (maxSendableBalance == null || maxSendableBalance === 0n) return;
    setAmount(formattedMaxBalance ?? "0");
  };

  const handleSend = async () => {
    setError(null);
    setTxHash(null);
    if (!client || !currentConfig || !publicKey) {
      setError("Connect your wallet on a supported cluster.");
      return;
    }
    const recipientMeta = recipient.trim();
    if (!recipientMeta || !amount) {
      setError("Enter recipient and amount.");
      return;
    }
    if (!isMetaAddress(recipientMeta)) {
      setError("Enter a valid stealth meta-address (0x + 132 hex chars).");
      return;
    }

    let value: bigint;
    try {
      value = parseLamports(amount);
    } catch {
      setError("Invalid amount.");
      return;
    }
    if (value === 0n) {
      setError("Amount must be greater than 0.");
      return;
    }

    setSending(true);
    setSteps([]);
    setError(null);

    const addStep = (status: ProtocolStep["status"], label: string, detail?: string) => {
      const id = `step-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setSteps((prev) => prev.concat([{ id, status, label, detail }]));
    };

    try {
      addStep(
        "wait",
        relayCrossChain
          ? "Sending transfer + cross-chain announcement…"
          : "Deriving stealth destination + sending…",
      );
      logPush("blockchain", "Preparing stealth SOL transfer + announce");

      // One call: derive one-time stealth destination, transfer SOL, and announce
      // (announce_with_relay when relaying cross-chain over Wormhole).
      const result = await client.sendStealthPayment({
        chain: "solana",
        recipient: recipientMeta,
        amount: value,
        announce: true,
        relay: relayCrossChain,
      });

      setTxHash(result.txHash);
      const destination = result.destination ?? result.stealthAddress;
      addStep("done", "Transfer confirmed.", result.txHash);
      if (relayCrossChain) {
        addStep("done", "Announcement relayed to Ethereum via Wormhole.");
      }
      logPush("blockchain", `Tx: ${result.txHash.slice(0, 18)}…`);

      pushTx({
        cluster,
        kind: "sent",
        counterparty: shortenAddress(destination),
        amountLamports: value.toString(),
        tokenSymbol: "SOL",
        tokenAddress: null,
        amount: formatSol(value),
        txHash: result.txHash,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Send failed";
      setError(msg);
      setSteps((prev) => {
        if (prev.length === 0) return prev;
        const last = prev[prev.length - 1];
        return prev.slice(0, -1).concat([{ ...last, status: "error" as const, detail: msg }]);
      });
      logPush("ui", `Send failed: ${msg}`);
    } finally {
      setSending(false);
    }
  };

  if (!isSetup) {
    return (
      <div className="card max-w-lg mx-auto text-center text-neutral-500">
        Complete key setup first so you can receive as well.
      </div>
    );
  }

  return (
    <div className="card max-w-lg mx-auto">
      <h2 className="text-lg font-semibold text-white mb-1">Send SOL</h2>
      <p className="text-sm text-neutral-500 mb-6">
        Send SOL to a stealth meta-address. The app derives a one-time stealth Solana destination and publishes an on-chain announcement.
      </p>

      <div className="space-y-4">
        <div>
          <label className="block text-sm text-neutral-500 mb-1.5">Recipient Meta-Address</label>
          <input
            type="text"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            placeholder="0x02… (132 hex chars)"
            className="input-field"
          />
        </div>
        <div>
          <label className="block text-sm text-neutral-500 mb-1.5">Amount (SOL)</label>
          <div className="relative flex rounded-lg shadow-sm">
            <input
              type="text"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0.01"
              className={`input-field flex-1 pr-14 ${isInsufficientBalance ? "border-red-500/50 focus:border-red-500/70 focus:ring-red-500/20" : ""}`}
            />
            <button
              type="button"
              onClick={handleMaxAmount}
              disabled={maxSendableBalance == null || maxSendableBalance === 0n || balanceLoading}
              className="absolute right-2 top-1/2 -translate-y-1/2 py-1 px-2 text-xs font-medium text-neutral-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              MAX
            </button>
          </div>
          {balanceLoading && <p className="mt-1.5 text-neutral-600 text-xs">Loading balance…</p>}
          {isInsufficientBalance && formattedMaxBalance != null && (
            <p className="mt-1.5 text-red-400 text-xs">
              Exceeds available balance ({formattedMaxBalance} SOL)
            </p>
          )}
        </div>
        <label className="flex items-start gap-2.5 rounded-lg border border-ink-700 bg-ink-900/30 px-3 py-2.5 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={relayCrossChain}
            onChange={(e) => setRelayCrossChain(e.target.checked)}
            className="mt-0.5 h-3.5 w-3.5 rounded border-ink-600 bg-ink-900 accent-sol-purple"
          />
          <span className="text-xs text-mist">
            Also relay the announcement to Ethereum (Wormhole). The recipient sees it on either chain.
            {ethereumAddress == null && (
              <span className="block text-mist/60 mt-0.5">No Ethereum wallet needed to relay from Solana.</span>
            )}
          </span>
        </label>
        {error && <p className="text-error text-sm">{error}</p>}
        {txHash &&
          (() => {
            const explorerUrl = getExplorerTxUrl(txHash);
            return (
              <div className="p-3 rounded-lg bg-neutral-900 border border-border text-sm space-y-2">
                <div>
                  <span className="text-success">Sent.</span>{" "}
                  <span className="font-mono text-neutral-500 break-all text-xs">{txHash}</span>
                </div>
                {explorerUrl && (
                  <a
                    href={explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-neutral-400 hover:text-neutral-300"
                  >
                    <svg
                      width="12"
                      height="12"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden
                    >
                      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                      <polyline points="15 3 21 3 21 9" />
                      <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                    View on Explorer
                  </a>
                )}
              </div>
            );
          })()}
        {sending && steps.length > 0 && <ProtocolStepper steps={steps} />}
        <button
          type="button"
          onClick={() => void handleSend()}
          disabled={sending || !currentConfig || isInsufficientBalance || !recipient.trim() || !amount.trim()}
          className={`w-full py-2.5 px-4 rounded-lg text-sm font-medium btn-primary ${sending ? "loading" : ""}`}
        >
          {sending ? "Sending…" : "Send"}
        </button>
      </div>
    </div>
  );
}
