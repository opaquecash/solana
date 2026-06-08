/**
 * Onboarding wizard when the user is not registered on the current cluster.
 * Step 1: Info -> Step 2: Generate Stealth Keys (sign) -> Step 3: Register on-chain with progress.
 * On success: "Vault Unlocked" animation, then onComplete() to transition to dashboard.
 */

import { useEffect, useState } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { Connection, Transaction } from "@solana/web3.js";
import { motion, AnimatePresence } from "framer-motion";
import { getCluster, getRpcUrl } from "../lib/chain";
import { useKeys } from "../context/KeysContext";
import { buildRegisterKeysInstruction, SCHEME_ID_SECP256K1 } from "../lib/contracts";
import { hexToBytes, SETUP_MESSAGE, type Hex } from "../lib/stealth";
import { getConfigForCluster, isClusterSupported } from "../contracts/contract-config";
import {
  getRememberSignaturePreference,
  loadSignatureSession,
  saveSignatureSession,
  setRememberSignaturePreference,
} from "../lib/signatureSession";

type Step = "info" | "generate" | "register" | "success";
type RegisterPhase = "idle" | "deriving" | "broadcasting" | "confirming";

function toErrorMessage(value: unknown): string {
  if (value instanceof Error) return value.message;
  if (typeof value === "string") return value;
  if (value == null) return "Unknown error";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function extractNestedErrorLines(error: unknown): string[] {
  const lines: string[] = [];
  if (!error || typeof error !== "object") return lines;
  const asRecord = error as Record<string, unknown>;
  const candidates = [asRecord.cause, asRecord.error, asRecord.originalError];
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue;
    const c = candidate as Record<string, unknown>;
    if (Array.isArray(c.logs)) {
      lines.push(...(c.logs as unknown[]).map((entry) => toErrorMessage(entry)));
    }
    if (typeof c.message === "string") lines.push(c.message);
  }
  return lines;
}

export type RegistrationWizardProps = {
  onComplete: () => void;
};

export function RegistrationWizard({ onComplete }: RegistrationWizardProps) {
  const { setFromSignature, stealthMetaAddressHex } = useKeys();
  const { publicKey, signMessage, sendTransaction } = useWallet();
  const cluster = getCluster();
  const currentConfig = getConfigForCluster(cluster);
  const address = publicKey?.toBase58() ?? null;
  const [step, setStep] = useState<Step>("info");
  const [signing, setSigning] = useState(false);
  const [registerPhase, setRegisterPhase] = useState<RegisterPhase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [, setTxSig] = useState<string | null>(null);
  const [rememberSession, setRememberSession] = useState<boolean>(() => getRememberSignaturePreference());

  useEffect(() => {
    setRememberSignaturePreference(rememberSession);
  }, [rememberSession]);

  const wrongCluster = !isClusterSupported(cluster);

  const handleGenerateKeys = async () => {
    if (!address || !signMessage) {
      setError("No wallet found.");
      return;
    }
    setError(null);
    setSigning(true);
    try {
      let sig = await loadSignatureSession({
        address,
        cluster,
        message: SETUP_MESSAGE,
      });
      if (!sig) {
        const encoded = new TextEncoder().encode(SETUP_MESSAGE);
        const sigBytes = await signMessage(encoded);
        const hex = `0x${Array.from(sigBytes).map(b => b.toString(16).padStart(2, "0")).join("")}` as `0x${string}`;
        sig = hex;
        await saveSignatureSession({
          signatureHex: hex,
          address,
          cluster,
          message: SETUP_MESSAGE,
          remember: rememberSession,
        });
      }
      setFromSignature(sig);
      setStep("register");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Signature failed");
    } finally {
      setSigning(false);
    }
  };

  const handleRegister = async () => {
    if (!stealthMetaAddressHex || !publicKey || !currentConfig) return;
    setError(null);
    setTxSig(null);
    setRegisterPhase("deriving");
    await new Promise((r) => setTimeout(r, 400));
    setRegisterPhase("broadcasting");
    try {
      const rpcUrl = getRpcUrl();
      const connection = new Connection(rpcUrl, "confirmed");
      const metaBytes = hexToBytes(stealthMetaAddressHex as Hex);
      const ix = buildRegisterKeysInstruction(
        publicKey,
        SCHEME_ID_SECP256K1,
        metaBytes,
      );
      const tx = new Transaction().add(ix);
      tx.feePayer = publicKey;
      const latestBlockhash = await connection.getLatestBlockhash("confirmed");
      tx.recentBlockhash = latestBlockhash.blockhash;
      tx.lastValidBlockHeight = latestBlockhash.lastValidBlockHeight;

      const walletAccount = await connection.getAccountInfo(publicKey, "confirmed");
      if (!walletAccount) {
        const walletAddress = publicKey.toBase58();
        const msg =
          `Connected wallet ${walletAddress.slice(0, 6)}...${walletAddress.slice(-6)} is not initialized on ${cluster}. ` +
          `Switch Phantom to Devnet and fund this exact wallet with devnet SOL, then retry.`;
        console.error("[RegistrationWizard] Wallet account not found on cluster", {
          cluster,
          rpcUrl,
          wallet: walletAddress,
        });
        setError(msg);
        setRegisterPhase("idle");
        return;
      }

      const walletLamports = await connection.getBalance(publicKey, "confirmed");
      if (walletLamports === 0) {
        const walletAddress = publicKey.toBase58();
        const msg =
          `Connected wallet ${walletAddress.slice(0, 6)}...${walletAddress.slice(-6)} has 0 SOL on ${cluster}. ` +
          `Fund this wallet on devnet before registering.`;
        console.error("[RegistrationWizard] Wallet has zero balance", {
          cluster,
          rpcUrl,
          wallet: walletAddress,
        });
        setError(msg);
        setRegisterPhase("idle");
        return;
      }

      // Best-effort pre-send simulation for clearer diagnostics in dev.
      try {
        const simulation = await connection.simulateTransaction(tx);
        if (simulation.value.err) {
          const accountStates = await Promise.all(
            ix.keys.map(async (k) => {
              const info = await connection.getAccountInfo(k.pubkey, "confirmed");
              return {
                pubkey: k.pubkey.toBase58(),
                exists: info != null,
                lamports: info?.lamports ?? 0,
                owner: info?.owner?.toBase58() ?? null,
                executable: info?.executable ?? false,
                isSigner: k.isSigner,
                isWritable: k.isWritable,
              };
            })
          );
          console.error("[RegistrationWizard] register_keys simulation failed", {
            rpcUrl,
            cluster,
            wallet: publicKey.toBase58(),
            programId: ix.programId.toBase58(),
            accounts: ix.keys.map((k) => ({
              pubkey: k.pubkey.toBase58(),
              isSigner: k.isSigner,
              isWritable: k.isWritable,
            })),
            accountStates,
            simulationErr: simulation.value.err,
            simulationLogs: simulation.value.logs ?? [],
          });
        }
      } catch (simulationError) {
        console.warn("[RegistrationWizard] register_keys simulation unavailable", {
          rpcUrl,
          simulationError: toErrorMessage(simulationError),
        });
      }

      const sig = await sendTransaction(tx, connection);
      setTxSig(sig);
      setRegisterPhase("confirming");
      await connection.confirmTransaction(
        {
          signature: sig,
          blockhash: latestBlockhash.blockhash,
          lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
        },
        "confirmed"
      );
      setRegisterPhase("idle");
      setStep("success");
      setTimeout(() => {
        onComplete();
      }, 1800);
    } catch (e) {
      const nestedLines = extractNestedErrorLines(e);
      const base = toErrorMessage(e);
      const details = nestedLines.length > 0 ? nestedLines.slice(0, 4).join(" | ") : null;
      const message = details ? `${base} — ${details}` : base;
      console.error("[RegistrationWizard] register_keys failed", {
        cluster,
        rpcUrl: getRpcUrl(),
        wallet: publicKey.toBase58(),
        error: e,
        parsedMessage: message,
      });
      setError(message || "Registration failed");
      setRegisterPhase("idle");
    }
  };

  const registerInProgress = registerPhase !== "idle";
  const progressSteps: { label: string; active: boolean; done: boolean }[] = [
    { label: "Deriving Keys", active: registerPhase === "deriving", done: registerPhase !== "deriving" && (registerPhase === "broadcasting" || registerPhase === "confirming" || step === "success") },
    { label: "Broadcasting Transaction", active: registerPhase === "broadcasting", done: registerPhase === "confirming" || step === "success" },
    { label: "Confirming…", active: registerPhase === "confirming", done: step === "success" },
  ];

  return (
    <div className="w-full max-w-lg mx-auto">
      <AnimatePresence mode="wait">
        {step === "success" ? (
          <motion.div
            key="success"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0 }}
            className="card flex flex-col items-center justify-center py-12 px-6 text-center"
          >
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 200, damping: 15 }}
              className="w-20 h-20 rounded-2xl bg-emerald-500/20 border-2 border-emerald-500/50 flex items-center justify-center mb-6"
              aria-hidden
            >
              <svg
                className="w-10 h-10 text-emerald-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"
                />
              </svg>
            </motion.div>
            <h2 className="text-xl font-semibold text-white mb-1">Vault Unlocked</h2>
            <p className="text-sm text-neutral-500">Taking you to your dashboard…</p>
          </motion.div>
        ) : (
          <motion.div
            key="wizard"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="card"
          >
            <h2 className="text-lg font-semibold text-white mb-1">Registration required</h2>

            {step === "info" && (
              <div className="space-y-4">
                <p className="text-sm text-neutral-400 leading-relaxed">
                  Your wallet is not yet registered on this cluster. To receive private payments, you
                  need to generate and publish your Stealth Meta-Address. This is a one-time setup
                  per cluster.
                </p>
                <button
                  type="button"
                  onClick={() => setStep("generate")}
                  className="w-full py-3 px-4 rounded-lg text-sm font-medium btn-primary"
                >
                  Continue
                </button>
              </div>
            )}

            {step === "generate" && (
              <div className="space-y-4 mb-0">
                <p className="text-sm text-neutral-400">
                  Sign a message in your wallet to derive your spending and viewing keys. Keys are
                  generated locally and never leave your device.
                </p>
                <label className="inline-flex items-center gap-2 text-xs text-mist cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberSession}
                    onChange={(e) => setRememberSession(e.target.checked)}
                    className="h-3.5 w-3.5 rounded border-ink-600 bg-ink-900 accent-sol-purple"
                  />
                  Remember signature for this tab (about 30 minutes)
                </label>
                {error && <p className="text-sm text-red-400">{error}</p>}
                <button
                  type="button"
                  onClick={handleGenerateKeys}
                  disabled={signing}
                  className="w-full py-3 px-4 rounded-lg text-sm font-medium bg-white text-black hover:opacity-90 disabled:opacity-50 transition-opacity"
                >
                  {signing ? "Check your wallet…" : "Generate Stealth Keys"}
                </button>
              </div>
            )}

            {step === "register" && (
              <div className="space-y-4 mb-0">
                {wrongCluster && (
                  <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 space-y-2">
                    <p className="text-sm text-amber-200">
                      Wrong cluster: registration is available on devnet only.
                    </p>
                  </div>
                )}
                <p className="text-sm text-neutral-400">
                  Publish your Stealth Meta-Address on-chain so others can send to you by your Solana
                  address.
                </p>
                {error && <p className="text-sm text-red-400">{error}</p>}
                <div className="space-y-2">
                  {progressSteps.map(({ label, active, done }) => (
                    <div
                      key={label}
                      className={`flex items-center gap-2 text-sm ${
                        active ? "text-white" : done ? "text-emerald-500/80" : "text-neutral-500"
                      }`}
                    >
                      {done ? (
                        <span className="text-emerald-500" aria-hidden>✓</span>
                      ) : active ? (
                        <span className="inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" aria-hidden />
                      ) : (
                        <span className="w-4 h-4 rounded-full border border-neutral-600" aria-hidden />
                      )}
                      {label}
                    </div>
                  ))}
                </div>
                {!registerInProgress && (
                  <button
                    type="button"
                    onClick={handleRegister}
                    disabled={!currentConfig || wrongCluster}
                    className="w-full py-3 px-4 rounded-lg text-sm font-medium btn-primary disabled:opacity-50 disabled:cursor-not-allowed mt-4"
                  >
                    Register on {cluster}
                  </button>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
