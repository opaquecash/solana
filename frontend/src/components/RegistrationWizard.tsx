/**
 * Onboarding wizard shown when the user has derived keys but is not yet registered on the current
 * cluster. Step 1: Info -> Step 2: Register on-chain (via `OpaqueClient.registerMetaAddress`) with
 * progress. On success: "Vault Unlocked" animation, then onComplete() to transition to dashboard.
 */

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { getCluster } from "../lib/chain";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import { isClusterSupported } from "../contracts/contract-config";

type Step = "info" | "register" | "success";
type RegisterPhase = "idle" | "broadcasting" | "confirming";

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

export type RegistrationWizardProps = {
  onComplete: () => void;
};

export function RegistrationWizard({ onComplete }: RegistrationWizardProps) {
  const { client } = useOpaqueSession();
  const cluster = getCluster();
  const [step, setStep] = useState<Step>("info");
  const [registerPhase, setRegisterPhase] = useState<RegisterPhase>("idle");
  const [error, setError] = useState<string | null>(null);

  const wrongCluster = !isClusterSupported(cluster);

  const handleRegister = async () => {
    if (!client) {
      setError("Session not ready. Reconnect your wallet.");
      return;
    }
    setError(null);
    setRegisterPhase("broadcasting");
    try {
      // OpaqueClient signs register_keys with the connected Solana wallet and confirms it.
      await client.registerMetaAddress("solana");
      setRegisterPhase("confirming");
      setRegisterPhase("idle");
      setStep("success");
      setTimeout(() => {
        onComplete();
      }, 1800);
    } catch (e) {
      setError(toErrorMessage(e) || "Registration failed");
      setRegisterPhase("idle");
    }
  };

  const registerInProgress = registerPhase !== "idle";
  const progressSteps: { label: string; active: boolean; done: boolean }[] = [
    {
      label: "Broadcasting Transaction",
      active: registerPhase === "broadcasting",
      done: registerPhase === "confirming" || step === "success",
    },
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
                  need to publish your Stealth Meta-Address. This is a one-time setup per cluster.
                </p>
                <button
                  type="button"
                  onClick={() => setStep("register")}
                  className="w-full py-3 px-4 rounded-lg text-sm font-medium btn-primary"
                >
                  Continue
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
                    disabled={!client || wrongCluster}
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
