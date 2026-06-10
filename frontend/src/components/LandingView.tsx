import { useCallback, useEffect, useRef, useState } from "react";
import { useWallet } from "../hooks/useWallet";
import { useOpaqueSession } from "../opaque/useOpaqueSession";
import {
  getRememberSignaturePreference,
  setRememberSignaturePreference,
} from "../lib/signatureSession";

type Phase = "idle" | "connecting" | "deriving" | "error";

export function LandingView() {
  const { isSetup, connect: deriveSession, status } = useOpaqueSession();
  const { connected, connecting, connect: connectWallet, wallets } = useWallet();
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [rememberSession, setRememberSession] = useState<boolean>(() =>
    getRememberSignaturePreference(),
  );
  /** Set after `connectWallet()` so the derive runs once the wallet reports connected. */
  const pendingRef = useRef(false);

  useEffect(() => {
    setRememberSignaturePreference(rememberSession);
  }, [rememberSession]);

  const runDerive = useCallback(async () => {
    setError(null);
    setPhase("deriving");
    try {
      // Builds the OpaqueClient (sign or restore cached signature, derive keys, load scanner).
      // Once the session is set, App swaps out of LandingView automatically.
      await deriveSession({ remember: rememberSession });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Setup failed");
      setPhase("error");
    }
  }, [deriveSession, rememberSession]);

  // Wallet connect is async (adapter state lands a tick later); derive once it reports connected.
  useEffect(() => {
    if (pendingRef.current && connected) {
      pendingRef.current = false;
      void runDerive();
    }
  }, [connected, runDerive]);

  const handleEnterVault = async () => {
    setError(null);
    if (!connected) {
      if (wallets.length === 0) {
        setError("No Solana wallet found. Install Phantom or Solflare.");
        setPhase("error");
        return;
      }
      setPhase("connecting");
      pendingRef.current = true;
      try {
        await connectWallet();
      } catch (e) {
        pendingRef.current = false;
        setError(e instanceof Error ? e.message : "Failed to connect");
        setPhase("error");
      }
      return;
    }
    void runDerive();
  };

  if (isSetup) return null;

  const showSpinner = phase === "connecting" || phase === "deriving";

  return (
    <div className="flex flex-1 flex-col items-center justify-center px-5 sm:px-8 py-16">
      <div className="w-full max-w-md text-center">
        <h1 className="font-display text-5xl font-extrabold tracking-tight text-white sm:text-6xl">
          Opaque<span className="text-sol-gradient">.</span>
        </h1>

        <p className="mt-4 text-mist">
          Connect a Solana wallet and derive stealth keys to begin. Keys are generated on-device and never
          leave your browser.
        </p>

        {phase === "idle" && (
          <>
            <button
              type="button"
              onClick={handleEnterVault}
              disabled={connecting}
              className="mt-8 w-full rounded-xl bg-sol-gradient px-6 py-3.5 text-sm font-semibold text-white transition-all hover:shadow-[0_0_32px_rgba(153,69,255,0.3)] hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
            >
              {!connected ? "Connect wallet & initialize" : "Initialize protocol"}
            </button>
            <label className="mt-3 inline-flex items-center gap-2 text-xs text-mist cursor-pointer select-none">
              <input
                type="checkbox"
                checked={rememberSession}
                onChange={(e) => setRememberSession(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-ink-600 bg-ink-900 accent-sol-purple"
              />
              Remember signature for this tab (about 30 minutes)
            </label>
          </>
        )}

        {showSpinner && (
          <div className="mt-8 flex flex-col items-center gap-3">
            <span className="h-6 w-6 animate-spin rounded-full border-2 border-ink-600 border-t-sol-purple" />
            <p className="text-sm text-mist">
              {phase === "connecting"
                ? "Check your wallet to connect…"
                : status ?? "Deriving your stealth keys…"}
            </p>
          </div>
        )}

        {phase === "error" && error && (
          <div className="mt-6 rounded-xl border border-red-500/30 bg-red-950/20 px-4 py-3 text-left text-sm text-red-200">
            {error}
          </div>
        )}
      </div>
    </div>
  );
}
