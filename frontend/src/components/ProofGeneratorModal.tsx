/**
 * Proof Generator Modal
 *
 * Generates a Groth16 ZK proof for a discovered reputation trait in the browser via
 * OpaqueClient.generateReputationProof (no private data leaves the device), then submits it to
 * the Solana reputation verifier via client.submitReputationVerification. All crypto lives in
 * the SDK; this component is UI + orchestration only.
 */

import { useState } from "react";
import type { DiscoveredTrait, ProofData } from "@opaquecash/opaque";
import { useOpaqueSession } from "../opaque/useOpaqueSession";

type ProofStep = "setup" | "generating" | "done" | "submitting" | "verified" | "error";

interface ProofGeneratorModalProps {
  trait: DiscoveredTrait;
  onClose: () => void;
}

export function ProofGeneratorModal({ trait, onClose }: ProofGeneratorModalProps) {
  const { client, isSetup } = useOpaqueSession();
  const [step, setStep] = useState<ProofStep>("setup");
  const [externalNullifier, setExternalNullifier] = useState("");
  const [proof, setProof] = useState<ProofData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [txSig, setTxSig] = useState<string | null>(null);

  const handleGenerate = async () => {
    if (!externalNullifier.trim()) {
      setError("External nullifier is required.");
      return;
    }
    if (!client || !isSetup) {
      setError("Keys not set up. Please sign in first.");
      return;
    }
    setStep("generating");
    setError(null);
    try {
      // Reconstruct the one-time stealth key for this trait, then prove entirely in-browser.
      const stealthPrivKeyBytes = client.getStealthSignerPrivateKeyForReputationTrait(trait);
      const proofData = await client.generateReputationProof({
        trait,
        stealthPrivKeyBytes,
        externalNullifier: externalNullifier.trim(),
      });
      setProof(proofData);
      setStep("done");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/fetch|404|NetworkError|Failed to load/.test(msg)) {
        setError("Reputation circuit artifacts could not be loaded. Check the configured artifact paths.");
      } else {
        setError(msg);
      }
      setStep("error");
    }
  };

  const handleCopy = async () => {
    if (!proof) return;
    await navigator.clipboard.writeText(JSON.stringify(proof, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmitOnChain = async () => {
    if (!proof || !client) {
      setError("Generate a proof first.");
      return;
    }
    setStep("submitting");
    setError(null);
    try {
      const { txHash } = await client.submitReputationVerification("solana", {
        proofData: proof,
        merkleRoot: proof.publicSignals[0],
        externalNullifier: externalNullifier.trim(),
      });
      setTxSig(txHash);
      setStep("verified");
    } catch (e) {
      setError(e instanceof Error ? e.message : "On-chain verification failed");
      setStep("error");
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-2xl border border-ink-700 bg-ink-900 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-ink-800">
          <h2 className="text-base font-semibold text-white">Generate ZK Proof</h2>
          <button type="button" onClick={onClose} className="text-ink-500 hover:text-white transition-colors text-xl leading-none" aria-label="Close">×</button>
        </div>

        <div className="px-6 py-5 space-y-5">
          <div className="rounded-xl border border-ink-700 bg-ink-950 px-4 py-3 space-y-1">
            <p className="text-xs text-mist">Proving trait</p>
            <p className="text-sm font-semibold text-white">Trait #{trait.attestationId}</p>
            <p className="text-xs text-ink-500 font-mono truncate">{trait.stealthAddress}</p>
          </div>

          {step === "setup" && (
            <>
              <div className="space-y-2">
                <label className="block text-sm font-medium text-white">External Nullifier</label>
                <input
                  type="text"
                  placeholder="Decimal or 0x-hex domain separator from the requesting dApp"
                  value={externalNullifier}
                  onChange={(e) => setExternalNullifier(e.target.value)}
                  className="w-full rounded-xl border border-ink-700 bg-ink-950 px-4 py-3 text-white placeholder-ink-500 focus:outline-none focus:border-sol-purple text-sm font-mono"
                />
                <p className="text-xs text-mist">
                  Must be a decimal number or 0x-prefixed hex. Prevents replay across different applications.
                </p>
              </div>
              {error && <p className="text-sm text-red-400">{error}</p>}
              <button type="button" onClick={handleGenerate} disabled={!externalNullifier.trim()} className="w-full rounded-xl bg-sol-purple py-3 text-sm font-semibold text-white hover:bg-sol-purple/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                Generate Proof in Browser
              </button>
              <p className="text-center text-xs text-ink-500">No private data leaves your browser. Proof generation takes 10–60 seconds.</p>
            </>
          )}

          {(step === "generating" || step === "submitting") && (
            <div className="flex flex-col items-center gap-4 py-6">
              <span className="h-10 w-10 animate-spin rounded-full border-2 border-ink-600 border-t-sol-purple" />
              <p className="text-sm text-mist">{step === "generating" ? "Generating ZK proof locally…" : "Submitting proof on-chain…"}</p>
            </div>
          )}

          {step === "done" && proof && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center shrink-0">
                  <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                </div>
                <p className="text-sm font-medium text-white">Proof ready. No private data left your browser.</p>
              </div>
              <div className="rounded-xl border border-ink-700 bg-ink-950 px-4 py-3">
                <p className="text-xs text-mist mb-2">Public signals</p>
                <div className="space-y-1">
                  {proof.publicSignals.map((value, i) => (
                    <div key={i} className="flex gap-2 text-xs">
                      <span className="text-mist w-8 shrink-0">[{i}]</span>
                      <span className="font-mono text-white truncate">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex gap-3">
                <button type="button" onClick={handleCopy} className="flex-1 rounded-xl border border-ink-700 bg-ink-800 py-2.5 text-sm font-medium text-white hover:bg-ink-700 transition-colors">{copied ? "Copied!" : "Copy Proof"}</button>
                <button type="button" onClick={handleSubmitOnChain} className="flex-1 rounded-xl bg-sol-purple py-2.5 text-sm font-semibold text-white hover:bg-sol-purple/90 transition-colors">Submit On-Chain</button>
              </div>
            </div>
          )}

          {step === "verified" && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <div className="w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center shrink-0">
                  <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                </div>
                <p className="text-sm font-medium text-white">Proof verified on-chain!</p>
              </div>
              {txSig && (
                <a href={`https://explorer.solana.com/tx/${txSig}?cluster=devnet`} target="_blank" rel="noopener noreferrer" className="block text-xs text-sol-purple hover:underline font-mono">{txSig.slice(0, 24)}… ↗</a>
              )}
              <button type="button" onClick={onClose} className="w-full rounded-xl border border-ink-700 bg-ink-800 py-2.5 text-sm font-medium text-white hover:bg-ink-700 transition-colors">Done</button>
            </div>
          )}

          {step === "error" && (
            <div className="space-y-4">
              <p className="text-sm text-red-400">{error}</p>
              <button type="button" onClick={() => { setStep("setup"); setError(null); }} className="w-full rounded-xl border border-ink-700 bg-ink-800 py-2.5 text-sm font-medium text-white hover:bg-ink-700 transition-colors">Try again</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
