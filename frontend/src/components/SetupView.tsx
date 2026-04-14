import { useState } from "react";
import { useWallet } from "../hooks/useWallet";
import { useKeys } from "../context/KeysContext";

const SETUP_MESSAGE =
  "Sign this message to derive your Opaque Cash stealth keys. This does not approve any transaction.";

export function SetupView() {
  const { setFromSignature, stealthMetaAddressHex, isSetup } = useKeys();
  const { publicKeyRef, signMessageRef, connected, connect, wallets } = useWallet();
  const [isSigning, setIsSigning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSign = async () => {
    setError(null);
    console.log("[Opaque] Setup: requesting signature…");
    setIsSigning(true);
    try {
      if (!connected) {
        if (wallets.length === 0) {
          throw new Error("No Solana wallet found. Install Phantom or Solflare.");
        }
        await connect();
        await new Promise<void>((r) => setTimeout(r, 0));
      }
      const pk = publicKeyRef.current;
      const sign = signMessageRef.current;
      if (!pk || !sign) {
        throw new Error("No wallet found. Install Phantom or Solflare.");
      }
      console.log("[Opaque] Setup: wallet address", { address: pk.toBase58().slice(0, 14) + "…" });
      const encoded = new TextEncoder().encode(SETUP_MESSAGE);
      const sigBytes = await sign(encoded);
      const sigHex = `0x${Array.from(sigBytes).map(b => b.toString(16).padStart(2, "0")).join("")}` as `0x${string}`;
      setFromSignature(sigHex);
      console.log("[Opaque] Setup: signature received");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to sign";
      console.error("[Opaque] Setup failed", { error: msg });
      setError(msg);
    } finally {
      setIsSigning(false);
    }
  };

  return (
    <div className="card max-w-lg mx-auto">
      <h2 className="text-lg font-semibold text-white mb-1">
        Key setup
      </h2>
      <p className="text-sm text-neutral-500 mb-6">
        Sign with your wallet to derive your viewing and spending keys. Keys stay in this session only.
      </p>

      {!isSetup && (
        <div className="space-y-4">
          <button
            type="button"
            onClick={handleSign}
            disabled={isSigning}
            className="w-full py-2.5 px-4 rounded-lg text-sm font-medium btn-primary"
          >
            {isSigning ? "Check your wallet…" : "Connect wallet & sign to derive keys"}
          </button>
          {error && (
            <p className="text-error text-sm">{error}</p>
          )}
        </div>
      )}

      {isSetup && stealthMetaAddressHex && (
        <div className="space-y-3">
          <p className="text-neutral-400 text-sm">Your stealth meta-address:</p>
          <div className="p-3 rounded-lg bg-neutral-900 border border-border font-mono text-address text-neutral-200 break-all">
            {stealthMetaAddressHex}
          </div>
          <p className="text-neutral-600 text-xs">
            Share this with senders. They will use it to generate a one-time stealth address for you.
          </p>
        </div>
      )}
    </div>
  );
}
