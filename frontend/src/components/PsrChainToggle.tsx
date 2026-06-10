/**
 * Small segmented control for choosing which chain a PSR action targets. The same OpaqueClient
 * method runs on either chain; Ethereum is disabled until an EVM wallet is connected.
 */

export type PsrChain = "solana" | "ethereum";

export function PsrChainToggle({
  value,
  onChange,
  ethConnected,
}: {
  value: PsrChain;
  onChange: (chain: PsrChain) => void;
  ethConnected: boolean;
}) {
  const chains: { id: PsrChain; label: string; disabled: boolean }[] = [
    { id: "solana", label: "Solana", disabled: false },
    { id: "ethereum", label: "Ethereum", disabled: !ethConnected },
  ];
  return (
    <div className="inline-flex rounded-lg border border-ink-700 bg-ink-900 p-0.5 text-xs">
      {chains.map((c) => (
        <button
          key={c.id}
          type="button"
          disabled={c.disabled}
          onClick={() => onChange(c.id)}
          title={c.disabled ? "Connect an Ethereum wallet to use this chain" : undefined}
          className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
            value === c.id
              ? "bg-sol-purple text-white"
              : c.disabled
                ? "text-ink-600 cursor-not-allowed"
                : "text-mist hover:text-white"
          }`}
        >
          {c.label}
        </button>
      ))}
    </div>
  );
}
