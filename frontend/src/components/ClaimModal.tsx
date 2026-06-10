import { formatSol } from "../lib/format";
import type { FoundTx } from "./PrivateBalanceView";
import type { TokenInfo } from "../lib/tokens";
import { ProtocolStepper } from "./ProtocolStepper";
import type { ProtocolStep } from "./ProtocolStepper";
import { ExplorerLink } from "./ExplorerLink";
import { ModalShell } from "./ModalShell";

type ClaimModalProps = {
  tx: FoundTx;
  asset: TokenInfo;
  destination: string;
  mainWalletAddress: string | undefined;
  cluster: string | null;
  claiming: boolean;
  error: string | null;
  withdrawalSteps?: ProtocolStep[];
  onDestinationChange: (value: string) => void;
  onConfirm: () => void;
  onClose: () => void;
};

export function ClaimModal({
  tx,
  asset,
  destination,
  mainWalletAddress,
  cluster,
  claiming,
  error,
  withdrawalSteps = [],
  onDestinationChange,
  onConfirm,
  onClose,
}: ClaimModalProps) {
  const amountRaw = tx.balance;
  const amountStr = formatSol(amountRaw);
  const destinationTrimmed = destination.trim();
  const isSameAsMain =
    !!mainWalletAddress &&
    destinationTrimmed.length > 0 &&
    destinationTrimmed === mainWalletAddress;

  return (
    <ModalShell
      open
      title="Withdraw"
      description="Sweep funds from a one-time stealth address."
      onClose={onClose}
      closeOnBackdrop={!claiming}
      maxWidthClassName="max-w-md"
    >

        <div className="mb-4 p-3 rounded-xl bg-ink-950/40 border border-ink-700 font-mono text-xs text-mist">
          <div className="flex justify-between items-center gap-2">
            <ExplorerLink cluster={cluster} value={tx.address} type="address" className="text-slate-200" />
            <span className="text-success font-medium shrink-0">{amountStr} {asset.symbol}</span>
          </div>
        </div>

        <div className="space-y-2 mb-5 p-3 rounded-xl bg-ink-950/30 border border-ink-700 font-mono text-xs text-mist/90">
          <p className="text-slate-200 font-medium">Protocol steps</p>
          <p>1. Reconstruct private key from spend key + shared secret</p>
          <p>2. Create independent transaction signed by stealth key</p>
          <p>3. On-chain sender = stealth address, no identity link</p>
        </div>

        <div className="mb-4">
          <label className="block text-sm text-mist mb-1.5 font-mono">
            Destination
          </label>
          <input
            type="text"
            value={destination}
            onChange={(e) => onDestinationChange(e.target.value)}
            placeholder="Solana address (use a fresh address)"
            className="input-field text-sm"
          />
        </div>

        {/* Privacy meter */}
        <div className="mb-5">
          <p className="text-xs text-mist/70 mb-1.5 font-mono">Privacy check</p>
          {isSameAsMain ? (
            <div className="p-3 rounded-xl bg-ink-950/40 border border-warning/20 text-warning text-sm">
              Sending to your connected wallet links your identity to this transaction. Use a fresh address.
            </div>
          ) : (
            <div className="p-3 rounded-xl bg-ink-950/40 border border-success/20 text-success text-sm">
              Destination differs from connected wallet — good for privacy.
            </div>
          )}
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-error/10 border border-error/30 text-error text-sm">
            {error}
          </div>
        )}

        {claiming && withdrawalSteps.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-mist/70 mb-2 font-mono">Progress</p>
            <ProtocolStepper steps={withdrawalSteps} />
          </div>
        )}

        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={onClose}
            disabled={claiming}
            className="px-4 py-2 rounded-xl text-sm font-medium text-mist border border-ink-600 bg-ink-950/30 hover:border-sol-purple/30 hover:text-white transition-colors disabled:opacity-40"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={claiming || !destinationTrimmed}
            className={`px-4 py-2 rounded-xl text-sm font-semibold bg-sol-gradient text-white hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed ${claiming ? "loading" : ""}`}
          >
            {claiming ? "Claiming…" : "Confirm"}
          </button>
        </div>
    </ModalShell>
  );
}
