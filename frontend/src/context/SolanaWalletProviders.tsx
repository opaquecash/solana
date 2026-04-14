import { useMemo, type ReactNode } from "react";
import { ConnectionProvider, WalletProvider } from "@solana/wallet-adapter-react";
import { WalletAdapterNetwork } from "@solana/wallet-adapter-base";
import { PhantomWalletAdapter } from "@solana/wallet-adapter-phantom";
import { SolflareWalletAdapter } from "@solana/wallet-adapter-solflare";
import { getCluster, getRpcUrl } from "../lib/chain";
import type { SolanaCluster } from "../lib/chain";

type Props = {
  children: ReactNode;
};

function solanaClusterToAdapterNetwork(c: SolanaCluster): WalletAdapterNetwork {
  if (c === "mainnet-beta") return WalletAdapterNetwork.Mainnet;
  if (c === "testnet") return WalletAdapterNetwork.Testnet;
  return WalletAdapterNetwork.Devnet;
}

/**
 * Required ancestor for `useWallet` / `useConnection` from `@solana/wallet-adapter-react`
 * and for the app’s `hooks/useWallet` wrapper.
 */
export function SolanaWalletProviders({ children }: Props) {
  const endpoint = useMemo(() => getRpcUrl(), []);
  const adapterNetwork = useMemo(() => solanaClusterToAdapterNetwork(getCluster()), []);

  const wallets = useMemo(
    () => [new PhantomWalletAdapter(), new SolflareWalletAdapter({ network: adapterNetwork })],
    [adapterNetwork],
  );

  return (
    <ConnectionProvider endpoint={endpoint}>
      <WalletProvider wallets={wallets} autoConnect={false}>
        {children}
      </WalletProvider>
    </ConnectionProvider>
  );
}
