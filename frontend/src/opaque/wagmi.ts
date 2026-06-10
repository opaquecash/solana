/**
 * wagmi config for the Ethereum (Sepolia) side of the multichain app. Solana stays on the
 * wallet-adapter; this adds an injected EVM connector so users can optionally connect MetaMask
 * (or any injected wallet) for EVM send, UAB relay, EVM PSR, and cross-chain scan.
 */

import { createConfig, http } from "wagmi";
import { sepolia } from "wagmi/chains";
import { injected } from "wagmi/connectors";
import { SEPOLIA_RPC_URL } from "./config";

export const wagmiConfig = createConfig({
  chains: [sepolia],
  connectors: [injected()],
  transports: {
    [sepolia.id]: http(SEPOLIA_RPC_URL),
  },
});
