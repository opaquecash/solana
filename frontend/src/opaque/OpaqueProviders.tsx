/**
 * EVM provider stack (wagmi + react-query) for the multichain app. Mount ABOVE the Solana
 * wallet providers in `main.tsx`; it is inert until a component uses a wagmi hook, so the
 * Solana-only flows are unaffected.
 */

import { useState, type ReactNode } from "react";
import { WagmiProvider } from "wagmi";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { wagmiConfig } from "./wagmi";

export function OpaqueProviders({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </WagmiProvider>
  );
}
