/**
 * Checks whether the connected wallet has a stealth meta-address registered on Solana, via the
 * active `OpaqueClient`. Re-runs when the client, address, or cluster changes.
 */

import { useState, useEffect } from "react";
import { useOpaqueStore } from "../opaque/store";

export type RegistrationStatus = {
  isRegistered: boolean;
  isLoading: boolean;
};

export function useRegistrationStatus(
  address: string | null,
  cluster: string | null
): RegistrationStatus {
  const client = useOpaqueStore((s) => s.client);
  const [isRegisteredOnChain, setIsRegisteredOnChain] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!client || !address || cluster == null) {
      setIsRegisteredOnChain(false);
      setIsLoading(false);
      return;
    }

    let cancelled = false;
    setIsLoading(true);

    client
      .isMetaAddressRegistered("solana")
      .then((registered) => {
        if (!cancelled) setIsRegisteredOnChain(registered);
      })
      .catch(() => {
        if (!cancelled) setIsRegisteredOnChain(false);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [client, address, cluster]);

  return { isRegistered: isRegisteredOnChain, isLoading };
}
