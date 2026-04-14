/**
 * SNS (Solana Name Service) resolution — placeholder for .sol domain names.
 * Solana uses Bonfida's SNS instead of ENS.
 */

/**
 * Check if an identifier looks like a Solana domain name (ends with .sol).
 */
export function isSolDomain(identifier: string): boolean {
  const t = identifier.trim().toLowerCase();
  return t.endsWith(".sol") && t.length > 4;
}

/**
 * Resolve a .sol domain name to a Solana address.
 * Returns null if the name doesn't exist or resolution is not configured.
 *
 * Note: Full SNS integration requires the @bonfida/spl-name-service package.
 * This is a placeholder that can be extended when SNS support is needed.
 */
export async function resolveSolDomainToAddress(
  _domain: string,
): Promise<string | null> {
  // TODO: Integrate @bonfida/spl-name-service for .sol domain resolution
  console.warn("[Opaque] .sol domain resolution is not yet implemented.");
  return null;
}

// Legacy ENS compat alias
export const isEnsName = isSolDomain;
export const resolveEnsToAddress = resolveSolDomainToAddress;
