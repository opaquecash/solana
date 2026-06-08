/**
 * Opaque Protocol — Client-side stealth address crypto (DKSAP)
 *
 * Implements the Dual-Key Stealth Address Protocol: senders derive a one-time
 * stealth address from the recipient's meta-address (viewing + spending public keys);
 * recipients use their viewing key to detect transfers and spending key to sweep.
 * Uses @noble/curves secp256k1; compatible with the Rust WASM scanner.
 *
 * Solana adaptation: stealth addresses are derived from secp256k1 keys (same crypto),
 * but stored/transmitted as raw bytes rather than EVM addresses. The on-chain stealth
 * "address" is the 20-byte Keccak hash of the uncompressed public key (for scanner
 * compatibility), while the actual Solana keypair is derived separately for signing.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { Keypair } from "@solana/web3.js";

const CURVE = secp256k1;
const DOMAIN = "opaque-cash-v1";

// Hex string type for compatibility
export type Hex = `0x${string}`;

// -----------------------------------------------------------------------------
// Canonical key-derivation message (CSAP §2.2)
// -----------------------------------------------------------------------------

/**
 * The ONE canonical message every Opaque entry point must ask the wallet to sign
 * before deriving stealth keys. It is chain-neutral on purpose: a given wallet must
 * derive the same key set regardless of which view it onboards through.
 *
 * MUST match `spec/CSAP.md` §2.2 exactly (byte-for-byte). Do not redefine this string
 * anywhere else — import it. A regression test pins it to the spec value.
 */
export const SETUP_MESSAGE =
  "Sign this message to derive your Opaque Cash stealth keys. This does not approve any transaction.";

/**
 * Legacy messages that earlier builds signed on Solana before the message was
 * standardised. A wallet that onboarded through the old LandingView/RegistrationWizard
 * signed the string below, deriving a DIFFERENT key set (and meta-address) than the
 * canonical one. These are kept ONLY so the migration scan (see
 * `deriveLegacyKeyCandidates`) can still discover and sweep funds at the old key set.
 * Never sign these for new derivations.
 */
export const LEGACY_SOLANA_SETUP_MESSAGES: readonly string[] = [
  "Sign this message to derive your Opaque Cash stealth keys on Solana. This is not a transaction and does not move funds.",
];

// -----------------------------------------------------------------------------
// Key derivation from wallet signature (entropy)
// -----------------------------------------------------------------------------

/**
 * Derive viewing key (v) and spending key (s) from a wallet signature used as entropy.
 * Uses HKDF-SHA256 to expand the signature into 64 bytes, then splits into two
 * 32-byte private keys. Domain string is "opaque-cash-v1".
 */
export function deriveKeysFromSignature(signatureHex: Hex | string): {
  viewingKey: Uint8Array;
  spendingKey: Uint8Array;
} {
  console.log("🔐 [Opaque] deriveKeysFromSignature");
  const sigBytes =
    typeof signatureHex === "string"
      ? (signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex)
      : signatureHex;
  const sig = typeof sigBytes === "string" ? hexToBytes(sigBytes) : sigBytes;
  const okm = hkdf(sha256, sig, undefined, DOMAIN, 64);
  const viewingKey = okm.slice(0, 32);
  const spendingKey = okm.slice(32, 64);
  console.log("🔐 [Opaque] Keys derived from signature ✅");
  return { viewingKey, spendingKey };
}

/**
 * Build the stealth meta-address from viewing and spending private keys.
 * Meta-address = compressed(V) || compressed(S) (66 bytes total).
 */
export function keysToStealthMetaAddress(
  viewingKey: Uint8Array,
  spendingKey: Uint8Array
): { V: Uint8Array; S: Uint8Array; metaAddress: Uint8Array } {
  const V = CURVE.getPublicKey(viewingKey, true);
  const S = CURVE.getPublicKey(spendingKey, true);
  const metaAddress = new Uint8Array(V.length + S.length);
  metaAddress.set(V, 0);
  metaAddress.set(S, V.length);
  return { V, S, metaAddress };
}

/**
 * Encode the 66-byte stealth meta-address as 0x-prefixed hex.
 */
export function stealthMetaAddressToHex(metaAddress: Uint8Array): Hex {
  return ("0x" + bytesToHex(metaAddress)) as Hex;
}

// -----------------------------------------------------------------------------
// Legacy key-set migration (CSAP §2.2 — "scan both strings")
// -----------------------------------------------------------------------------

export type LegacyKeyCandidate = {
  /** The legacy message whose signature produced this key set. */
  message: string;
  viewingKey: Uint8Array;
  spendingKey: Uint8Array;
  /** Legacy stealth meta-address (0x + 66 hex) to scan for orphaned funds. */
  metaAddressHex: Hex;
};

/**
 * Derive the stealth key sets a wallet would have had under earlier signing
 * messages ({@link LEGACY_SOLANA_SETUP_MESSAGES}). Pure: the caller asks the wallet
 * to sign each legacy message and passes the signatures index-aligned with `messages`.
 *
 * Why this exists: before the message was standardised, the Solana LandingView /
 * RegistrationWizard signed a different string than SetupView, so the same wallet
 * derived a DIFFERENT key set (and meta-address) depending on the onboarding path.
 * Now that every entry point signs {@link SETUP_MESSAGE}, those users would otherwise
 * lose sight of funds sent to the old meta-address.
 *
 * Migration flow (scan-both): on a returning Solana wallet — (1) derive canonical keys
 * from SETUP_MESSAGE as usual; (2) call this with signatures over each legacy message;
 * (3) scan each returned `metaAddressHex` for announcements/funds; (4) if any are found,
 * sweep them to the canonical stealth address and stop offering migration for that
 * wallet. New derivations MUST always use SETUP_MESSAGE — never a legacy message.
 */
export function deriveLegacyKeyCandidates(
  legacySignatures: ReadonlyArray<Hex | string>,
  messages: readonly string[] = LEGACY_SOLANA_SETUP_MESSAGES,
): LegacyKeyCandidate[] {
  return legacySignatures.map((sig, i) => {
    const { viewingKey, spendingKey } = deriveKeysFromSignature(sig);
    const { metaAddress } = keysToStealthMetaAddress(viewingKey, spendingKey);
    return {
      message: messages[i] ?? LEGACY_SOLANA_SETUP_MESSAGES[0],
      viewingKey,
      spendingKey,
      metaAddressHex: stealthMetaAddressToHex(metaAddress),
    };
  });
}

/**
 * Parse a recipient stealth meta-address into viewing and spending public keys.
 * Format: first 33 bytes = compressed viewing public key V, next 33 = compressed S.
 */
export function parseStealthMetaAddress(metaHex: Hex | string): {
  viewPubKey: Uint8Array;
  spendPubKey: Uint8Array;
} {
  const raw =
    typeof metaHex === "string" && metaHex.startsWith("0x")
      ? metaHex.slice(2)
      : metaHex;
  const bytes = hexToBytes(raw as string);
  if (bytes.length < 66)
    throw new Error("Invalid stealth meta-address: expected 66 bytes");
  return {
    viewPubKey: bytes.slice(0, 33),
    spendPubKey: bytes.slice(33, 66),
  };
}

// -----------------------------------------------------------------------------
// Sender: derive stealth address and view tag (DKSAP)
// -----------------------------------------------------------------------------

function sharedSecretSender(
  ephemeralPriv: Uint8Array,
  viewPubKey: Uint8Array
): Uint8Array {
  const P = CURVE.ProjectivePoint.fromHex(viewPubKey);
  const scalar = bytesToBigInt(ephemeralPriv) % CURVE.CURVE.n;
  if (scalar === 0n) throw new Error("Invalid ephemeral key");
  const sharedPoint = P.multiply(scalar);
  return sharedPoint.toRawBytes(true);
}

function hashSharedSecret(sharedSecret: Uint8Array): {
  sH: Uint8Array;
  viewTag: number;
} {
  const sH = keccak_256(sharedSecret);
  const viewTag = sH[0];
  return { sH, viewTag };
}

/**
 * Derive the stealth public key and address bytes from spending public key and hashed secret.
 * Returns the 20-byte stealth "address" (Keccak hash of uncompressed pubkey, EVM-compatible)
 * for scanner matching, plus the full stealth public key for Solana key derivation.
 */
function stealthPointAndAddress(
  spendPubKey: Uint8Array,
  sH: Uint8Array
): { stealthAddress: string; stealthPubKeyUncompressed: Uint8Array } {
  const n = CURVE.CURVE.n;
  const sHBig = bytesToBigInt(sH);
  const sHMod = sHBig % n;
  if (sHMod === 0n) throw new Error("Invalid scalar from hash");
  const S_h = CURVE.ProjectivePoint.BASE.multiply(sHMod);
  const P_spend = CURVE.ProjectivePoint.fromHex(spendPubKey);
  const P_stealth = P_spend.add(S_h);
  const uncompressed = P_stealth.toRawBytes(false);
  const hash = keccak_256(uncompressed.slice(1));
  const addrBytes = hash.slice(12);
  const addr = "0x" + bytesToHex(addrBytes);
  return { stealthAddress: addr, stealthPubKeyUncompressed: uncompressed };
}

/**
 * Sender-side: compute a one-time stealth address and view tag for a recipient.
 * The stealth address is returned as a hex string for scanner compatibility.
 */
export function computeStealthAddressAndViewTag(
  recipientMetaAddressHex: Hex | string
): {
  ephemeralPriv: Uint8Array;
  ephemeralPubKey: Uint8Array;
  stealthAddress: string;
  stealthSolanaAddress: string;
  viewTag: number;
  metadata: Uint8Array;
} {
  console.log("🔐 [Opaque] computeStealthAddressAndViewTag");
  const { viewPubKey, spendPubKey } = parseStealthMetaAddress(
    recipientMetaAddressHex as Hex
  );
  const ephemeralPriv = CURVE.utils.randomPrivateKey();
  const ephemeralPubKey = CURVE.getPublicKey(ephemeralPriv, true);

  const shared = sharedSecretSender(ephemeralPriv, viewPubKey);
  const { sH, viewTag } = hashSharedSecret(shared);
  const { stealthAddress, stealthPubKeyUncompressed } = stealthPointAndAddress(spendPubKey, sH);
  const stealthSolanaAddress = deriveStealthSolanaAddress(stealthPubKeyUncompressed);

  const metadata = new Uint8Array(1);
  metadata[0] = viewTag;

  console.log("🔐 [Opaque] Stealth address computed ✅", { stealth: stealthAddress.slice(0, 14) + "…", viewTag });
  return {
    ephemeralPriv,
    ephemeralPubKey,
    stealthAddress,
    stealthSolanaAddress,
    viewTag,
    metadata,
  };
}

/**
 * Rebuild announce() parameters for a manual ghost receive using the stored
 * ephemeral private key.
 */
export function buildGhostAnnouncementPayload(
  recipientMetaAddressHex: Hex | string,
  ephemeralPrivKeyHex: Hex | string
): {
  stealthAddress: string;
  ephemeralPubKey: Uint8Array;
  metadata: Uint8Array;
  viewTag: number;
} {
  const { viewPubKey, spendPubKey } = parseStealthMetaAddress(recipientMetaAddressHex as Hex);
  const h = (ephemeralPrivKeyHex as string).startsWith("0x")
    ? (ephemeralPrivKeyHex as string).slice(2)
    : ephemeralPrivKeyHex;
  const ephemeralPriv = hexToBytes(h as string);
  if (ephemeralPriv.length !== 32) {
    throw new Error("Ephemeral private key must be 32 bytes.");
  }
  const ephemeralPubKey = CURVE.getPublicKey(ephemeralPriv, true);
  const shared = sharedSecretSender(ephemeralPriv, viewPubKey);
  const { sH, viewTag } = hashSharedSecret(shared);
  const { stealthAddress } = stealthPointAndAddress(spendPubKey, sH);
  const metadata = new Uint8Array(1);
  metadata[0] = viewTag;
  return { stealthAddress, ephemeralPubKey, metadata, viewTag };
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2) throw new Error("Invalid hex length");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
  return x;
}

// -----------------------------------------------------------------------------
// Deterministic ephemeral key for the "Announcer" stealth signer
// -----------------------------------------------------------------------------

const ANNOUNCER_SALT = "opaque-announcer-v1";

/**
 * Deterministic ephemeral scalar for the "Announcer" stealth signer.
 */
export function deriveAnnouncerEphemeralKey(metaAddressHex: Hex | string): Uint8Array {
  const raw =
    typeof metaAddressHex === "string" && metaAddressHex.startsWith("0x")
      ? metaAddressHex.slice(2)
      : metaAddressHex;
  const seed = new TextEncoder().encode(raw + ANNOUNCER_SALT);
  const okm = hkdf(sha256, seed, undefined, "opaque-announcer-ephemeral", 32);
  const n = CURVE.CURVE.n;
  let scalar = bytesToBigInt(okm) % n;
  if (scalar === 0n) scalar = 1n;
  const out = new Uint8Array(32);
  let x = scalar;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * Format lamports as SOL (with appropriate precision).
 */
export function formatSol(lamports: bigint): string {
  const sol = Number(lamports) / 1e9;
  return sol.toFixed(9).replace(/\.?0+$/, "");
}

/**
 * Derive a deterministic one-time Solana destination from the stealth secp256k1 point.
 * This allows sender and recipient (who can reconstruct the same stealth point) to agree
 * on the same destination without leaking linkage through the recipient's main wallet key.
 */
function deriveStealthSolanaAddress(stealthPubKeyUncompressed: Uint8Array): string {
  return deriveStealthSolanaKeypair(stealthPubKeyUncompressed).publicKey.toBase58();
}

function deriveStealthSolanaKeypair(stealthPubKeyUncompressed: Uint8Array): Keypair {
  const domain = new TextEncoder().encode("opaque-solana-stealth-v1");
  const input = new Uint8Array(domain.length + stealthPubKeyUncompressed.length);
  input.set(domain, 0);
  input.set(stealthPubKeyUncompressed, domain.length);
  const seed = sha256(input);
  return Keypair.fromSeed(seed.slice(0, 32));
}

/**
 * Deterministically derive the same stealth Solana destination from a reconstructed
 * stealth private key (recipient side).
 */
export function deriveStealthSolanaAddressFromStealthPrivKey(
  stealthPrivKey: Uint8Array,
): string {
  const stealthPubKeyUncompressed = CURVE.getPublicKey(stealthPrivKey, false);
  return deriveStealthSolanaAddress(stealthPubKeyUncompressed);
}

/**
 * Derive the deterministic Solana keypair used to hold stealth funds from
 * a reconstructed secp256k1 stealth private key.
 */
export function deriveStealthSolanaKeypairFromStealthPrivKey(
  stealthPrivKey: Uint8Array,
): Keypair {
  const stealthPubKeyUncompressed = CURVE.getPublicKey(stealthPrivKey, false);
  return deriveStealthSolanaKeypair(stealthPubKeyUncompressed);
}
