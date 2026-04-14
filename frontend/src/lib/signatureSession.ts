type Hex = `0x${string}`;

type SignatureSessionRecord = {
  signatureHex: Hex;
  address: string;
  cluster: string;
  message: string;
  issuedAt: number;
  expiresAt: number;
};

const DATA_KEY = "opaque.signature.session.data.v1";
const AES_KEY_KEY = "opaque.signature.session.aes.v1";
const PREF_KEY = "opaque.signature.session.pref.v1";
const DEFAULT_TTL_MS = 30 * 60 * 1000; // 30 minutes

function normalizeWalletAddress(address: string): string {
  return address.startsWith("0x") ? address.toLowerCase() : address;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i] ?? 0);
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function getOrCreateAesKeyRaw(): Promise<Uint8Array | null> {
  if (typeof window === "undefined") return null;
  if (!window.crypto?.getRandomValues) return null;
  const existing = sessionStorage.getItem(AES_KEY_KEY);
  if (existing) return base64ToBytes(existing);
  const raw = new Uint8Array(32);
  window.crypto.getRandomValues(raw);
  sessionStorage.setItem(AES_KEY_KEY, bytesToBase64(raw));
  return raw;
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toArrayBuffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function setRememberSignaturePreference(remember: boolean): void {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(PREF_KEY, remember ? "1" : "0");
}

export function getRememberSignaturePreference(): boolean {
  if (typeof window === "undefined") return false;
  return sessionStorage.getItem(PREF_KEY) === "1";
}

export function clearSignatureSession(): void {
  if (typeof window === "undefined") return;
  sessionStorage.removeItem(DATA_KEY);
  sessionStorage.removeItem(AES_KEY_KEY);
  sessionStorage.removeItem(PREF_KEY);
}

export async function saveSignatureSession(params: {
  signatureHex: Hex;
  address: string;
  cluster: string;
  message: string;
  remember: boolean;
  ttlMs?: number;
}): Promise<void> {
  if (typeof window === "undefined") return;
  const { remember } = params;
  setRememberSignaturePreference(remember);
  if (!remember) {
    clearSignatureSession();
    return;
  }

  const rawKey = await getOrCreateAesKeyRaw();
  if (!rawKey) return;
  const aesKey = await importAesKey(rawKey);

  const now = Date.now();
  const record: SignatureSessionRecord = {
    signatureHex: params.signatureHex,
    address: normalizeWalletAddress(params.address),
    cluster: params.cluster,
    message: params.message,
    issuedAt: now,
    expiresAt: now + (params.ttlMs ?? DEFAULT_TTL_MS),
  };

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(record));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, aesKey, plaintext)
  );
  sessionStorage.setItem(
    DATA_KEY,
    JSON.stringify({
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
    })
  );
}

export async function loadSignatureSession(params: {
  address: string;
  cluster: string;
  message: string;
}): Promise<Hex | null> {
  if (typeof window === "undefined") return null;
  const rawPayload = sessionStorage.getItem(DATA_KEY);
  const rawKey = sessionStorage.getItem(AES_KEY_KEY);
  if (!rawPayload || !rawKey) return null;

  try {
    const parsed = JSON.parse(rawPayload) as { iv: string; ciphertext: string };
    const iv = base64ToBytes(parsed.iv);
    const ciphertext = base64ToBytes(parsed.ciphertext);
    const aesKey = await importAesKey(base64ToBytes(rawKey));
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(ciphertext)
    );
    const text = new TextDecoder().decode(new Uint8Array(decrypted));
    const record = JSON.parse(text) as SignatureSessionRecord;

    const expired = Date.now() > record.expiresAt;
    const addressMismatch = record.address !== normalizeWalletAddress(params.address);
    const clusterMismatch = record.cluster !== params.cluster;
    const messageMismatch = record.message !== params.message;
    if (expired || addressMismatch || clusterMismatch || messageMismatch) {
      clearSignatureSession();
      return null;
    }
    return record.signatureHex;
  } catch {
    clearSignatureSession();
    return null;
  }
}

