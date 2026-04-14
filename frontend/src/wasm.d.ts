/**
 * Type declaration for the WASM module loaded via Vite alias @wasm/cryptography.js
 */
declare module '@wasm/cryptography.js' {
  /** Async init (loads .wasm); call this before using any other exports */
  export default function init(module_or_path?: unknown): Promise<unknown>;
  export function initSync(module: unknown): unknown;
  export function derive_stealth_address_wasm(
    view_privkey_bytes: Uint8Array,
    spend_pubkey_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ): { stealthAddress: string; viewTag: number };
  export function check_announcement_wasm(
    announcement_stealth_address: string,
    view_tag: number,
    view_privkey_bytes: Uint8Array,
    spend_pubkey_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ): boolean;
  export function check_announcement_view_tag_wasm(
    view_tag: number,
    view_privkey_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ): string;
  export function reconstruct_signing_key_wasm(
    master_spend_priv_bytes: Uint8Array,
    master_view_priv_bytes: Uint8Array,
    ephemeral_pubkey_bytes: Uint8Array
  ): Uint8Array;
}
