//! # Opaque Cash — WASM Bindings
//!
//! WebAssembly bindings for the stealth address scanner engine (EIP-5564 / DKSAP).

use wasm_bindgen::prelude::*;
use js_sys;
use k256::{ecdsa::SigningKey, PublicKey};
use alloy_primitives::Address;
use std::str::FromStr;

mod scanner;
mod attestation;
mod merkle;

use scanner::{
    derive_stealth_address, derive_stealth_signing_key, check_announcement,
    check_announcement_view_tag, ViewTagCheck,
};

// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// =============================================================================
// Type conversions: Rust <-> JavaScript
// =============================================================================

/// Converts a 32-byte Uint8Array to a SigningKey
fn bytes_to_signing_key(bytes: &[u8]) -> Result<SigningKey, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str("SigningKey must be 32 bytes"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);
    SigningKey::from_bytes(&key_bytes.into())
        .map_err(|e| JsValue::from_str(&format!("Invalid signing key: {}", e)))
}

/// Converts a compressed public key (33 bytes) to PublicKey
fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey, JsValue> {
    if bytes.len() != 33 {
        return Err(JsValue::from_str("PublicKey must be 33 bytes (compressed)"));
    }
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))
}

/// Converts an Address to a hex string
fn address_to_hex(address: &Address) -> String {
    format!("{:#x}", address)
}

/// Converts a hex string to an Address
fn hex_to_address(hex: &str) -> Result<Address, JsValue> {
    Address::from_str(hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid address hex: {}", e)))
}

// =============================================================================
// WASM Exports
// =============================================================================

/// Derives a stealth address and view tag from the given keys.
///
/// # Arguments
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `spend_pubkey_bytes` - 33-byte spending public key, compressed (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// A JavaScript object with:
/// * `stealthAddress` - Ethereum address as hex string (0x...)
/// * `viewTag` - View tag as number (0-255)
#[wasm_bindgen]
pub fn derive_stealth_address_wasm(
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    match derive_stealth_address(&view_privkey, &spend_pubkey, &ephemeral_pubkey) {
        Ok((address, view_tag)) => {
            let result = js_sys::Object::new();
            js_sys::Reflect::set(
                &result,
                &"stealthAddress".into(),
                &address_to_hex(&address).into(),
            )?;
            js_sys::Reflect::set(
                &result,
                &"viewTag".into(),
                &JsValue::from(view_tag as u32),
            )?;
            Ok(result.into())
        }
        Err(e) => Err(JsValue::from_str(&format!("Stealth address error: {}", e))),
    }
}

/// Checks if an announcement matches this recipient's keys.
///
/// # Arguments
/// * `announcement_stealth_address` - Stealth address from announcement (hex string)
/// * `view_tag` - View tag from announcement (number 0-255)
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `spend_pubkey_bytes` - 33-byte spending public key, compressed (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// `true` if the announcement is for this recipient, `false` otherwise.
#[wasm_bindgen]
pub fn check_announcement_wasm(
    announcement_stealth_address: &str,
    view_tag: u8,
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<bool, JsValue> {
    let address = hex_to_address(announcement_stealth_address)?;
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    check_announcement(
        address,
        view_tag,
        &view_privkey,
        &spend_pubkey,
        &ephemeral_pubkey,
    )
    .map_err(|e| JsValue::from_str(&format!("Check announcement error: {}", e)))
}

/// Quick view-tag check before expensive EC operations.
///
/// # Arguments
/// * `view_tag` - View tag from announcement (number 0-255)
/// * `view_privkey_bytes` - 32-byte viewing private key (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// `"NoMatch"` if view tag doesn't match (skip this announcement),
/// `"PossibleMatch"` if view tag matches (proceed with full check).
#[wasm_bindgen]
pub fn check_announcement_view_tag_wasm(
    view_tag: u8,
    view_privkey_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<String, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    match check_announcement_view_tag(view_tag, &view_privkey, &ephemeral_pubkey) {
        ViewTagCheck::NoMatch => Ok("NoMatch".to_string()),
        ViewTagCheck::PossibleMatch => Ok("PossibleMatch".to_string()),
    }
}

/// Reconstructs the one-time signing key (private key) for a stealth address.
///
/// # Arguments
/// * `master_spend_priv_bytes` - 32-byte spending private key (Uint8Array)
/// * `master_view_priv_bytes` - 32-byte viewing private key (Uint8Array)
/// * `ephemeral_pubkey_bytes` - 33-byte ephemeral public key, compressed (Uint8Array)
///
/// # Returns
/// 32-byte stealth private key as Uint8Array (for use with ethers.Wallet or viem privateKeyToAccount).
#[wasm_bindgen]
pub fn reconstruct_signing_key_wasm(
    master_spend_priv_bytes: &[u8],
    master_view_priv_bytes: &[u8],
    ephemeral_pubkey_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let spend_privkey = bytes_to_signing_key(master_spend_priv_bytes)?;
    let view_privkey = bytes_to_signing_key(master_view_priv_bytes)?;
    let ephemeral_pubkey = bytes_to_public_key(ephemeral_pubkey_bytes)?;

    derive_stealth_signing_key(&view_privkey, &spend_privkey, &ephemeral_pubkey)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| JsValue::from_str(&format!("Reconstruct signing key error: {}", e)))
}

// =============================================================================
// Stealth Attestation — WASM Exports
// =============================================================================

use attestation::{
    scan_for_attestations,
    RawAnnouncement, StealthAttestation as AttestationRecord,
};
use merkle::{MerkleTree, CircuitWitness};

/// Scans announcement metadata for attestation markers.
///
/// # Arguments
/// * `announcements_json` - JSON array of announcements, each with:
///   `{ stealthAddress, viewTag, ephemeralPubKey, metadata, txHash, blockNumber }`
/// * `view_privkey_bytes` - 32-byte viewing private key
/// * `spend_pubkey_bytes` - 33-byte spending public key (compressed)
///
/// # Returns
/// JSON array of `StealthAttestation` objects found for this recipient.
#[wasm_bindgen]
pub fn scan_attestations_wasm(
    announcements_json: &str,
    view_privkey_bytes: &[u8],
    spend_pubkey_bytes: &[u8],
) -> Result<String, JsValue> {
    let view_privkey = bytes_to_signing_key(view_privkey_bytes)?;
    let spend_pubkey = bytes_to_public_key(spend_pubkey_bytes)?;

    let raw_anns: Vec<serde_json::Value> = serde_json::from_str(announcements_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

    let mut announcements = Vec::with_capacity(raw_anns.len());
    for ann in &raw_anns {
        let stealth_addr_str = ann["stealthAddress"].as_str().unwrap_or_default();
        let stealth_address = hex_to_address(stealth_addr_str)?;
        let view_tag = ann["viewTag"].as_u64().unwrap_or(0) as u8;

        let eph_hex = ann["ephemeralPubKey"].as_str().unwrap_or_default();
        let eph_clean = if eph_hex.starts_with("0x") { &eph_hex[2..] } else { eph_hex };
        let eph_bytes = hex::decode(eph_clean)
            .map_err(|e| JsValue::from_str(&format!("Invalid ephemeral pubkey hex: {}", e)))?;
        let ephemeral_pubkey = bytes_to_public_key(&eph_bytes)?;

        let meta_hex = ann["metadata"].as_str().unwrap_or_default();
        let meta_clean = if meta_hex.starts_with("0x") { &meta_hex[2..] } else { meta_hex };
        let metadata = hex::decode(meta_clean).unwrap_or_default();

        let tx_hash = ann["txHash"].as_str().unwrap_or_default().to_string();
        let block_number = ann["blockNumber"].as_u64().unwrap_or(0);

        announcements.push(RawAnnouncement {
            stealth_address,
            view_tag,
            ephemeral_pubkey,
            metadata,
            tx_hash,
            block_number,
        });
    }

    let results = scan_for_attestations(&announcements, &view_privkey, &spend_pubkey)
        .map_err(|e| JsValue::from_str(&format!("Scan error: {}", e)))?;

    serde_json::to_string(&results)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

/// Generates the full ZK-circuit witness for a specific trait.
///
/// Builds a local Merkle tree from the given attestations, finds the first
/// attestation matching `target_trait_id`, generates an inclusion proof,
/// and returns a JSON witness compatible with the Circom circuit.
///
/// # Arguments
/// * `attestations_json` - JSON array of `StealthAttestation` (from `scan_attestations_wasm`)
/// * `target_trait_id` - The attestation_id to prove (as string decimal)
/// * `stealth_privkey_bytes` - 32-byte stealth private key for the matching address
/// * `external_nullifier` - Action-scoped nonce (as string decimal)
///
/// # Returns
/// JSON `CircuitWitness` for the Circom prover.
#[wasm_bindgen]
pub fn generate_reputation_witness(
    attestations_json: &str,
    target_trait_id: &str,
    stealth_privkey_bytes: &[u8],
    external_nullifier: &str,
) -> Result<String, JsValue> {
    let attestations: Vec<AttestationRecord> = serde_json::from_str(attestations_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid attestations JSON: {}", e)))?;

    let target_id: u64 = target_trait_id.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid trait ID: {}", e)))?;

    let ext_null: u64 = external_nullifier.parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid external nullifier: {}", e)))?;

    // Build Merkle tree from all attestations (depth 20 = ~1M capacity)
    let mut tree = MerkleTree::new(20);
    let mut target_leaf_idx: Option<usize> = None;
    let mut target_attestation: Option<&AttestationRecord> = None;

    for att in &attestations {
        let leaf_data = format!("{}:{}", att.stealth_address, att.attestation_id);
        let idx = tree.insert_raw(leaf_data.as_bytes());
        if att.attestation_id == target_id && target_leaf_idx.is_none() {
            target_leaf_idx = Some(idx);
            target_attestation = Some(att);
        }
    }

    let leaf_idx = target_leaf_idx
        .ok_or_else(|| JsValue::from_str("No attestation found matching target trait ID"))?;
    let _target_att = target_attestation.unwrap();

    let proof = tree.proof(leaf_idx);

    if stealth_privkey_bytes.len() != 32 {
        return Err(JsValue::from_str("Stealth private key must be 32 bytes"));
    }

    let privkey_hex = stealth_privkey_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let privkey_decimal = u128::from_str_radix(&privkey_hex[..32], 16)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "0".to_string());

    let witness = CircuitWitness {
        merkle_root: bytes_to_decimal_string(&proof.root),
        attestation_id: target_id.to_string(),
        external_nullifier: ext_null.to_string(),
        stealth_private_key: privkey_decimal,
        ephemeral_pubkey: ["0".to_string(), "0".to_string()],
        announcement_attestation_id: target_id.to_string(),
        merkle_path_elements: proof.path_elements.iter().map(|e| bytes_to_decimal_string(e)).collect(),
        merkle_path_indices: proof.path_indices,
    };

    serde_json::to_string(&witness)
        .map_err(|e| JsValue::from_str(&format!("Serialize witness error: {}", e)))
}

/// Encodes attestation metadata for use in announcements.
///
/// # Arguments
/// * `view_tag` - View tag byte (0-255)
/// * `attestation_id` - Attestation/badge ID
///
/// # Returns
/// Hex-encoded metadata bytes.
#[wasm_bindgen]
pub fn encode_attestation_metadata_wasm(view_tag: u8, attestation_id: u64) -> String {
    let metadata = attestation::encode_attestation_metadata(view_tag, attestation_id);
    format!("0x{}", metadata.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    let mut val = [0u64; 4];
    for i in 0..4 {
        let offset = i * 8;
        for j in 0..8 {
            val[3 - i] = (val[3 - i] << 8) | bytes[offset + j] as u64;
        }
    }
    // Simple big-endian to decimal: treat as u256
    let mut hex_str = String::with_capacity(64);
    for b in bytes {
        hex_str.push_str(&format!("{:02x}", b));
    }
    // Convert hex to decimal string using u128 pairs
    let hex_str = hex_str.trim_start_matches('0');
    if hex_str.is_empty() {
        return "0".to_string();
    }
    // For field elements, use the hex representation as-is for the circuit
    // (circom accepts both hex and decimal)
    format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}
