//! # Stealth Attestation Scanner
//!
//! Extends the EIP-5564 scanner to detect "Reputation Events" embedded in
//! announcement metadata. When the view-tag matches, the metadata is decoded
//! to extract an `attestation_id`. Matching announcements are collected so
//! the user can generate a ZK witness for the Circom circuit.

use alloy_primitives::Address;
use k256::{ecdsa::SigningKey, PublicKey};
use serde::{Deserialize, Serialize};

use crate::scanner::{
    check_announcement_view_tag, derive_stealth_address, StealthAddressError, ViewTagCheck,
};

// =============================================================================
// Attestation types
// =============================================================================

/// A discovered attestation tied to a stealth address announcement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAttestation {
    pub stealth_address: String,
    pub attestation_id: u64,
    pub tx_hash: String,
    pub block_number: u64,
    pub ephemeral_pubkey: Vec<u8>,
}

/// Aggregated reputation score for a specific trait requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub trait_id: String,
    pub matching_announcements: Vec<StealthAttestation>,
    pub total_count: u64,
}

// =============================================================================
// Metadata attestation encoding
// =============================================================================

/// Attestation metadata layout in announcement `metadata` field:
///   byte[0]    = view_tag (standard EIP-5564)
///   byte[1]    = 0xAT (attestation marker = 0xA7)
///   byte[2..10] = attestation_id (big-endian u64)
///
/// Remaining bytes are reserved for future extensions.
const ATTESTATION_MARKER: u8 = 0xA7;
const ATTESTATION_METADATA_MIN_LEN: usize = 10;

/// Extracts an attestation_id from announcement metadata, if present.
pub fn extract_attestation_id(metadata: &[u8]) -> Option<u64> {
    if metadata.len() < ATTESTATION_METADATA_MIN_LEN {
        return None;
    }
    if metadata[1] != ATTESTATION_MARKER {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&metadata[2..10]);
    Some(u64::from_be_bytes(buf))
}

/// Encodes an attestation_id into metadata format (view_tag must be set by caller at byte[0]).
pub fn encode_attestation_metadata(view_tag: u8, attestation_id: u64) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(ATTESTATION_METADATA_MIN_LEN);
    metadata.push(view_tag);
    metadata.push(ATTESTATION_MARKER);
    metadata.extend_from_slice(&attestation_id.to_be_bytes());
    metadata
}

// =============================================================================
// Attestation scanning
// =============================================================================

/// Raw announcement data from the chain/subgraph, before WASM boundary.
#[derive(Clone, Debug)]
pub struct RawAnnouncement {
    pub stealth_address: Address,
    pub view_tag: u8,
    pub ephemeral_pubkey: PublicKey,
    pub metadata: Vec<u8>,
    pub tx_hash: String,
    pub block_number: u64,
}

/// Scans a batch of announcements for attestations owned by this recipient.
///
/// Two-pass filter:
/// 1. View-tag pre-check (skip ~255/256 of announcements)
/// 2. Full stealth address derivation + attestation extraction
pub fn scan_for_attestations(
    announcements: &[RawAnnouncement],
    view_privkey: &SigningKey,
    spend_pubkey: &PublicKey,
) -> Result<Vec<StealthAttestation>, StealthAddressError> {
    let mut results = Vec::new();

    for ann in announcements {
        match check_announcement_view_tag(ann.view_tag, view_privkey, &ann.ephemeral_pubkey) {
            ViewTagCheck::NoMatch => continue,
            ViewTagCheck::PossibleMatch => {}
        }

        let (derived_addr, _) =
            derive_stealth_address(view_privkey, spend_pubkey, &ann.ephemeral_pubkey)?;

        if derived_addr != ann.stealth_address {
            continue;
        }

        if let Some(attestation_id) = extract_attestation_id(&ann.metadata) {
            let compressed = ann
                .ephemeral_pubkey
                .to_sec1_bytes()
                .to_vec();

            results.push(StealthAttestation {
                stealth_address: format!("{:#x}", ann.stealth_address),
                attestation_id,
                tx_hash: ann.tx_hash.clone(),
                block_number: ann.block_number,
                ephemeral_pubkey: compressed,
            });
        }
    }

    Ok(results)
}

/// Aggregates attestations matching a specific trait requirement.
///
/// For simple badge checks, `requirement` is a single attestation_id.
/// For threshold checks (e.g. "Total Volume > 5 ETH"), the caller should
/// pass all volume-type attestation IDs and the function counts matches.
pub fn aggregate_for_trait(
    attestations: &[StealthAttestation],
    trait_id: &str,
    required_attestation_ids: &[u64],
) -> ReputationSummary {
    let matching: Vec<StealthAttestation> = attestations
        .iter()
        .filter(|a| required_attestation_ids.contains(&a.attestation_id))
        .cloned()
        .collect();

    let total_count = matching.len() as u64;

    ReputationSummary {
        trait_id: trait_id.to_string(),
        matching_announcements: matching,
        total_count,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_attestation_metadata() {
        let view_tag = 0x42;
        let attestation_id = 12345u64;
        let encoded = encode_attestation_metadata(view_tag, attestation_id);
        assert_eq!(encoded[0], view_tag);
        assert_eq!(encoded[1], ATTESTATION_MARKER);
        let decoded = extract_attestation_id(&encoded).expect("should decode");
        assert_eq!(decoded, attestation_id);
    }

    #[test]
    fn short_metadata_returns_none() {
        assert!(extract_attestation_id(&[0x42]).is_none());
        assert!(extract_attestation_id(&[0x42, 0xA7]).is_none());
    }

    #[test]
    fn wrong_marker_returns_none() {
        let mut data = vec![0x42, 0xFF];
        data.extend_from_slice(&42u64.to_be_bytes());
        assert!(extract_attestation_id(&data).is_none());
    }
}
