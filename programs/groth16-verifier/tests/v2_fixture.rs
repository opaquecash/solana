//! V2 proof round-trip against the program's hard-coded verification key.
//!
//! The fixture in circuits/test/fixtures/v2/ (git submodule) is a real Groth16
//! proof generated with the production proving key. solana-bn254 falls back to
//! a native ark-bn254 implementation off-chain, so this exercises the exact
//! pairing path the program runs on-chain. If any VK_*_V2 constant drifted
//! from the circuit's verification_key.json, the pairing check would fail.

use groth16_verifier::verify_v2_raw;
use num_bigint::BigUint;
use serde_json::Value;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../circuits/test/fixtures/v2"
);

fn load(name: &str) -> Value {
    let path = format!("{FIXTURES}/{name}");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("cannot read {path}: {e} — run `git submodule update --init`")
    });
    serde_json::from_str(&data).unwrap()
}

/// Decimal field-element string → 32-byte big-endian.
fn be32(v: &Value) -> [u8; 32] {
    let n = BigUint::parse_bytes(v.as_str().unwrap().as_bytes(), 10).unwrap();
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// snarkjs G1 [x, y, "1"] → x || y
fn g1(v: &Value) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&be32(&v[0]));
    out[32..].copy_from_slice(&be32(&v[1]));
    out
}

/// snarkjs G2 [[c0, c1], [c0, c1], ...] → c1 || c0 per coordinate
/// (imaginary-first, matching the EVM pairing convention the program uses).
fn g2(v: &Value) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&be32(&v[0][1]));
    out[32..64].copy_from_slice(&be32(&v[0][0]));
    out[64..96].copy_from_slice(&be32(&v[1][1]));
    out[96..].copy_from_slice(&be32(&v[1][0]));
    out
}

fn fixture() -> ([u8; 64], [u8; 128], [u8; 64], [[u8; 32]; 4]) {
    let proof = load("proof.json");
    let public = load("public.json");
    let signals = [
        be32(&public[0]),
        be32(&public[1]),
        be32(&public[2]),
        be32(&public[3]),
    ];
    (g1(&proof["pi_a"]), g2(&proof["pi_b"]), g1(&proof["pi_c"]), signals)
}

#[test]
fn production_fixture_proof_verifies() {
    let (a, b, c, signals) = fixture();
    let ok = verify_v2_raw(a, b, c, &signals).expect("verification must not error");
    assert!(ok, "production fixture proof must verify against VK_*_V2");
}

#[test]
fn tampered_public_signal_is_rejected() {
    let (a, b, c, mut signals) = fixture();
    signals[3][31] ^= 1; // flip nullifier_hash
    let ok = verify_v2_raw(a, b, c, &signals).expect("verification must not error");
    assert!(!ok, "tampered public signal must not verify");
}

#[test]
fn swapped_proof_points_are_rejected() {
    let (a, b, c, signals) = fixture();
    // use C where A belongs (and vice versa) — must fail the pairing
    let ok = verify_v2_raw(c, b, a, &signals).expect("verification must not error");
    assert!(!ok, "mangled proof must not verify");
}

#[test]
fn out_of_field_signal_is_an_error() {
    let (a, b, c, mut signals) = fixture();
    signals[0] = [0xff; 32]; // ≥ r — must be rejected before any curve math
    assert!(verify_v2_raw(a, b, c, &signals).is_err());
}
