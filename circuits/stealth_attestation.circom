pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/escalarmulany.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/mux1.circom";

// =============================================================================
// Stealth Attestation Circuit — Opaque Cash
//
// Proves ownership of a "Ghost Address" and validity of an attestation
// without revealing the address. Uses BabyJubJub + Poseidon for on-chain
// efficiency. Compatible with Groth16.
//
// Private inputs:
//   - stealth_private_key    (scalar on BabyJubJub)
//   - ephemeral_pubkey       (point on BabyJubJub, [x, y])
//   - announcement_attestation_id (the attestation_id stored in the announcement leaf)
//   - merkle_path_elements   (sibling hashes for Merkle inclusion proof)
//   - merkle_path_indices    (0/1 direction bits for each level)
//
// Public inputs:
//   - merkle_root            (root of the announcement Merkle tree)
//   - attestation_id         (the badge ID being proven, e.g. "")
//   - external_nullifier     (action-scoped nonce: vote ID, loan app ID, etc.)
//
// Outputs:
//   - nullifier              (Poseidon(stealth_private_key, external_nullifier))
//   - is_valid               (1 if all checks pass, 0 otherwise)
// =============================================================================

template StealthAttestation(TREE_DEPTH) {
    // --- Public inputs ---
    signal input merkle_root;
    signal input attestation_id;
    signal input external_nullifier;

    // --- Private inputs ---
    signal input stealth_private_key;
    signal input ephemeral_pubkey[2]; // BabyJubJub point (x, y)
    signal input announcement_attestation_id;
    signal input merkle_path_elements[TREE_DEPTH];
    signal input merkle_path_indices[TREE_DEPTH];

    // --- Outputs ---
    signal output nullifier;
    signal output is_valid;

    // =========================================================================
    // Step 1: Derive the stealth public key from the private key
    //         P_stealth = stealth_private_key * G  (BabyJubJub base point)
    // =========================================================================
    component privToBits = Num2Bits(253);
    privToBits.in <== stealth_private_key;

    // BabyJubJub base point (generator)
    var BASE_X = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var BASE_Y = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    component scalarMul = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        scalarMul.e[i] <== privToBits.out[i];
    }
    scalarMul.p[0] <== BASE_X;
    scalarMul.p[1] <== BASE_Y;

    signal stealth_pubkey_x <== scalarMul.out[0];
    signal stealth_pubkey_y <== scalarMul.out[1];

    // =========================================================================
    // Step 2: Compute shared secret via ECDH
    //         S = stealth_private_key * ephemeral_pubkey
    // =========================================================================
    component ecdh = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        ecdh.e[i] <== privToBits.out[i];
    }
    ecdh.p[0] <== ephemeral_pubkey[0];
    ecdh.p[1] <== ephemeral_pubkey[1];

    signal shared_secret_x <== ecdh.out[0];
    signal shared_secret_y <== ecdh.out[1];

    // =========================================================================
    // Step 3: Derive stealth address commitment from shared secret
    //         address_hash = Poseidon(shared_secret_x, shared_secret_y,
    //                                 stealth_pubkey_x, stealth_pubkey_y)
    // =========================================================================
    component addressHash = Poseidon(4);
    addressHash.inputs[0] <== shared_secret_x;
    addressHash.inputs[1] <== shared_secret_y;
    addressHash.inputs[2] <== stealth_pubkey_x;
    addressHash.inputs[3] <== stealth_pubkey_y;

    signal stealth_address_commitment <== addressHash.out;

    // =========================================================================
    // Step 4: Compute announcement leaf
    //         leaf = Poseidon(stealth_address_commitment, announcement_attestation_id)
    // =========================================================================
    component leafHash = Poseidon(2);
    leafHash.inputs[0] <== stealth_address_commitment;
    leafHash.inputs[1] <== announcement_attestation_id;

    signal leaf <== leafHash.out;

    // =========================================================================
    // Step 5: Verify Merkle inclusion proof
    //         Walk from leaf to root using path elements and direction indices
    // =========================================================================
    component merkleHashers[TREE_DEPTH];
    component muxLeft[TREE_DEPTH];
    component muxRight[TREE_DEPTH];

    signal computed_path[TREE_DEPTH + 1];
    computed_path[0] <== leaf;

    for (var i = 0; i < TREE_DEPTH; i++) {
        // Constrain path indices to be binary
        merkle_path_indices[i] * (1 - merkle_path_indices[i]) === 0;

        // Select left/right inputs based on direction
        muxLeft[i] = Mux1();
        muxLeft[i].c[0] <== computed_path[i];
        muxLeft[i].c[1] <== merkle_path_elements[i];
        muxLeft[i].s <== merkle_path_indices[i];

        muxRight[i] = Mux1();
        muxRight[i].c[0] <== merkle_path_elements[i];
        muxRight[i].c[1] <== computed_path[i];
        muxRight[i].s <== merkle_path_indices[i];

        merkleHashers[i] = Poseidon(2);
        merkleHashers[i].inputs[0] <== muxLeft[i].out;
        merkleHashers[i].inputs[1] <== muxRight[i].out;

        computed_path[i + 1] <== merkleHashers[i].out;
    }

    // =========================================================================
    // Step 6: Check Merkle root matches
    // =========================================================================
    component rootCheck = IsEqual();
    rootCheck.in[0] <== computed_path[TREE_DEPTH];
    rootCheck.in[1] <== merkle_root;

    signal root_valid <== rootCheck.out;

    // =========================================================================
    // Step 7: Check attestation_id matches
    //         Verify the announcement's attestation matches the claimed badge
    // =========================================================================
    component attestCheck = IsEqual();
    attestCheck.in[0] <== announcement_attestation_id;
    attestCheck.in[1] <== attestation_id;

    signal attest_valid <== attestCheck.out;

    // =========================================================================
    // Step 8: Generate Sybil-resistant nullifier
    //         nullifier = Poseidon(stealth_private_key, external_nullifier)
    //         Same key + same action => same nullifier (prevents double-claims)
    // =========================================================================
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== stealth_private_key;
    nullifierHash.inputs[1] <== external_nullifier;

    nullifier <== nullifierHash.out;

    // =========================================================================
    // Step 9: Combine validity checks
    //         is_valid = root_valid AND attest_valid
    // =========================================================================
    is_valid <== root_valid * attest_valid;
}

// Instantiate with tree depth 20 (~1M announcements capacity)
component main {public [merkle_root, attestation_id, external_nullifier]} = StealthAttestation(20);
