#!/usr/bin/env bash
# Populate target/idl/ for `anchor test`.
#
# Anchor's post-test program-log step reads target/idl/<program>.json for every
# entry in [programs.localnet] and exits non-zero on a missing file. IDLs are
# built for the anchor-lang 0.32 programs; the two anchor-lang 0.30.1 programs
# (attestation-engine-v2, schema-registry) cannot compile the IDL generator
# under current rustc, so they get minimal stubs (used only for log labelling).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p target/idl

for p in stealth_registry stealth_announcer uab_receiver groth16_verifier reputation_verifier ons_mirror ons_registration; do
  anchor idl build -p "$p" -o "target/idl/$p.json"
done

stub() {
  cat > "target/idl/$1.json" <<EOF
{
  "address": "$2",
  "metadata": {
    "name": "$1",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Stub IDL (anchor-syn 0.30.1 cannot generate one; used only for anchor test log labelling)"
  },
  "instructions": [],
  "accounts": [],
  "types": []
}
EOF
}

stub schema_registry FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB
stub attestation_engine_v2 4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM

echo "target/idl populated:"
ls target/idl/
