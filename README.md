<div align="center">

```
╔══════════════════════════════════════════════════════╗
║                                                      ║
║    ██████╗ ██████╗  █████╗  ██████╗ ██╗   ██╗███████╗║
║   ██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔════╝║
║   ██║   ██║██████╔╝███████║██║   ██║██║   ██║█████╗  ║
║   ██║   ██║██╔═══╝ ██╔══██║██║▄▄ ██║██║   ██║██╔══╝  ║
║   ╚██████╔╝██║     ██║  ██║╚██████╔╝╚██████╔╝███████╗║
║    ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝  ╚═════╝ ╚══════╝║
║                                                      ║
╚══════════════════════════════════════════════════════╝
```

### *Private payments. Provable reputation. Zero exposure.*

**The first full-stack stealth address protocol on Solana — with on-chain ZK reputation.**

<br/>

[![CI](https://github.com/opaquecash/solana/actions/workflows/solana-programs.yml/badge.svg)](https://github.com/opaquecash/solana/actions/workflows/solana-programs.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-5c7cfa?style=flat-square)](https://opensource.org/licenses/MIT)
[![Solana Devnet](https://img.shields.io/badge/network-Solana%20Devnet-9945ff?style=flat-square)](https://solana.opaque.cash)
[![Live App](https://img.shields.io/badge/app-live-00c48c?style=flat-square)](https://solana.opaque.cash)
[![Demo](https://img.shields.io/badge/demo-YouTube-ff0000?style=flat-square)](https://youtu.be/s2XDjNAAk4Q)

[**Live App**](https://solana.opaque.cash) · [**GitHub**](https://github.com/collinsadi/opaque-solana) · [**Watch Demo**](https://youtu.be/s2XDjNAAk4Q) · [**Ethereum Version**](https://github.com/collinsadi/opaque) · [**Demo Attestation Gated App**](https://sol-demo.opaque.cash)


</div>

---

## The Problem Nobody Talks About Enough

Your Solana wallet is a glass house.

Every address you've ever sent to, every protocol you've ever touched, every balance you hold — it's all permanent, immutable, and publicly searchable by anyone with a browser. There is no incognito mode. There is no "close tab." Your entire on-chain history follows your wallet address like a shadow.

This isn't a hypothetical concern. It's a design flaw with real-world consequences — and Solana users have paid dearly for it.

### The Incidents That Prove the Problem Is Real

**August 2022 — The Slope Wallet Breach:** Hackers drained over **9,200 Solana wallets** and stole between $4.5M–$8M in SOL and tokens. The attack exploited a telemetry server that had been silently logging users' seed phrases in plaintext. Once attackers obtained those keys, the fully public nature of Solana meant they could surgically identify and drain every linked wallet with mechanical precision. The transparent ledger became a treasure map.

**November 2024 — The DEXX Hack:** The popular memecoin trading terminal suffered a catastrophic private key leak that exposed **at least 900 unique users** and drained an estimated **$30 million** in assets. SlowMist identified over 8,620 Solana addresses linked to the hacker. One individual lost over $1 million. Because all wallet activity is public, the attacker could observe balances, identify the most valuable targets, and prioritize which wallets to drain first. Transparency turned into a targeting system.

**December 2024 — The @solana/web3.js Supply Chain Attack:** Attackers compromised the npm publish credentials for `@solana/web3.js` — a library downloaded over 600,000 times per week — and deployed malicious versions designed to exfiltrate private keys from any dApp that handled them. The attack was sophisticated precisely because Solana's transparency made it easy to monitor which wallets were interacting with affected dApps and where the drained funds went.

The pattern is clear: **transparency without privacy tools turns every hack into a precision strike.** Victims don't just lose funds — they lose anonymity, and attackers use the public ledger as a targeting layer.

Opaque was built to change that.

---

## What Opaque Does

Opaque is an **open protocol for unlinkable payments and proof-backed reputation on Solana**. It has two core primitives:

**1. Stealth Payments** — Every transaction lands at a fresh, one-time address that only the recipient controls. Send or receive SOL without leaving a traceable link between sender and recipient on-chain. No one watching the blockchain can connect your payments to your identity.

**2. Programmable Stealth Reputation (PSR)** — When trust needs to be established, the protocol lets you prove things about yourself — "I passed KYC," "I'm an early adopter," "this account is in good standing" — using Groth16 zero-knowledge proofs. The verifier learns only what you choose to reveal. Your wallet, your other traits, your transaction history: all remain private.

Together, these two layers mean you can transact privately *and* still be trusted — without ever linking your real identity to any on-chain action.

---

## How It Works

### Stealth Payments — The DKSAP Protocol

Opaque implements the **Dual-Key Stealth Address Protocol (DKSAP)**, the same cryptographic standard that powers EIP-5564 on Ethereum, adapted natively for Solana.

```
Recipient                                         Sender
─────────                                         ──────
Generates:  viewing key (v) + spending key (s)
Publishes:  meta-address  →  V ∥ S
                                                  Picks random ephemeral key (r)
                                                  Computes shared secret:  s = r · V
                                                  Hashes:  sH = Keccak256(s)
                                                  View tag:  sH[0]  (1 byte)
                                                  Stealth pubkey:  P = S + sH · G
                                                  Derives Solana address from P
                                                  Sends SOL → stealth address
                                                  Announces: (ephemeral_pub, view_tag)

Scanner skips 99.6% of announcements via view tag
Computes: s = v · R  (same shared secret)
Derives stealth address — it matches ✓
Reconstructs spending key: p = s + sH
Sweeps funds to main wallet ✓
```

**Key insight:** The scanner never needs a server. It runs as a Rust-compiled WASM module directly in your browser. View tags let it skip ~99.6% of all announcements without expensive elliptic curve math, making scanning fast enough to run client-side in real time.

### Private Reputation — The PSR System

Most reputation systems fail at privacy: they require you to link your verified identity to your on-chain wallet. Opaque's Programmable Stealth Reputation (PSR) breaks this constraint. You prove you hold a credential — without revealing which address holds it, which wallet you control, or anything else about your on-chain history.

#### How It Works End-to-End

```
Step 1 — Issuance
──────────────────
Issuer creates a Schema on-chain (e.g. "KYC Verified", "DAO Contributor",
"Credit Score > 700"). The schema defines what fields the attestation contains
and whether it is revocable.

Issuer calls IssueAttestation with:
  • recipient = keccak256(stealth_address)   ← never links to a wallet
  • field data (ABI-encoded per schema)
  • optional expiry slot

Issuer also broadcasts an encrypted announcement on the StealthAnnouncer
program with a V2 metadata marker (0xB2) that embeds:
  • view tag (1 byte) — lets the recipient's scanner skip 99.6% of noise
  • schema ID, issuer pubkey, attestation UID, random nonce

Step 2 — Discovery
───────────────────
Recipient's WASM scanner (running in-browser, no server) loads all
announcements, applies view-tag filtering, and re-derives stealth keys.
For matching announcements with the 0xB2 marker, the scanner extracts
the attestation metadata and surfaces the trait in the "My Traits" tab.
The trait includes the Merkle leaf preimage needed for ZK proof generation.

Step 3 — Proof Generation
──────────────────────────
When the recipient wants to prove a trait to a verifier (e.g. a DeFi
protocol gating access), they:

  1. Build the Merkle witness locally (browser, no server):
       leaf = Poseidon(stealth_pk_field, schema_id, issuer_pk_x,
                       trait_data_hash, nonce_field)
  2. Compute nullifier:
       nullifier = Poseidon(stealth_private_key, external_nullifier)
       (external_nullifier is provided by the verifying protocol)
  3. Run snarkjs Groth16 prover in-browser using the compiled circuit
  4. Get back a 256-byte proof + public signals

Step 4 — On-Chain Verification
────────────────────────────────
Recipient submits the proof to the OpaqueReputationVerifier program:

  Verifier checks:
    ✓ Merkle root matches the on-chain registry (attestation exists)
    ✓ Schema is not deprecated and not expired
    ✓ Nullifier has not been consumed (prevents replay attacks)
    ✓ Groth16 proof is valid — via CPI to the Groth16Verifier program
       which uses Solana's native alt_bn128 syscalls for BN254 pairing

  On success:
    • Nullifier stored on-chain (Sybil resistance)
    • ReputationVerified event emitted ✓

What's public:   attestation schema ID, nullifier hash, verification result
What's private:  your wallet, your stealth address, all other traits,
                 the issuer's knowledge of which wallet you control
```

#### Security Model

**What an attacker sees on-chain:**
- A schema PDA with a field definition and an authority pubkey
- An attestation PDA with a keccak256 hash (no address, no identity)
- An announcement with an encrypted ephemeral key and scrambled metadata
- A nullifier hash when you verify (reveals nothing about who you are)

**What an attacker cannot derive:**
- Which wallet received an attestation (the hash reveals nothing without the stealth key)
- Which stealth address you control (DKSAP ensures only you can scan your announcements)
- Whether two verifications were made by the same person (each nullifier uses the verifier's external nullifier — cross-protocol linkage is cryptographically prevented)
- Any other traits you hold (proof reveals only the requested schema)

**Cryptographic guarantees:**
- **Binding:** You cannot forge an attestation — the Merkle leaf commits to the actual issuer pubkey and the on-chain schema authority is verified
- **Soundness:** The Groth16 circuit enforces that the nullifier was derived from the actual stealth private key, not a fabricated one
- **Zero-knowledge:** snarkjs Groth16 on BN254 provides computational zero-knowledge — the proof reveals nothing beyond "this person holds a valid attestation under schema X"
- **Replay prevention:** Nullifiers are consumed on-chain. The same credential cannot be used twice for the same external nullifier
- **Revocation:** Issuers can revoke attestations. The on-chain revocationSlot field is checked by the verifier before accepting a proof

**Trust assumptions:**
- The issuer is trusted to issue accurate attestations (this is the same trust model as any credential system — e.g. a KYC provider, DAO governance, employer)
- The ZK proving key was generated with a trusted setup ceremony (powers of tau)
- Solana consensus is not compromised (standard on-chain assumption)

#### Why This Matters

Without PSR, the only way to prove reputation on Solana is to reveal your wallet — permanently linking your identity to every transaction you've ever made. This creates a paradox: the more reputation you build, the more exposed you become.

PSR breaks this paradox. You accumulate credentials privately, under stealth addresses. You reveal only what you choose, when you choose, to the specific protocol that needs it. The proof is mathematically binding — the verifier gets the same confidence as a public wallet check, without any of the privacy cost.

This is the missing primitive for DeFi compliance, private DAO governance, privacy-preserving KYC, and any system where trust must be established without surveillance.

---

## Real-World Use Cases

### 1. Private Payroll & Business Payments
A startup paying contractors in SOL doesn't want competitors analyzing their wallet to reverse-engineer team size, burn rate, or vendor relationships. With Opaque, the company registers its meta-address. Contractors send invoices tied to stealth addresses. Every payment is unlinkable — the ledger shows a transfer to a one-time address, not to a known contractor wallet.

### 2. Confidential DAO Contributions
A contributor to a DAO shouldn't have their governance votes, treasury contributions, and grant applications forever linked to one deanonymized wallet. Using Opaque, they operate from stealth addresses. When reputation matters — "has this contributor been active for 6+ months?" — they generate a ZK proof of the relevant attestation without revealing which address holds it.

### 3. Protected NFT Collectors
High-value NFT collectors on Solana are targets. A wallet holding rare assets is a target for social engineering, sim-swapping, and phishing. Receiving future purchases through stealth addresses breaks the link between a collector's public identity and their growing holdings.

### 4. Compliant Privacy for Enterprises
An enterprise onboarding employees onto Solana needs to verify KYC without publishing a ledger of verified wallets. PSR lets a compliance provider issue attestations to stealth addresses. Employees prove compliance to gated DeFi protocols with a ZK proof — without linking their verified identity to an on-chain history.

### 5. Whistleblower & Journalist Funding
Journalists or human rights organizations in high-risk regions can receive funding via stealth addresses. Donors can prove they're legitimate contributors (not sanctioned entities) via ZK attestations — without their identity or contribution amounts becoming traceable on-chain.

### 6. Ghost Address Generation
Need a one-time address for a single interaction — an airdrop, a test, a private sale — without broadcasting anything on-chain? Opaque's Ghost Address mode generates offline one-time addresses with no announcement, no on-chain footprint at all. Local-only, instant, and fully unlinkable.

---

## Why Solana Needs This Now

The privacy landscape on Solana has been a graveyard of pivots.

**Elusiv** — the ecosystem's leading privacy protocol — announced it was shutting down on February 29, 2024, moving into withdrawal-only mode. It used shared pools for private transfers, meaning all private activity was still funneled through a common shielded pool that required trust in the protocol itself. More critically, it had no stealth address standard and no reputation layer. When the team pivoted to building Arcium (a broader encrypted computing network), Solana lost its primary privacy option.

**Light Protocol** — which brought a UTXO model and ZK execution to Solana — similarly pivoted in early 2024, redirecting its ZK infrastructure toward compression and scaling rather than privacy. Another promising privacy primitive, gone from the space.

The Solana privacy ecosystem has a persistent pattern: projects build useful primitives, then abandon them. This leaves users with no durable, open, composable standard to build on.

**Opaque is different for three reasons:**

1. **It's a protocol, not a product.** The stealth meta-address registry and announcer are open Anchor programs. Any dApp can integrate them. Any wallet can build on top. There's no central team to pivot or shut down.

2. **It has a standard.** By mirroring ERC-6538 and EIP-5564, Opaque introduces the first inter-operable stealth address standard to Solana — with cross-chain scanner compatibility built in.

3. **It goes beyond payments.** Neither Elusiv nor Light Protocol ever built a reputation layer. PSR is unique: it lets you be private *and* trusted — the missing combination for any serious DeFi or compliance use case.

---

## Landscape Comparison

| | **Opaque** | **Elusiv (sunset 2024)** | **Light Protocol (pivoted 2024)** |
|:---|:---:|:---:|:---:|
| Stealth addresses (per-tx unlinkability) | ✅ Full DKSAP | ❌ Shared pool model | ❌ UTXO model, no stealth |
| Registry standard (ERC-6538 equivalent) | ✅ | ❌ | ❌ |
| View tags (efficient scanning) | ✅ 99.6% skip rate | ❌ | ❌ |
| Client-side WASM scanner | ✅ No server needed | ❌ Centralized relayer | ❌ |
| Ghost addresses (offline, no announcement) | ✅ | ❌ | ❌ |
| ZK reputation layer (PSR) | ✅ On-chain Groth16 | ❌ | ❌ |
| Nullifier-based Sybil resistance | ✅ | ❌ | ❌ |
| On-chain ZK verifier | ✅ BN254 via alt_bn128 | ❌ | ❌ |
| Cross-chain scanner compatibility | ✅ (matches Ethereum DKSAP) | ❌ | ❌ |
| Still active | ✅ | ❌ Sunset | ❌ Pivoted |
| Open protocol (no central dependency) | ✅ | ❌ | ❌ |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Frontend  (React / TypeScript)                  │
│   Wallet connect · Stealth send/receive · Private balance scanner   │
│   Reputation dashboard · ZK proof generation (snarkjs in-browser)   │
└──────────┬──────────────────┬──────────────────┬────────────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────┐ ┌────────────────┐ ┌─────────────────────────────┐
│  Scanner (WASM)  │ │ Circom Circuit │ │   Solana Programs (Anchor)  │
│  Rust → WASM     │ │ Groth16 ZK     │ │                             │
│  DKSAP engine    │ │ stealth_        │ │  stealth-registry           │
│  View-tag filter │ │ attestation     │ │  stealth-announcer          │
│  Attestation     │ │ .circom         │ │  groth16-verifier           │
│  discovery       │ │ (Merkle depth-20)│ │  reputation-verifier       │
└──────────────────┘ └────────────────┘ └─────────────────────────────┘
```

---

## Deployed Programs (Solana Devnet)

| Program | Address | Explorer |
|:--------|:--------|:---------|
| **StealthMetaAddressRegistry** | `E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno` | [View →](https://explorer.solana.com/address/E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno?cluster=devnet) |
| **StealthAddressAnnouncer** | `HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf` | [View →](https://explorer.solana.com/address/HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf?cluster=devnet) |
| **Groth16Verifier** | `6mFaKyp7F4NqNeoiBLEWSqy5wJSk7rWf1EYumVXgHvhQ` | [View →](https://explorer.solana.com/address/6mFaKyp7F4NqNeoiBLEWSqy5wJSk7rWf1EYumVXgHvhQ?cluster=devnet) |
| **OpaqueReputationVerifier** | `BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM` | [View →](https://explorer.solana.com/address/BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM?cluster=devnet) |
| **uab_receiver** (Universal Announcement Bus) | `7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM` | [View →](https://explorer.solana.com/address/7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM?cluster=devnet) |

`stealth_announcer` also gained `announce_with_relay` (cross-chain announce via Wormhole). The UAB cross-chain transport is specified in `opaquecash/spec` (UAB.md).

---

## Technical Differentiation

The deeper you look at Opaque, the more separation you'll find from everything else in the Solana privacy space.

**Dual keys, not single keys.** Most stealth implementations use a single key — one secret controls both viewing and spending. DKSAP separates these: you can share your *viewing* key with a trusted third party (an accountant, a compliance officer, a multisig co-signer) without ever handing over spending authority. This is what makes the protocol enterprise-grade.

**View tags eliminate the scanning bottleneck.** Without view tags, a scanner must perform full elliptic curve math on every announcement to check if it belongs to you. At scale, this is prohibitively expensive. Opaque embeds a single-byte view tag in every announcement, allowing scanners to discard ~99.6% of all records without any EC operations. Combined with the Rust/WASM scanner running entirely in-browser, this means no server, no trust dependency, and fast scanning at any scale.

**Native on-chain ZK verification.** Opaque uses Solana's `alt_bn128` precompile syscalls for BN254 pairing operations directly on-chain. The proof is verified by the `Groth16Verifier` program — not off-chain, not by a trusted committee, but by the Solana runtime itself. This is the highest trust guarantee possible.

**Cross-chain by design.** Because Opaque uses secp256k1 and Keccak-256 — the same cryptographic foundation as EIP-5564 — a scanner built for Ethereum stealth addresses can scan Opaque announcements. This means future cross-chain tooling can work across both ecosystems with the same codebase.

---

## Repository Map

| Path | Contents |
|:-----|:---------|
| [opaquecash/app](https://github.com/opaquecash/app) | React/TS reference UI — send, receive, private balance, reputation dashboard |
| [`programs/`](programs/) | Anchor programs — Registry, Announcer, Groth16 Verifier, Reputation Verifier |
| [`circuits/`](circuits/) | Circom ZK circuit for stealth attestation proofs (Groth16, Merkle depth-20) |
| [`scanner/`](scanner/) | Rust WASM core — DKSAP engine, view-tag filtering, attestation detection, Merkle tree |

---

## Running Locally

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Solana CLI](https://docs.solanalabs.com/cli/install) v1.18+
- [Anchor CLI](https://www.anchor-lang.com/docs/installation) v0.30+
- [Node.js](https://nodejs.org/) 18+
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for WASM scanner builds)
- [Circom](https://docs.circom.io/getting-started/installation/) 2.1+ *(only if modifying circuits)*

### 1. Clone

```bash
git clone https://github.com/collinsadi/opaque-solana.git
cd opaque-solana
```

### 2. Build & Deploy Solana Programs

```bash
# Point CLI to devnet and fund your keypair
solana config set --url devnet
solana airdrop 2

# Build, deploy, test
anchor build
anchor deploy
anchor test
```

After deploying, update program IDs in `Anchor.toml` and [`src/contracts/deployed-addresses.json`](https://github.com/opaquecash/app/blob/main/src/contracts/deployed-addresses.json) in the [app repo](https://github.com/opaquecash/app) with the output from `anchor deploy`.

### 3. Build the Scanner (WASM)

The scanner is the canonical [`opaque-scanner`](https://crates.io/crates/opaque-scanner)
crate ([opaquecash/scanner](https://github.com/opaquecash/scanner)); it is no longer
vendored in this repo. Build the browser WASM from it:

```bash
git clone https://github.com/opaquecash/scanner.git opaque-scanner
git clone https://github.com/opaquecash/app.git opaque-app
cd opaque-scanner
wasm-pack build --target web --out-dir ../opaque-app/src/wasm
cd ..
```

### 4. Run the Frontend

The UI lives in the standalone [opaquecash/app](https://github.com/opaquecash/app) repository:

```bash
git clone https://github.com/opaquecash/app.git
cd app
npm install
echo "VITE_SOLANA_CLUSTER=devnet" > .env
npm run dev
```

Visit `http://localhost:5173`. Connect Phantom or Solflare on Devnet.

### 5. Optional: Rebuild ZK Circuits

Only needed if you're modifying the attestation circuit:

```bash
cd circuits
npm install
npm run build       # Compile Circom circuit
npm run setup       # Powers of tau ceremony
npm run contribute  # Add entropy
npm run export-vkey # Export verification key
npm run export-sol  # Export Solidity verifier (for cross-chain reference)
cd ..
```

---

## Testing the Full Flow

**Connect** your wallet (Phantom or Solflare) and switch to Devnet.

**Register** your stealth meta-address through the onboarding wizard. This maps your Solana pubkey to your `V ∥ S` meta-address in the registry.

**Receive** — share your meta-address or just your Solana pubkey with a sender. They look up your meta-address from the registry.

**Send** — paste a recipient's meta-address or registered pubkey, enter an amount. The frontend derives a one-time stealth address, sends SOL to it, and emits a compact announcement on-chain.

**Scan** — open Private Balance. The WASM scanner loads announcements, applies view-tag filtering, and identifies which stealth outputs are yours. Sweep any discovered balance back to your main wallet.

**Reputation** — an issuer embeds an attestation in an announcement to your stealth address. You discover it via scanning. Generate a Groth16 ZK proof in-browser with snarkjs, submit it on-chain, and receive a `ReputationVerified` event — without ever linking your proof to your wallet identity.

---

## Cryptographic Stack

| Layer | Primitive | Purpose |
|:------|:----------|:--------|
| Key derivation | secp256k1 ECDH | DKSAP shared secret computation |
| Address hashing | Keccak-256 | Stealth address derivation (cross-chain compatible) |
| View filtering | 1-byte view tag | Skip 99.6% of announcements without EC math |
| ZK proving | Groth16 (BN254) | In-browser reputation proof generation |
| ZK verification | alt_bn128 syscalls | Native on-chain pairing verification |
| Sybil resistance | Poseidon hash nullifiers | Prevent proof replay |
| Merkle proofs | Depth-20 Merkle tree | Attestation inclusion proofs |
| Smart contracts | Anchor / Rust | All four on-chain programs |

---

## Inspiration & Standards

Opaque is a direct Solana implementation of the Ethereum stealth address standard:

- **EIP-5564** — [Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- **ERC-6538** — [Stealth Meta-Address Registry](https://eips.ethereum.org/EIPS/erc-6538)

The Ethereum version of Opaque (same creator, same DKSAP math) is available at [github.com/collinsadi/opaque](https://github.com/collinsadi/opaque). A stealth meta-address generated in either ecosystem is scannable by the same scanner implementation.

> **Disclaimer:** This is experimental software deployed on Devnet. Read [DISCLAIMER.md](DISCLAIMER.md) before deploying or relying on it for anything with real value.

---

## License

[MIT](LICENSE) — Built in public by [Collins Adi](https://github.com/collinsadi).

*Every transaction deserves the right to be private.*
