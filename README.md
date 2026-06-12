# Opaque — Solana programs

[![CI](https://github.com/opaquecash/solana/actions/workflows/solana-programs.yml/badge.svg)](https://github.com/opaquecash/solana/actions/workflows/solana-programs.yml)

Anchor programs for the [Opaque protocol](https://opaque.cash) on Solana: stealth
payments (DKSAP), ZK reputation (PSR V2), cross-chain announcements (UAB/Wormhole),
ONS naming, the relayer market, the privacy pool, and conditional disclosure.

Protocol design lives in [`opaquecash/spec`](https://github.com/opaquecash/spec);
integrate via the [`@opaquecash/*` SDK](https://github.com/opaquecash/sdk); developer
docs at [docs.opaque.cash](https://docs.opaque.cash).

> Experimental software, **devnet only**. See [DISCLAIMER.md](DISCLAIMER.md).

## Programs (devnet)

| Program | Address | Spec |
|---|---|---|
| `stealth-registry` | `E9LBRG5eP2kvuNfveouqQ9tA5P6nrpyLyWFjH9MFYVno` | [CSAP](https://github.com/opaquecash/spec/blob/main/CSAP.md) |
| `stealth-announcer` | `HGFn2fH7bVQ5cSuiG52NjzN9m11YrB3FZUfoN9b9A5jf` | [CSAP](https://github.com/opaquecash/spec/blob/main/CSAP.md) / [UAB](https://github.com/opaquecash/spec/blob/main/UAB.md) |
| `schema-registry` | `FbgMJYGWnLKLcrKYS1NxM5uER1ihQkYLMTLs4STuDMWB` | [PSR](https://github.com/opaquecash/spec/blob/main/PSR.md) |
| `attestation-engine-v2` | `4T9kPCVCFGdEuLpEqRJihsPCbEEo2LWWDEPFvUESEqtM` | [PSR](https://github.com/opaquecash/spec/blob/main/PSR.md) |
| `groth16-verifier` | `6mFaKyp7F4NqNeoiBLEWSqy5wJSk7rWf1EYumVXgHvhQ` | [PSR](https://github.com/opaquecash/spec/blob/main/PSR.md) |
| `reputation-verifier` | `BSnkCDoTpgNVN5BbF3aN5L5EJPiaYUkqqj9MHp8kaqWM` | [PSR](https://github.com/opaquecash/spec/blob/main/PSR.md) |
| `uab-receiver` | `7d4Sbmmpy954JwSNdjwf31pgbeWUQqwpgNdte5iy3vuM` | [UAB](https://github.com/opaquecash/spec/blob/main/UAB.md) |
| `ons-mirror` | `D7EXuwcsGrUAYC6k69jrKvsKethsKYgR1pokkTcFvWsk` | [ONS](https://github.com/opaquecash/spec/blob/main/ONS.md) |
| `ons-registration` | `5gfK9J8FJi3FpsQD33Hkrfwq8KqN4yadB2PDF9REnwMT` | [ONS](https://github.com/opaquecash/spec/blob/main/ONS.md) |
| `relayer-registry` | `E4xmYaAU31dbNTbhfMfp2F24b48DAxJigvZTVbsKJREg` | [relayer-market](https://github.com/opaquecash/spec/blob/main/relayer-market.md) |
| `opaque-privacy-pool` | `5NjweHM4z7NrG4NLVUyJ8rtX8jLM3xtBWAR1wSJZ7vjY` | [privacy-pool](https://github.com/opaquecash/spec/blob/main/privacy-pool.md) |
| `conditional-disclosure` | `7sDCTbMDwjzYA3KHhNPZUVa8Swvj6adJTgSkJqmsn6V7` | [conditional-disclosure](https://github.com/opaquecash/spec/blob/main/conditional-disclosure.md) |

Program ids are the source of truth in `Anchor.toml`; `npm run generate` exports them to
the [`@opaquecash/deployments`](https://github.com/opaquecash/sdk) package — consumers
read addresses from there, never hardcode them.

## Layout

```
programs/        one Anchor program per directory (table above)
tests/           localnet integration suites (ts-mocha; genesis fixtures in tests/fixtures/)
scripts/         IDL generation, deployments export, VAA/ONS fixture generators, live e2e scripts
circuits/        git submodule → opaquecash/circuits (proof fixtures used by tests)
```

## Develop

Prerequisites: Rust, Solana CLI, Anchor 0.32+, Node 18+.

```bash
git submodule update --init    # circuits fixtures
npm install
anchor build
anchor test                    # boots a local validator with all programs + fixtures
```

ZK tests that generate fresh proofs need the circuit artifacts — build them in the
submodule first (see [circuits/README](https://github.com/opaquecash/circuits)).

Deploy explicitly (the provider defaults to localnet):

```bash
anchor deploy -p <program> --provider.cluster devnet
```

Live devnet acceptance flows: `scripts/e2e-privacy-pool.mjs`, `scripts/e2e-disclosure.mjs`.

## License

GPL-3.0.
