/**
 * Browser globals expected by @solana/web3.js and related packages.
 * Import this module before any Solana imports.
 */
import { Buffer } from "buffer";
import process from "process";

const g = globalThis as typeof globalThis & {
  Buffer?: typeof Buffer;
  global?: typeof globalThis;
  process?: typeof process;
};
if (g.Buffer === undefined) {
  g.Buffer = Buffer;
}
// Some bundled deps still read `global` (Node) instead of `globalThis`.
if (g.global === undefined) {
  g.global = globalThis;
}
// Some ZK proving dependencies may reference Node's `process` in browser builds.
if (g.process === undefined) {
  g.process = process;
}
