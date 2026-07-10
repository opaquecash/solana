/**
 * Phase 1.6 happy-path integration tests, run on the Anchor local validator
 * (`anchor test --skip-build` after `anchor build --no-idl`).
 *
 * Instructions are built raw (discriminator + borsh) so the suite does not
 * depend on IDL generation, which is unavailable for the anchor-syn 0.30.1
 * programs (see .github/workflows/solana-programs.yml).
 */
import { createHash } from "node:crypto";
import { expect } from "chai";
import {
  ComputeBudgetProgram,
  Ed25519Program,
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SYSVAR_RENT_PUBKEY,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  PROGRAMS,
  WORMHOLE_CORE,
  be32,
  connection,
  deriveStealthAddress,
  disc,
  hexBytes,
  loadDksapVector,
  loadV2Fixture,
  payer,
  pda,
  programData,
  send,
  sendExpectFail,
  str,
  u16le,
  u32le,
  u64le,
  vec,
} from "./helpers";

const SYS = SystemProgram.programId;

describe("stealth-registry", () => {
  const metaAddress = Buffer.alloc(98, 7); // 98-byte V‖S‖S_ed placeholder
  const entryPda = pda(PROGRAMS.stealthRegistry, [
    Buffer.from("stealth_meta"),
    payer.publicKey.toBuffer(),
    u64le(1),
  ]);

  it("register_keys stores the 98-byte meta-address in the registry PDA", async () => {
    await send([
      new TransactionInstruction({
        programId: PROGRAMS.stealthRegistry,
        keys: [
          { pubkey: entryPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([disc("register_keys"), u64le(1), vec(metaAddress)]),
      }),
    ]);

    const info = await connection.getAccountInfo(entryPda);
    expect(info).to.not.be.null;
    // RegistryEntry: 8 disc + 32 registrant + 8 scheme_id + 4 vec len + 98 bytes
    const data = info!.data;
    expect(data.subarray(8, 40)).to.deep.equal(payer.publicKey.toBuffer());
    expect(data.readBigUInt64LE(40)).to.equal(1n);
    expect(data.readUInt32LE(48)).to.equal(98);
    expect(data.subarray(52, 150)).to.deep.equal(metaAddress);
  });

  it("resolve returns the registered meta-address", async () => {
    const tx = new Transaction().add(
      new TransactionInstruction({
        programId: PROGRAMS.stealthRegistry,
        keys: [{ pubkey: entryPda, isSigner: false, isWritable: false }],
        data: disc("resolve"),
      }),
    );
    tx.feePayer = payer.publicKey;
    tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    tx.sign(payer);
    const sim = await connection.simulateTransaction(tx);
    expect(sim.value.err).to.be.null;
    const ret = Buffer.from(sim.value.returnData!.data[0], "base64");
    // borsh Vec<u8>: 4-byte LE length + bytes
    expect(ret.readUInt32LE(0)).to.equal(98);
    expect(ret.subarray(4, 102)).to.deep.equal(metaAddress);
  });
});

describe("stealth-registry register_keys_on_behalf (OPQ-001)", () => {
  const AUTH_DOMAIN = Buffer.from("opaque-stealth-register-on-behalf-v1", "utf8");
  const SCHEME = 1n;

  /** The canonical message the on-chain program rebuilds and requires signed. */
  function authMessage(
    registrant: PublicKey,
    nonce: bigint,
    meta: Buffer,
  ): Buffer {
    return Buffer.concat([
      AUTH_DOMAIN,
      PROGRAMS.stealthRegistry.toBuffer(),
      registrant.toBuffer(),
      u64le(SCHEME),
      u64le(nonce),
      meta,
    ]);
  }

  function entryPdaFor(registrant: PublicKey): PublicKey {
    return pda(PROGRAMS.stealthRegistry, [
      Buffer.from("stealth_meta"),
      registrant.toBuffer(),
      u64le(SCHEME),
    ]);
  }
  function noncePdaFor(registrant: PublicKey): PublicKey {
    return pda(PROGRAMS.stealthRegistry, [Buffer.from("nonce"), registrant.toBuffer()]);
  }

  function onBehalfIx(registrant: PublicKey, meta: Buffer): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAMS.stealthRegistry,
      keys: [
        { pubkey: entryPdaFor(registrant), isSigner: false, isWritable: true },
        { pubkey: registrant, isSigner: false, isWritable: false },
        { pubkey: noncePdaFor(registrant), isSigner: false, isWritable: true },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SYS, isSigner: false, isWritable: false },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([disc("register_keys_on_behalf"), u64le(SCHEME), vec(meta)]),
    });
  }

  it("registers when authorized by the registrant's Ed25519 signature", async () => {
    const registrant = Keypair.generate();
    const meta = Buffer.alloc(98, 9);
    const message = authMessage(registrant.publicKey, 0n, meta);
    const signature = ed25519.sign(message, registrant.secretKey.subarray(0, 32));
    const edIx = Ed25519Program.createInstructionWithPublicKey({
      publicKey: registrant.publicKey.toBytes(),
      message,
      signature,
    });

    await send([edIx, onBehalfIx(registrant.publicKey, meta)]);

    const info = await connection.getAccountInfo(entryPdaFor(registrant.publicKey));
    expect(info).to.not.be.null;
    expect(info!.data.subarray(8, 40)).to.deep.equal(registrant.publicKey.toBuffer());
    expect(info!.data.subarray(52, 150)).to.deep.equal(meta);
    // nonce consumed (0 -> 1) so the signature cannot be replayed
    const nonceInfo = await connection.getAccountInfo(noncePdaFor(registrant.publicKey));
    expect(nonceInfo!.data.readBigUInt64LE(8)).to.equal(1n);
  });

  it("rejects when no Ed25519 signature instruction is present", async () => {
    const registrant = Keypair.generate();
    const meta = Buffer.alloc(98, 3);
    const logs = await sendExpectFail([onBehalfIx(registrant.publicKey, meta)]);
    expect(logs).to.match(/InvalidSignature/);
    // nothing was written
    expect(await connection.getAccountInfo(entryPdaFor(registrant.publicKey))).to.be.null;
  });

  it("rejects a valid signature made by someone other than the registrant", async () => {
    const registrant = Keypair.generate();
    const attacker = Keypair.generate();
    const meta = Buffer.alloc(98, 4);
    // Attacker signs the exact required message, but with their own key.
    const message = authMessage(registrant.publicKey, 0n, meta);
    const signature = ed25519.sign(message, attacker.secretKey.subarray(0, 32));
    const edIx = Ed25519Program.createInstructionWithPublicKey({
      publicKey: attacker.publicKey.toBytes(),
      message,
      signature,
    });
    const logs = await sendExpectFail([edIx, onBehalfIx(registrant.publicKey, meta)]);
    expect(logs).to.match(/InvalidSignature/);
    expect(await connection.getAccountInfo(entryPdaFor(registrant.publicKey))).to.be.null;
  });
});

describe("stealth-announcer", () => {
  const stealthAddress = Buffer.alloc(20, 0xaa);
  const ephemeralPubKey = Buffer.alloc(33, 2);
  const metadata = Buffer.from([0xe1]); // view tag

  it("announce emits the Announcement event", async () => {
    const sig = await send([
      new TransactionInstruction({
        programId: PROGRAMS.stealthAnnouncer,
        keys: [{ pubkey: payer.publicKey, isSigner: true, isWritable: true }],
        data: Buffer.concat([
          disc("announce"),
          u64le(1),
          vec(stealthAddress),
          vec(ephemeralPubKey),
          vec(metadata),
        ]),
      }),
    ]);
    const tx = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const logs = tx!.meta!.logMessages!.join("\n");
    expect(logs).to.include("Program data:"); // anchor event emitted
  });

  it("announce rejects a wrong-length ephemeral key", async () => {
    const logs = await sendExpectFail([
      new TransactionInstruction({
        programId: PROGRAMS.stealthAnnouncer,
        keys: [{ pubkey: payer.publicKey, isSigner: true, isWritable: true }],
        data: Buffer.concat([
          disc("announce"),
          u64le(1),
          vec(stealthAddress),
          vec(Buffer.alloc(32, 2)), // 32, not 33
          vec(metadata),
        ]),
      }),
    ]);
    expect(logs).to.include("InvalidEphemeralKey");
  });

  it("announce_with_relay validates payload and reaches the Wormhole CPI boundary", async () => {
    // The core bridge is not deployed on localnet, so the CPI must fail —
    // but only after the local Announcement event is emitted, which proves
    // argument encoding, account constraints, and payload validation.
    const emitter = pda(PROGRAMS.stealthAnnouncer, [Buffer.from("emitter")]);
    const whPda = (seed: string | Buffer) =>
      pda(WORMHOLE_CORE, [typeof seed === "string" ? Buffer.from(seed) : seed]);
    const sequence = pda(WORMHOLE_CORE, [Buffer.from("Sequence"), emitter.toBuffer()]);
    const message = Keypair.generate();

    const logs = await sendExpectFail(
      [
        new TransactionInstruction({
          programId: PROGRAMS.stealthAnnouncer,
          keys: [
            { pubkey: payer.publicKey, isSigner: true, isWritable: true },
            { pubkey: emitter, isSigner: false, isWritable: false },
            { pubkey: whPda("Bridge"), isSigner: false, isWritable: true },
            { pubkey: whPda("fee_collector"), isSigner: false, isWritable: true },
            { pubkey: sequence, isSigner: false, isWritable: true },
            { pubkey: message.publicKey, isSigner: true, isWritable: true },
            { pubkey: WORMHOLE_CORE, isSigner: false, isWritable: false },
            { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
            { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
            { pubkey: SYS, isSigner: false, isWritable: false },
          ],
          data: Buffer.concat([
            disc("announce_with_relay"),
            u64le(1),
            vec(stealthAddress),
            vec(ephemeralPubKey),
            vec(metadata),
            u32le(0), // batch_id
            u64le(0), // wormhole_fee
          ]),
        }),
      ],
      [message],
    );
    expect(logs).to.include("Program data:"); // local Announcement emitted pre-CPI
  });
});

describe("uab-receiver", () => {
  const configPda = pda(PROGRAMS.uabReceiver, [Buffer.from("config")]);
  const emitter = Buffer.alloc(32, 9);

  it("initialize stores the trusted source emitter", async () => {
    await send([
      new TransactionInstruction({
        programId: PROGRAMS.uabReceiver,
        keys: [
          { pubkey: configPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([disc("initialize"), u16le(2), emitter]),
      }),
    ]);
    const info = await connection.getAccountInfo(configPda);
    // Config: 8 disc + 32 admin + 2 source_chain + 32 source_emitter + bump
    expect(info!.data.readUInt16LE(40)).to.equal(2);
    expect(info!.data.subarray(42, 74)).to.deep.equal(emitter);
  });

  function receiveIx(postedVaa: Keypair["publicKey"]): TransactionInstruction {
    return new TransactionInstruction({
      programId: PROGRAMS.uabReceiver,
      keys: [
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: postedVaa, isSigner: false, isWritable: false },
        {
          pubkey: pda(PROGRAMS.uabReceiver, [Buffer.from("processed"), postedVaa.toBuffer()]),
          isSigner: false,
          isWritable: true,
        },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SYS, isSigner: false, isWritable: false },
      ],
      data: disc("receive_announcement"),
    });
  }

  it("receive_announcement rejects a VAA account not owned by the core bridge", async () => {
    const logs = await sendExpectFail([receiveIx(payer.publicKey)]);
    expect(logs).to.include("NotWormholeOwned");
  });

  it("receive_announcement rejects a wormhole-owned account without the VAA magic", async () => {
    const fake = Keypair.generate();
    const rent = await connection.getMinimumBalanceForRentExemption(200);
    await send(
      [
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: fake.publicKey,
          lamports: rent,
          space: 200,
          programId: WORMHOLE_CORE,
        }),
      ],
      [fake],
    );
    const logs = await sendExpectFail([receiveIx(fake.publicKey)]);
    expect(logs).to.include("NotPostedVaa");
  });

  // Phase 3.1: the cross-chain happy path. tests/fixtures/posted-vaa.json (generated by
  // scripts/generate-vaa-fixture.mjs, loaded at genesis via Anchor.toml) is an
  // Ethereum-origin posted VAA carrying the canonical 96-byte UAB payload for the CSAP
  // test-vector recipient: announce on Ethereum -> guardian hop (fixture) ->
  // receive_announcement re-emit -> scanner ownership, all on the local validator.
  const POSTED_VAA_FIXTURE = new PublicKey("ESv9V8KVyjJ1GQPWn8aCce6Q1xmdDZ4VW91cWTTFfg2A");

  it("receive_announcement re-emits an Ethereum-origin VAA and the scanner owns it", async () => {
    const vectors = loadDksapVector();
    const sig = await send([receiveIx(POSTED_VAA_FIXTURE)]);
    const tx = await connection.getTransaction(sig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });

    // Decode the CrossChainAnnouncement anchor event from the program logs.
    const EVENT_DISC = Buffer.from([13, 87, 101, 171, 128, 65, 106, 220]);
    const eventLine = tx!.meta!.logMessages!.find((l) => {
      if (!l.startsWith("Program data: ")) return false;
      return Buffer.from(l.slice("Program data: ".length), "base64")
        .subarray(0, 8)
        .equals(EVENT_DISC);
    });
    expect(eventLine, "CrossChainAnnouncement event emitted").to.not.equal(undefined);
    const ev = Buffer.from(eventLine!.slice("Program data: ".length), "base64");
    const sourceChain = ev.readUInt16LE(8);
    const sourceEmitter = ev.subarray(10, 42);
    const sequence = ev.readBigUInt64LE(42);
    const payloadLen = ev.readUInt32LE(50);
    const payload = ev.subarray(54, 54 + payloadLen);

    expect(sourceChain).to.equal(2); // origin = Ethereum
    expect(sourceEmitter).to.deep.equal(emitter);
    expect(sequence).to.equal(7n);
    expect(payloadLen).to.equal(96);

    // Payload fields (spec/payload-format.md).
    const viewTag = payload[0];
    const ephemeralPubKey = payload.subarray(1, 34);
    const stealthAddress = payload.subarray(46, 66);
    expect(viewTag).to.equal(Number(vectors.view_tag));
    expect(payload.readUInt16BE(66)).to.equal(2);

    // Scanner ownership: re-derive the stealth address from the recipient's viewing
    // key + the announced ephemeral key (DKSAP, CSAP 2.3) and require a match.
    const derived = deriveStealthAddress(
      hexBytes(vectors.viewing_private_key),
      hexBytes(vectors.spending_public_key),
      ephemeralPubKey,
    );
    expect(derived.viewTag).to.equal(viewTag);
    expect(Buffer.from(derived.address)).to.deep.equal(Buffer.from(stealthAddress));
  });

  it("receive_announcement rejects a replayed VAA (processed marker exists)", async () => {
    // The compute-budget ix makes the message distinct from the first delivery, so the
    // replay fails on the program (processed PDA init-once), not on tx dedup.
    const logs = await sendExpectFail([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 250_000 }),
      receiveIx(POSTED_VAA_FIXTURE),
    ]);
    expect(logs).to.include("already in use"); // processed PDA init-once
  });
});

describe("PSR V2: schema → attest → verify", () => {
  const schemaName = "KycPassed";
  const schemaId = createHash("sha256")
    .update(payer.publicKey.toBuffer())
    .update(Buffer.from(schemaName, "utf8"))
    .update(Buffer.from([1]))
    .digest();
  const schemaPda = pda(PROGRAMS.schemaRegistry, [
    Buffer.from("schema"),
    payer.publicKey.toBuffer(),
    schemaId,
  ]);
  const stealthAddressHash = Buffer.alloc(32, 0x5a);

  it("register_schema enforces the canonical schema id and stores the schema", async () => {
    await send([
      new TransactionInstruction({
        programId: PROGRAMS.schemaRegistry,
        keys: [
          { pubkey: schemaPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          disc("register_schema"),
          schemaId,
          str(schemaName),
          str("bool passed"),
          Buffer.from([1]), // revocable
          Buffer.from([0]), // resolver: None
          u64le(0), // schema_expiry_slot
        ]),
      }),
    ]);
    const info = await connection.getAccountInfo(schemaPda);
    expect(info).to.not.be.null;
    // SchemaPDA: 8 disc + 1 bump + 32 schema_id ...
    expect(info!.data.subarray(9, 41)).to.deep.equal(schemaId);
  });

  it("attest issues a schema-bound attestation from an authorized issuer", async () => {
    const attestationPda = pda(PROGRAMS.attestationEngineV2, [
      Buffer.from("attestation_v2"),
      schemaId,
      payer.publicKey.toBuffer(),
      stealthAddressHash,
    ]);
    await send([
      new TransactionInstruction({
        programId: PROGRAMS.attestationEngineV2,
        keys: [
          { pubkey: schemaPda, isSigner: false, isWritable: false },
          { pubkey: attestationPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          // resolver_program: None → pass the program id (anchor optional-account convention)
          { pubkey: PROGRAMS.attestationEngineV2, isSigner: false, isWritable: false },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          disc("attest"),
          stealthAddressHash,
          vec(Buffer.from([1])), // data: bool passed = true
          u64le(0), // expiration_slot
          Buffer.alloc(32), // ref_uid
        ]),
      }),
    ]);
    const info = await connection.getAccountInfo(attestationPda);
    expect(info).to.not.be.null;
    // AttestationPDA: 8 disc + 1 bump + 32 uid + 32 schema_pda + 32 schema_id ...
    expect(info!.data.subarray(73, 105)).to.deep.equal(schemaId);
  });

  it("verify_reputation accepts the real V2 fixture proof and consumes the nullifier", async () => {
    const { proofA, proofB, proofC, publicSignals } = loadV2Fixture();
    const rootBytes = be32(publicSignals[0]);
    const nullifierHash = be32(publicSignals[3]);
    const rep = PROGRAMS.reputationVerifier;
    const configPda = pda(rep, [Buffer.from("verifier_config")]);
    const historyPda = pda(rep, [Buffer.from("root_history")]);
    const rootPda = pda(rep, [Buffer.from("merkle_root"), rootBytes]);
    const nullifierPda = pda(rep, [Buffer.from("nullifier"), nullifierHash]);

    await send([
      new TransactionInstruction({
        programId: rep,
        keys: [
          { pubkey: configPda, isSigner: false, isWritable: true },
          { pubkey: historyPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: PROGRAMS.groth16Verifier, isSigner: false, isWritable: false },
          { pubkey: rep, isSigner: false, isWritable: false },
          { pubkey: programData(rep), isSigner: false, isWritable: false },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: disc("initialize"),
      }),
    ]);
    await send([
      new TransactionInstruction({
        programId: rep,
        keys: [
          { pubkey: configPda, isSigner: false, isWritable: false },
          { pubkey: rootPda, isSigner: false, isWritable: true },
          { pubkey: historyPda, isSigner: false, isWritable: true },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([disc("update_merkle_root"), rootBytes]),
      }),
    ]);

    const verifyIx = new TransactionInstruction({
      programId: rep,
      keys: [
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: rootPda, isSigner: false, isWritable: false },
        { pubkey: nullifierPda, isSigner: false, isWritable: true },
        { pubkey: PROGRAMS.groth16Verifier, isSigner: false, isWritable: false },
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: SYS, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        disc("verify_reputation"),
        proofA,
        proofB,
        proofC,
        rootBytes,
        be32(publicSignals[1]), // attestation_id (32-byte BE field element, OPQ-008)
        be32(publicSignals[2]), // external_nullifier (32-byte BE field element, OPQ-008)
        nullifierHash,
      ]),
    });
    await send([ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }), verifyIx]);
    const entry = await connection.getAccountInfo(nullifierPda);
    expect(entry, "nullifier must be consumed on-chain").to.not.be.null;

    // Replay must fail: the nullifier PDA already exists. A different CU limit
    // makes this a distinct transaction so the RPC doesn't dedupe it.
    const logs = await sendExpectFail([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 399_999 }),
      verifyIx,
    ]);
    expect(logs).to.match(/already in use|custom program error/i);
  });

  it("verify_reputation rejects a tampered proof", async () => {
    const { proofA, proofB, proofC, publicSignals } = loadV2Fixture();
    const rootBytes = be32(publicSignals[0]);
    const tamperedNullifier = be32(BigInt(publicSignals[3]) ^ 1n);
    const rep = PROGRAMS.reputationVerifier;

    const logs = await sendExpectFail([
      ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 }),
      new TransactionInstruction({
        programId: rep,
        keys: [
          { pubkey: pda(rep, [Buffer.from("verifier_config")]), isSigner: false, isWritable: false },
          { pubkey: pda(rep, [Buffer.from("merkle_root"), rootBytes]), isSigner: false, isWritable: false },
          { pubkey: pda(rep, [Buffer.from("nullifier"), tamperedNullifier]), isSigner: false, isWritable: true },
          { pubkey: PROGRAMS.groth16Verifier, isSigner: false, isWritable: false },
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: SYS, isSigner: false, isWritable: false },
        ],
        data: Buffer.concat([
          disc("verify_reputation"),
          proofA,
          proofB,
          proofC,
          rootBytes,
          be32(publicSignals[1]),
          be32(publicSignals[2]),
          tamperedNullifier,
        ]),
      }),
    ]);
    expect(logs).to.include("InvalidProof");
  });
});
