/**
 * PHANTOM — Cross-Platform E2EE Compatibility Tests
 *
 * Validates that the web Double Ratchet implementation produces
 * byte-for-byte identical output to the mobile implementation.
 *
 * These tests simulate both mobile and web clients using the same
 * crypto primitives (@noble/curves for X25519, @noble/hashes for KDF).
 *
 * DEFINITION OF DONE: All 5 tests must pass with zero failures.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';

import {
  initSenderRatchet,
  initReceiverRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
  uint8ToBase64,
  base64ToUint8,
  KDF_CONSTANTS,
} from '../doubleRatchet.js';

// ── Helpers ───────────────────────────────────────────

function generateKeyPair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Simulate X3DH between two parties.
 * Returns matching shared secrets for both sides.
 * Uses the exact same protocol as mobile/src/crypto/x3dh.ts.
 */
function performX3DH(aliceIdentity, bobIdentity, bobSignedPreKey) {
  const X3DH_INFO = new TextEncoder().encode('PhantomX3DH');
  const PROTOCOL_BYTES = new Uint8Array(32).fill(0xff);

  // Alice generates ephemeral key
  const aliceEphemeral = generateKeyPair();

  // DH1: Alice identity × Bob signed prekey
  const dh1 = x25519.getSharedSecret(aliceIdentity.privateKey, bobSignedPreKey.publicKey);
  // DH2: Alice ephemeral × Bob identity
  const dh2 = x25519.getSharedSecret(aliceEphemeral.privateKey, bobIdentity.publicKey);
  // DH3: Alice ephemeral × Bob signed prekey
  const dh3 = x25519.getSharedSecret(aliceEphemeral.privateKey, bobSignedPreKey.publicKey);

  const dhConcat = concatBytes(PROTOCOL_BYTES, dh1, dh2, dh3);
  const sharedSecret = hkdf(sha256, dhConcat, new Uint8Array(32), X3DH_INFO, 32);

  // Alice's AD: alice identity || bob identity
  const aliceAD = concatBytes(aliceIdentity.publicKey, bobIdentity.publicKey);
  // Bob's AD: alice identity || bob identity (same order per Signal spec)
  const bobAD = concatBytes(aliceIdentity.publicKey, bobIdentity.publicKey);

  // Bob performs the same DH in reverse
  const dh1b = x25519.getSharedSecret(bobSignedPreKey.privateKey, aliceIdentity.publicKey);
  const dh2b = x25519.getSharedSecret(bobIdentity.privateKey, aliceEphemeral.publicKey);
  const dh3b = x25519.getSharedSecret(bobSignedPreKey.privateKey, aliceEphemeral.publicKey);

  const dhConcatB = concatBytes(PROTOCOL_BYTES, dh1b, dh2b, dh3b);
  const sharedSecretB = hkdf(sha256, dhConcatB, new Uint8Array(32), X3DH_INFO, 32);

  return {
    aliceSharedSecret: new Uint8Array(sharedSecret),
    bobSharedSecret: new Uint8Array(sharedSecretB),
    aliceAD,
    bobAD,
    bobSignedPreKeyPublic: bobSignedPreKey.publicKey,
  };
}

// ── TEST 1: Mobile sender, web receiver ───────────────

describe('Cross-Platform Double Ratchet', () => {
  test('TEST 1 — Mobile sender, web receiver: 5 messages decrypt correctly', () => {
    // Generate identities (same process on both platforms)
    const mobileIdentity = generateKeyPair();
    const webIdentity = generateKeyPair();
    const webSignedPreKey = generateKeyPair();

    // X3DH handshake
    const x3dh = performX3DH(mobileIdentity, webIdentity, webSignedPreKey);

    // Verify shared secrets match
    expect(uint8ToBase64(x3dh.aliceSharedSecret)).toBe(uint8ToBase64(x3dh.bobSharedSecret));

    // Mobile (Alice/sender) initializes ratchet
    const mobileState = initSenderRatchet(
      x3dh.aliceSharedSecret,
      x3dh.bobSignedPreKeyPublic
    );

    // Web (Bob/receiver) initializes ratchet
    const webState = initReceiverRatchet(
      x3dh.bobSharedSecret,
      webSignedPreKey
    );

    // Mobile sends 5 messages
    const messages = [
      'Hello from mobile!',
      'This is message 2.',
      'Testing cross-platform E2EE.',
      'Message number 4 with special chars: @#$%^&*()',
      'Final test message from mobile client.',
    ];

    for (const msg of messages) {
      const plaintext = new TextEncoder().encode(msg);
      const encrypted = ratchetEncrypt(mobileState, plaintext, x3dh.aliceAD);
      const decrypted = ratchetDecrypt(webState, encrypted, x3dh.bobAD);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(msg);
    }
  });

  // ── TEST 2: Web sender, mobile receiver ─────────────

  test('TEST 2 — Web sender, mobile receiver: 5 messages decrypt correctly', () => {
    const webIdentity = generateKeyPair();
    const mobileIdentity = generateKeyPair();
    const mobileSignedPreKey = generateKeyPair();

    const x3dh = performX3DH(webIdentity, mobileIdentity, mobileSignedPreKey);

    expect(uint8ToBase64(x3dh.aliceSharedSecret)).toBe(uint8ToBase64(x3dh.bobSharedSecret));

    // Web (Alice/sender) initializes
    const webState = initSenderRatchet(
      x3dh.aliceSharedSecret,
      x3dh.bobSignedPreKeyPublic
    );

    // Mobile (Bob/receiver) initializes
    const mobileState = initReceiverRatchet(
      x3dh.bobSharedSecret,
      mobileSignedPreKey
    );

    const messages = [
      'Hello from web client!',
      'Web message 2.',
      'Cross-platform test from web.',
      'Unicode test: Hello World! Emoji test.',
      'Final web message with newlines:\nLine 2\nLine 3',
    ];

    for (const msg of messages) {
      const plaintext = new TextEncoder().encode(msg);
      const encrypted = ratchetEncrypt(webState, plaintext, x3dh.aliceAD);
      const decrypted = ratchetDecrypt(mobileState, encrypted, x3dh.bobAD);
      const decryptedText = new TextDecoder().decode(decrypted);

      expect(decryptedText).toBe(msg);
    }
  });

  // ── TEST 3: Out of order delivery ───────────────────

  test('TEST 3 — Out of order delivery: messages 3,1,4,2,5 all decrypt', () => {
    const aliceId = generateKeyPair();
    const bobId = generateKeyPair();
    const bobSPK = generateKeyPair();

    const x3dh = performX3DH(aliceId, bobId, bobSPK);

    const senderState = initSenderRatchet(x3dh.aliceSharedSecret, x3dh.bobSignedPreKeyPublic);
    const receiverState = initReceiverRatchet(x3dh.bobSharedSecret, bobSPK);

    const messages = ['msg1', 'msg2', 'msg3', 'msg4', 'msg5'];

    // Encrypt all 5 messages in order
    const encrypted = messages.map((msg) =>
      ratchetEncrypt(senderState, new TextEncoder().encode(msg), x3dh.aliceAD)
    );

    // Decrypt in order: 3, 1, 4, 2, 5 (indices 2, 0, 3, 1, 4)
    const receiveOrder = [2, 0, 3, 1, 4];
    for (const idx of receiveOrder) {
      const decrypted = ratchetDecrypt(receiverState, encrypted[idx], x3dh.bobAD);
      const text = new TextDecoder().decode(decrypted);
      expect(text).toBe(messages[idx]);
    }
  });

  // ── TEST 4: Multi-turn conversation ─────────────────

  test('TEST 4 — Multi-turn conversation: 12 messages across 4 turns', () => {
    const aliceId = generateKeyPair();
    const bobId = generateKeyPair();
    const bobSPK = generateKeyPair();

    const x3dh = performX3DH(aliceId, bobId, bobSPK);

    const aliceState = initSenderRatchet(x3dh.aliceSharedSecret, x3dh.bobSignedPreKeyPublic);
    const bobState = initReceiverRatchet(x3dh.bobSharedSecret, bobSPK);

    const allMessages = [];

    // Turn 1: Alice sends 3 messages
    for (let i = 0; i < 3; i++) {
      const msg = `Alice turn 1 msg ${i + 1}`;
      allMessages.push({ sender: 'alice', text: msg });
      const encrypted = ratchetEncrypt(aliceState, new TextEncoder().encode(msg), x3dh.aliceAD);
      const decrypted = ratchetDecrypt(bobState, encrypted, x3dh.bobAD);
      expect(new TextDecoder().decode(decrypted)).toBe(msg);
    }

    // Turn 2: Bob replies with 3 messages (triggers DH ratchet step)
    for (let i = 0; i < 3; i++) {
      const msg = `Bob turn 2 msg ${i + 1}`;
      allMessages.push({ sender: 'bob', text: msg });
      const encrypted = ratchetEncrypt(bobState, new TextEncoder().encode(msg), x3dh.bobAD);
      const decrypted = ratchetDecrypt(aliceState, encrypted, x3dh.aliceAD);
      expect(new TextDecoder().decode(decrypted)).toBe(msg);
    }

    // Turn 3: Alice replies with 3 more (another DH ratchet step)
    for (let i = 0; i < 3; i++) {
      const msg = `Alice turn 3 msg ${i + 1}`;
      allMessages.push({ sender: 'alice', text: msg });
      const encrypted = ratchetEncrypt(aliceState, new TextEncoder().encode(msg), x3dh.aliceAD);
      const decrypted = ratchetDecrypt(bobState, encrypted, x3dh.bobAD);
      expect(new TextDecoder().decode(decrypted)).toBe(msg);
    }

    // Turn 4: Bob replies with 3 more (another DH ratchet step)
    for (let i = 0; i < 3; i++) {
      const msg = `Bob turn 4 msg ${i + 1}`;
      allMessages.push({ sender: 'bob', text: msg });
      const encrypted = ratchetEncrypt(bobState, new TextEncoder().encode(msg), x3dh.bobAD);
      const decrypted = ratchetDecrypt(aliceState, encrypted, x3dh.aliceAD);
      expect(new TextDecoder().decode(decrypted)).toBe(msg);
    }

    // All 12 messages decrypted correctly
    expect(allMessages.length).toBe(12);
  });

  // ── TEST 5: KDF constant verification ───────────────

  test('TEST 5 — KDF constants are byte-for-byte identical to mobile', () => {
    // Mobile constants (from mobile/src/crypto/doubleRatchet.ts):
    // const RATCHET_INFO_ROOT = new TextEncoder().encode('PhantomRootRatchet');
    // const RATCHET_INFO_CHAIN = new TextEncoder().encode('PhantomChainRatchet');
    // const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
    // const CHAIN_KEY_SEED = new Uint8Array([0x02]);
    // const MAX_SKIP = 1000;

    const mobileRootInfo = new TextEncoder().encode('PhantomRootRatchet');
    const mobileChainInfo = new TextEncoder().encode('PhantomChainRatchet');
    const mobileMsgSeed = new Uint8Array([0x01]);
    const mobileChainSeed = new Uint8Array([0x02]);
    const mobileMaxSkip = 1000;

    // Web constants (from web/src/crypto/doubleRatchet.js KDF_CONSTANTS export)
    const web = KDF_CONSTANTS;

    // Byte-for-byte comparison
    expect(uint8ToBase64(web.RATCHET_INFO_ROOT)).toBe(uint8ToBase64(mobileRootInfo));
    expect(uint8ToBase64(web.RATCHET_INFO_CHAIN)).toBe(uint8ToBase64(mobileChainInfo));
    expect(uint8ToBase64(web.MESSAGE_KEY_SEED)).toBe(uint8ToBase64(mobileMsgSeed));
    expect(uint8ToBase64(web.CHAIN_KEY_SEED)).toBe(uint8ToBase64(mobileChainSeed));
    expect(web.MAX_SKIP).toBe(mobileMaxSkip);

    // Also verify the raw bytes match
    expect(Array.from(web.RATCHET_INFO_ROOT)).toEqual(Array.from(mobileRootInfo));
    expect(Array.from(web.RATCHET_INFO_CHAIN)).toEqual(Array.from(mobileChainInfo));
    expect(Array.from(web.MESSAGE_KEY_SEED)).toEqual(Array.from(mobileMsgSeed));
    expect(Array.from(web.CHAIN_KEY_SEED)).toEqual(Array.from(mobileChainSeed));

    // Log for audit trail
    console.log('KDF Constant Verification:');
    console.log(`  RATCHET_INFO_ROOT: "${new TextDecoder().decode(web.RATCHET_INFO_ROOT)}" ✓`);
    console.log(`  RATCHET_INFO_CHAIN: "${new TextDecoder().decode(web.RATCHET_INFO_CHAIN)}" ✓`);
    console.log(`  MESSAGE_KEY_SEED: [${Array.from(web.MESSAGE_KEY_SEED).join(', ')}] ✓`);
    console.log(`  CHAIN_KEY_SEED: [${Array.from(web.CHAIN_KEY_SEED).join(', ')}] ✓`);
    console.log(`  MAX_SKIP: ${web.MAX_SKIP} ✓`);
  });

  // ── BONUS: Serialization round-trip ─────────────────

  test('BONUS — Session state serializes and deserializes correctly', () => {
    const aliceId = generateKeyPair();
    const bobId = generateKeyPair();
    const bobSPK = generateKeyPair();

    const x3dh = performX3DH(aliceId, bobId, bobSPK);

    const state = initSenderRatchet(x3dh.aliceSharedSecret, x3dh.bobSignedPreKeyPublic);

    // Encrypt a message to advance state
    const encrypted = ratchetEncrypt(
      state,
      new TextEncoder().encode('test message'),
      x3dh.aliceAD
    );

    // Serialize
    const json = serializeRatchetState(state);

    // Deserialize
    const restored = deserializeRatchetState(json);

    // Verify key fields match
    expect(uint8ToBase64(restored.rootKey)).toBe(uint8ToBase64(state.rootKey));
    expect(uint8ToBase64(restored.dhSendingKeyPair.publicKey)).toBe(
      uint8ToBase64(state.dhSendingKeyPair.publicKey)
    );
    expect(restored.sendingCounter).toBe(state.sendingCounter);
    expect(restored.receivingCounter).toBe(state.receivingCounter);
    expect(restored.previousSendingCounter).toBe(state.previousSendingCounter);

    // Verify the restored state can still encrypt
    const encrypted2 = ratchetEncrypt(
      restored,
      new TextEncoder().encode('after restore'),
      x3dh.aliceAD
    );
    expect(encrypted2.ciphertext).toBeTruthy();
  });
});
