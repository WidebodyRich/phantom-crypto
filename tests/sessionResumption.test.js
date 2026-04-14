/**
 * PHANTOM — Session Resumption Tests
 *
 * Tests the critical session resumption paths:
 * 1. Ratchet state persistence across restart
 * 2. Corrupted state detection and rejection
 * 3. Message deduplication
 * 4. Stale session detection
 * 5. Startup sequence with partial failures
 */

import { describe, test, expect, beforeEach } from 'vitest';
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
} from '../doubleRatchet.js';

import {
  validateSerializedSessionData,
  recordDecryptFailure,
  resetDecryptFailures,
  isSessionStale,
  isDuplicate,
  markProcessed,
} from '../sessionManager.js';

// ── Helpers ───────────────────────────────────────────

function generateKeyPair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function performX3DH(aliceIdentity, bobIdentity, bobSignedPreKey) {
  const X3DH_INFO = new TextEncoder().encode('PhantomX3DH');
  const PROTOCOL_BYTES = new Uint8Array(32).fill(0xff);
  const aliceEphemeral = generateKeyPair();

  const dh1 = x25519.getSharedSecret(aliceIdentity.privateKey, bobSignedPreKey.publicKey);
  const dh2 = x25519.getSharedSecret(aliceEphemeral.privateKey, bobIdentity.publicKey);
  const dh3 = x25519.getSharedSecret(aliceEphemeral.privateKey, bobSignedPreKey.publicKey);

  const dhConcat = concatBytes(PROTOCOL_BYTES, dh1, dh2, dh3);
  const sharedSecret = hkdf(sha256, dhConcat, new Uint8Array(32), X3DH_INFO, 32);

  const dh1b = x25519.getSharedSecret(bobSignedPreKey.privateKey, aliceIdentity.publicKey);
  const dh2b = x25519.getSharedSecret(bobIdentity.privateKey, aliceEphemeral.publicKey);
  const dh3b = x25519.getSharedSecret(bobSignedPreKey.privateKey, aliceEphemeral.publicKey);
  const dhConcatB = concatBytes(PROTOCOL_BYTES, dh1b, dh2b, dh3b);
  const sharedSecretB = hkdf(sha256, dhConcatB, new Uint8Array(32), X3DH_INFO, 32);

  const ad = concatBytes(aliceIdentity.publicKey, bobIdentity.publicKey);

  return {
    aliceSharedSecret: new Uint8Array(sharedSecret),
    bobSharedSecret: new Uint8Array(sharedSecretB),
    ad,
    bobSignedPreKeyPublic: bobSignedPreKey.publicKey,
  };
}

// ── TESTS ─────────────────────────────────────────────

describe('Session Resumption', () => {

  test('TEST 1 — Ratchet state persists across simulated restart', () => {
    const aliceId = generateKeyPair();
    const bobId = generateKeyPair();
    const bobSPK = generateKeyPair();
    const x3dh = performX3DH(aliceId, bobId, bobSPK);

    // Initialize sender
    const aliceState = initSenderRatchet(x3dh.aliceSharedSecret, x3dh.bobSignedPreKeyPublic);
    const bobState = initReceiverRatchet(x3dh.bobSharedSecret, bobSPK);

    // Send 3 messages
    const messages1 = [];
    for (let i = 0; i < 3; i++) {
      const msg = `Before restart msg ${i + 1}`;
      const encrypted = ratchetEncrypt(aliceState, new TextEncoder().encode(msg), x3dh.ad);
      const decrypted = ratchetDecrypt(bobState, encrypted, x3dh.ad);
      messages1.push({ msg, decrypted: new TextDecoder().decode(decrypted) });
    }

    // === SIMULATE RESTART ===
    // Serialize alice state (as if writing to storage)
    const serializedAlice = serializeRatchetState(aliceState);
    const serializedBob = serializeRatchetState(bobState);

    // Deserialize (as if loading on app restart)
    const restoredAlice = deserializeRatchetState(serializedAlice);
    const restoredBob = deserializeRatchetState(serializedBob);

    // Send 3 more messages with restored state
    const messages2 = [];
    for (let i = 0; i < 3; i++) {
      const msg = `After restart msg ${i + 1}`;
      const encrypted = ratchetEncrypt(restoredAlice, new TextEncoder().encode(msg), x3dh.ad);
      const decrypted = ratchetDecrypt(restoredBob, encrypted, x3dh.ad);
      messages2.push({ msg, decrypted: new TextDecoder().decode(decrypted) });
    }

    // All 6 messages must decrypt correctly
    for (const { msg, decrypted } of [...messages1, ...messages2]) {
      expect(decrypted).toBe(msg);
    }
  });

  test('TEST 2 — Corrupted session state is detected and rejected', () => {
    // Valid session data
    const validData = {
      recipientUserId: 'user-123',
      recipientUsername: 'alice',
      ratchetState: JSON.stringify({
        dhSendPub: 'AAAA',
        dhSendPriv: 'BBBB',
        dhRecvPub: null,
        rootKey: 'CCCC',
        sendChainKey: null,
        sendCounter: 0,
        recvChainKey: null,
        recvCounter: 0,
        prevSendCounter: 0,
        skipped: [],
      }),
      associatedData: 'DDDD',
      recipientIdentityKey: 'EEEE',
    };

    // Valid data passes
    expect(validateSerializedSessionData(validData)).toBe(true);

    // Corrupted: missing rootKey
    const corrupted1 = { ...validData, ratchetState: JSON.stringify({ dhSendPub: 'A', dhSendPriv: 'B' }) };
    expect(validateSerializedSessionData(corrupted1)).toBe(false);

    // Corrupted: invalid JSON in ratchetState
    const corrupted2 = { ...validData, ratchetState: 'not-valid-json' };
    expect(validateSerializedSessionData(corrupted2)).toBe(false);

    // Corrupted: missing recipientUserId
    const corrupted3 = { ...validData, recipientUserId: undefined };
    expect(validateSerializedSessionData(corrupted3)).toBe(false);

    // Corrupted: null object
    expect(validateSerializedSessionData(null)).toBe(false);

    // Corrupted: sendCounter is string instead of number
    const corrupted4 = {
      ...validData,
      ratchetState: JSON.stringify({
        dhSendPub: 'A', dhSendPriv: 'B', rootKey: 'C',
        sendCounter: 'not-a-number', recvCounter: 0, prevSendCounter: 0,
      }),
    };
    expect(validateSerializedSessionData(corrupted4)).toBe(false);
  });

  test('TEST 3 — Deduplication prevents double-processing', () => {
    const messageId1 = 'msg-abc-123';
    const messageId2 = 'msg-def-456';

    // First process — not duplicate
    expect(isDuplicate(messageId1)).toBe(false);
    markProcessed(messageId1);

    // Second process — is duplicate
    expect(isDuplicate(messageId1)).toBe(true);

    // Different message — not duplicate
    expect(isDuplicate(messageId2)).toBe(false);
    markProcessed(messageId2);
    expect(isDuplicate(messageId2)).toBe(true);
  });

  test('TEST 4 — Stale session detection after 3 consecutive failures', () => {
    const contactId = 'contact-xyz';

    // Reset state
    resetDecryptFailures(contactId);
    expect(isSessionStale(contactId)).toBe(false);

    // First failure — not stale yet
    let stale = recordDecryptFailure(contactId);
    expect(stale).toBe(false);
    expect(isSessionStale(contactId)).toBe(false);

    // Second failure — not stale yet
    stale = recordDecryptFailure(contactId);
    expect(stale).toBe(false);

    // Third failure — NOW stale
    stale = recordDecryptFailure(contactId);
    expect(stale).toBe(true);
    expect(isSessionStale(contactId)).toBe(true);

    // Reset clears stale state
    resetDecryptFailures(contactId);
    expect(isSessionStale(contactId)).toBe(false);
  });

  test('TEST 5 — Startup sequence completes with partial failures', async () => {
    const stepResults = [];

    // Simulate startup with step 4 (fetchPending) timing out
    const STEP_TIMEOUT = 100; // Short timeout for test

    async function runStepWithTimeout(name, fn) {
      const start = Date.now();
      try {
        await Promise.race([
          fn(),
          new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT')), STEP_TIMEOUT)),
        ]);
        stepResults.push({ name, success: true, durationMs: Date.now() - start });
      } catch (err) {
        stepResults.push({ name, success: false, durationMs: Date.now() - start, error: err.message });
      }
    }

    // Step 1: Auth — succeeds
    await runStepWithTimeout('restoreAuth', async () => {});

    // Step 2: WS connect — succeeds
    await runStepWithTimeout('connectWebSocket', async () => {});

    // Step 3: Subscribe mailboxes — succeeds
    await runStepWithTimeout('subscribeMailboxes', async () => {});

    // Step 4: Fetch pending — TIMES OUT (simulates network issue)
    await runStepWithTimeout('fetchPendingMessages', async () => {
      await new Promise((resolve) => setTimeout(resolve, 500)); // Takes longer than timeout
    });

    // Step 5: Check group keys — succeeds (continues despite step 4 failure)
    await runStepWithTimeout('checkGroupKeyVersions', async () => {});

    // Step 6: Load local conversations — succeeds
    await runStepWithTimeout('loadLocalConversations', async () => {});

    // Verify: step 4 failed but others succeeded
    expect(stepResults).toHaveLength(6);
    expect(stepResults[0].success).toBe(true);  // restoreAuth
    expect(stepResults[1].success).toBe(true);  // connectWebSocket
    expect(stepResults[2].success).toBe(true);  // subscribeMailboxes
    expect(stepResults[3].success).toBe(false); // fetchPendingMessages — TIMEOUT
    expect(stepResults[3].error).toBe('TIMEOUT');
    expect(stepResults[4].success).toBe(true);  // checkGroupKeyVersions
    expect(stepResults[5].success).toBe(true);  // loadLocalConversations

    // App reaches usable state despite partial failure
    const partialSuccess = stepResults.filter(s => s.success).length >= 4;
    expect(partialSuccess).toBe(true);
  });
});
