/**
 * PHANTOM — Double Ratchet Algorithm (Web Port)
 *
 * Line-for-line port of mobile/src/crypto/doubleRatchet.ts.
 * Every constant, every KDF info string, every magic number is
 * byte-for-byte identical to the mobile implementation.
 *
 * Two ratchets work together:
 * 1. Symmetric-key ratchet (KDF chain) — new key per message
 * 2. DH ratchet — new DH exchange on each reply turn
 *
 * This implements the full Signal Double Ratchet specification.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';

// ── Constants — MUST match mobile exactly ─────────────
// Changing any byte here = silent decrypt failure cross-platform.

const RATCHET_INFO_ROOT = new TextEncoder().encode('PhantomRootRatchet');
const RATCHET_INFO_CHAIN = new TextEncoder().encode('PhantomChainRatchet');
const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
const CHAIN_KEY_SEED = new Uint8Array([0x02]);
const MAX_SKIP = 1000;

// ── Utility functions ─────────────────────────────────

export function uint8ToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToUint8(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function secureWipeKey(key) {
  for (let i = 0; i < key.length; i++) {
    key[i] = 0;
  }
}

function uint8ArrayEquals(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function generateDHKeyPair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function makeSkipKey(publicKeyBase64, counter) {
  return `${publicKeyBase64}:${counter}`;
}

// ── KDF Functions — MUST match mobile exactly ─────────

/**
 * Root key KDF: derives new root key + chain key from DH output.
 * Uses HKDF with SHA-256.
 * salt = rootKey, ikm = dhOutput, info = 'PhantomRootRatchet', len = 64
 */
function kdfRootKey(rootKey, dhOutput) {
  const derived = hkdf(sha256, dhOutput, rootKey, RATCHET_INFO_ROOT, 64);
  const newRootKey = derived.slice(0, 32);
  const chainKey = derived.slice(32, 64);
  return [newRootKey, chainKey];
}

/**
 * Chain key KDF: derives new chain key + message key.
 * Uses HMAC-SHA256 with different constants to separate outputs.
 * CHAIN_KEY_SEED = [0x02], MESSAGE_KEY_SEED = [0x01]
 */
function kdfChainKey(chainKey) {
  const newChainKey = hmac(sha256, chainKey, CHAIN_KEY_SEED);
  const messageKey = hmac(sha256, chainKey, MESSAGE_KEY_SEED);
  return [newChainKey, messageKey];
}

// ── AES-GCM Encryption ───────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM using @noble/ciphers.
 * Nonce is randomly generated per message (96 bits).
 * AAD includes header + associated data for authentication.
 */
function encryptAesGcm(messageKey, plaintext, associatedData, header) {
  const nonce = randomBytes(12);

  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const aad = concatBytes(associatedData, headerBytes);

  const aes = gcm(messageKey, nonce, aad);
  const ciphertext = aes.encrypt(plaintext);

  return {
    header,
    nonce: uint8ToBase64(nonce),
    ciphertext: uint8ToBase64(ciphertext),
  };
}

/**
 * Decrypt ciphertext with AES-256-GCM.
 */
function decryptAesGcm(messageKey, message, associatedData) {
  const nonce = base64ToUint8(message.nonce);
  const ciphertext = base64ToUint8(message.ciphertext);

  const headerBytes = new TextEncoder().encode(JSON.stringify(message.header));
  const aad = concatBytes(associatedData, headerBytes);

  const aes = gcm(messageKey, nonce, aad);
  return aes.decrypt(ciphertext);
}

// ── Initialization ────────────────────────────────────

/**
 * Initialize ratchet state for the sender (Alice — who initiated X3DH).
 * Called after X3DH completes.
 *
 * @param {Uint8Array} sharedSecret — The SK from X3DH (32 bytes)
 * @param {Uint8Array} recipientPublicKey — Bob's signed prekey
 * @returns {Object} RatchetState
 */
export function initSenderRatchet(sharedSecret, recipientPublicKey) {
  const dhKeyPair = generateDHKeyPair();

  const dhOutput = x25519.getSharedSecret(dhKeyPair.privateKey, recipientPublicKey);
  const [newRootKey, sendingChainKey] = kdfRootKey(sharedSecret, dhOutput);
  secureWipeKey(dhOutput);

  return {
    dhSendingKeyPair: dhKeyPair,
    dhReceivingPublicKey: recipientPublicKey,
    rootKey: newRootKey,
    sendingChainKey,
    sendingCounter: 0,
    receivingChainKey: null,
    receivingCounter: 0,
    previousSendingCounter: 0,
    skippedKeys: new Map(),
  };
}

/**
 * Initialize ratchet state for the receiver (Bob — who received X3DH).
 *
 * @param {Uint8Array} sharedSecret — The SK from X3DH (32 bytes)
 * @param {Object} ourSignedPreKeyPair — Bob's signed prekey pair { publicKey, privateKey }
 * @returns {Object} RatchetState
 */
export function initReceiverRatchet(sharedSecret, ourSignedPreKeyPair) {
  return {
    dhSendingKeyPair: ourSignedPreKeyPair,
    dhReceivingPublicKey: null,
    rootKey: sharedSecret,
    sendingChainKey: null,
    sendingCounter: 0,
    receivingChainKey: null,
    receivingCounter: 0,
    previousSendingCounter: 0,
    skippedKeys: new Map(),
  };
}

// ── Encrypt ───────────────────────────────────────────

/**
 * Encrypt a plaintext message using the Double Ratchet.
 * Each call advances the symmetric ratchet — every message
 * gets a unique key that is deleted after use.
 *
 * @param {Object} state — RatchetState (mutated in place)
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} associatedData
 * @returns {Object} EncryptedMessage { header, nonce, ciphertext }
 */
export function ratchetEncrypt(state, plaintext, associatedData) {
  if (!state.sendingChainKey) {
    throw new Error('Sending chain not initialized');
  }

  const [newChainKey, messageKey] = kdfChainKey(state.sendingChainKey);

  secureWipeKey(state.sendingChainKey);
  state.sendingChainKey = newChainKey;

  const header = {
    publicKey: uint8ToBase64(state.dhSendingKeyPair.publicKey),
    counter: state.sendingCounter,
    previousCounter: state.previousSendingCounter,
  };

  state.sendingCounter++;

  const encrypted = encryptAesGcm(messageKey, plaintext, associatedData, header);

  secureWipeKey(messageKey);

  return encrypted;
}

// ── Decrypt ───────────────────────────────────────────

/**
 * Decrypt an incoming message using the Double Ratchet.
 * Handles DH ratchet steps and out-of-order messages.
 *
 * @param {Object} state — RatchetState (mutated in place)
 * @param {Object} message — EncryptedMessage { header, nonce, ciphertext }
 * @param {Uint8Array} associatedData
 * @returns {Uint8Array} plaintext
 */
export function ratchetDecrypt(state, message, associatedData) {
  const headerPubKey = base64ToUint8(message.header.publicKey);

  // Check if this is a skipped message we already have a key for
  const skipKey = makeSkipKey(message.header.publicKey, message.header.counter);
  const skippedMessageKey = state.skippedKeys.get(skipKey);
  if (skippedMessageKey) {
    state.skippedKeys.delete(skipKey);
    const plaintext = decryptAesGcm(skippedMessageKey, message, associatedData);
    secureWipeKey(skippedMessageKey);
    return plaintext;
  }

  // Check if we need a DH ratchet step (new public key from sender)
  if (
    !state.dhReceivingPublicKey ||
    !uint8ArrayEquals(headerPubKey, state.dhReceivingPublicKey)
  ) {
    // Skip any remaining messages in the current receiving chain
    if (state.receivingChainKey) {
      skipMessageKeys(state, state.dhReceivingPublicKey, message.header.previousCounter);
    }

    // Perform DH ratchet step
    dhRatchetStep(state, headerPubKey);
  }

  // Skip ahead if counter is higher than expected (out-of-order)
  skipMessageKeys(
    state,
    base64ToUint8(message.header.publicKey),
    message.header.counter
  );

  // Derive message key from receiving chain
  if (!state.receivingChainKey) {
    throw new Error('Receiving chain not initialized');
  }

  const [newChainKey, messageKey] = kdfChainKey(state.receivingChainKey);
  secureWipeKey(state.receivingChainKey);
  state.receivingChainKey = newChainKey;
  state.receivingCounter++;

  const plaintext = decryptAesGcm(messageKey, message, associatedData);
  secureWipeKey(messageKey);

  return plaintext;
}

// ── DH Ratchet Step ───────────────────────────────────

function dhRatchetStep(state, theirPublicKey) {
  state.previousSendingCounter = state.sendingCounter;
  state.sendingCounter = 0;
  state.receivingCounter = 0;
  state.dhReceivingPublicKey = theirPublicKey;

  // DH with their new public key and our current private key → receiving chain
  const dhReceive = x25519.getSharedSecret(
    state.dhSendingKeyPair.privateKey,
    theirPublicKey
  );
  const [rootKey1, receivingChainKey] = kdfRootKey(state.rootKey, dhReceive);
  secureWipeKey(dhReceive);
  secureWipeKey(state.rootKey);
  state.rootKey = rootKey1;
  state.receivingChainKey = receivingChainKey;

  // Generate new DH key pair for our next sending
  const oldKeyPair = state.dhSendingKeyPair;
  state.dhSendingKeyPair = generateDHKeyPair();
  secureWipeKey(oldKeyPair.privateKey);

  // DH with their public key and our NEW private key → sending chain
  const dhSend = x25519.getSharedSecret(
    state.dhSendingKeyPair.privateKey,
    theirPublicKey
  );
  const [rootKey2, sendingChainKey] = kdfRootKey(state.rootKey, dhSend);
  secureWipeKey(dhSend);
  secureWipeKey(state.rootKey);
  state.rootKey = rootKey2;
  state.sendingChainKey = sendingChainKey;
}

// ── Skip Message Keys ─────────────────────────────────

function skipMessageKeys(state, theirPublicKey, until) {
  if (!state.receivingChainKey || !theirPublicKey) return;

  if (until - state.receivingCounter > MAX_SKIP) {
    throw new Error('Too many skipped messages');
  }

  const pubKeyBase64 = uint8ToBase64(theirPublicKey);

  while (state.receivingCounter < until) {
    const [newChainKey, messageKey] = kdfChainKey(state.receivingChainKey);
    secureWipeKey(state.receivingChainKey);
    state.receivingChainKey = newChainKey;

    const key = makeSkipKey(pubKeyBase64, state.receivingCounter);
    state.skippedKeys.set(key, messageKey);
    state.receivingCounter++;
  }
}

// ── Serialization ─────────────────────────────────────
// Format matches mobile exactly for cross-platform session resumption.

/**
 * Serialize ratchet state for encrypted local storage.
 * NEVER send this to the server.
 */
export function serializeRatchetState(state) {
  const serializable = {
    dhSendPub: uint8ToBase64(state.dhSendingKeyPair.publicKey),
    dhSendPriv: uint8ToBase64(state.dhSendingKeyPair.privateKey),
    dhRecvPub: state.dhReceivingPublicKey
      ? uint8ToBase64(state.dhReceivingPublicKey)
      : null,
    rootKey: uint8ToBase64(state.rootKey),
    sendChainKey: state.sendingChainKey
      ? uint8ToBase64(state.sendingChainKey)
      : null,
    sendCounter: state.sendingCounter,
    recvChainKey: state.receivingChainKey
      ? uint8ToBase64(state.receivingChainKey)
      : null,
    recvCounter: state.receivingCounter,
    prevSendCounter: state.previousSendingCounter,
    skipped: Array.from(state.skippedKeys.entries()).map(([k, v]) => [
      k,
      uint8ToBase64(v),
    ]),
  };
  return JSON.stringify(serializable);
}

/**
 * Deserialize ratchet state from encrypted local storage.
 */
export function deserializeRatchetState(json) {
  const data = JSON.parse(json);
  return {
    dhSendingKeyPair: {
      publicKey: base64ToUint8(data.dhSendPub),
      privateKey: base64ToUint8(data.dhSendPriv),
    },
    dhReceivingPublicKey: data.dhRecvPub
      ? base64ToUint8(data.dhRecvPub)
      : null,
    rootKey: base64ToUint8(data.rootKey),
    sendingChainKey: data.sendChainKey
      ? base64ToUint8(data.sendChainKey)
      : null,
    sendingCounter: data.sendCounter,
    receivingChainKey: data.recvChainKey
      ? base64ToUint8(data.recvChainKey)
      : null,
    receivingCounter: data.recvCounter,
    previousSendingCounter: data.prevSendCounter,
    skippedKeys: new Map(
      (data.skipped || []).map(([k, v]) => [k, base64ToUint8(v)])
    ),
  };
}

// ── Exported constants for cross-platform verification ──

export const KDF_CONSTANTS = {
  RATCHET_INFO_ROOT,
  RATCHET_INFO_CHAIN,
  MESSAGE_KEY_SEED,
  CHAIN_KEY_SEED,
  MAX_SKIP,
};
