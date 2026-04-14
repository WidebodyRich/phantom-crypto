// ═══════════════════════════════════════════════════════
// PHANTOM — Double Ratchet Algorithm
// ═══════════════════════════════════════════════════════
// Every single message gets a unique encryption key.
// Compromising one key reveals nothing about past or
// future messages. Keys are deleted immediately after use.
//
// Two ratchets work together:
// 1. Symmetric-key ratchet (KDF chain) — new key per message
// 2. DH ratchet — new DH exchange on each reply turn
//
// This implements the full Signal Double Ratchet specification.

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { KeyPair, uint8ToBase64, base64ToUint8, secureWipeKey } from './keyDerivation';

const RATCHET_INFO_ROOT = new TextEncoder().encode('PhantomRootRatchet');
const RATCHET_INFO_CHAIN = new TextEncoder().encode('PhantomChainRatchet');
const MESSAGE_KEY_SEED = new Uint8Array([0x01]);
const CHAIN_KEY_SEED = new Uint8Array([0x02]);

// ── Ratchet State ─────────────────────────────────────

export interface RatchetState {
  // DH ratchet
  dhSendingKeyPair: KeyPair;          // Our current DH ratchet key pair
  dhReceivingPublicKey: Uint8Array | null; // Their current DH ratchet public key

  // Root key
  rootKey: Uint8Array;                // 32 bytes — evolves with each DH ratchet step

  // Sending chain
  sendingChainKey: Uint8Array | null; // Current sending chain key
  sendingCounter: number;              // Messages sent in current sending chain

  // Receiving chain
  receivingChainKey: Uint8Array | null; // Current receiving chain key
  receivingCounter: number;             // Messages received in current receiving chain

  // Previous sending chain counter (for out-of-order messages)
  previousSendingCounter: number;

  // Skipped message keys (for out-of-order delivery)
  skippedKeys: Map<string, Uint8Array>; // "publicKey:counter" → message key
}

export interface RatchetHeader {
  publicKey: string;       // base64 — sender's current DH ratchet public key
  counter: number;          // Message number in current sending chain
  previousCounter: number;  // Length of previous sending chain
}

export interface EncryptedMessage {
  header: RatchetHeader;
  nonce: string;            // base64 — AES-GCM nonce
  ciphertext: string;       // base64 — encrypted message
}

const MAX_SKIP = 1000; // Maximum messages to skip for out-of-order handling

// ── Initialization ────────────────────────────────────

/**
 * Initialize ratchet state for the sender (Alice — who initiated X3DH).
 * Called after X3DH completes.
 *
 * @param sharedSecret — The SK from X3DH
 * @param recipientPublicKey — Bob's signed prekey (used as initial DH ratchet key)
 */
export function initSenderRatchet(
  sharedSecret: Uint8Array,
  recipientPublicKey: Uint8Array
): RatchetState {
  // Generate our first DH ratchet key pair
  const dhKeyPair = generateDHKeyPair();

  // Perform initial DH ratchet step
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
 * @param sharedSecret — The SK from X3DH
 * @param ourSignedPreKeyPair — Bob's signed prekey pair (used as initial DH ratchet key)
 */
export function initReceiverRatchet(
  sharedSecret: Uint8Array,
  ourSignedPreKeyPair: KeyPair
): RatchetState {
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
 */
export function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
  associatedData: Uint8Array
): EncryptedMessage {
  // Derive message key from sending chain
  if (!state.sendingChainKey) {
    throw new Error('Sending chain not initialized');
  }

  const [newChainKey, messageKey] = kdfChainKey(state.sendingChainKey);

  // Advance sending chain
  secureWipeKey(state.sendingChainKey);
  state.sendingChainKey = newChainKey;

  // Build header
  const header: RatchetHeader = {
    publicKey: uint8ToBase64(state.dhSendingKeyPair.publicKey),
    counter: state.sendingCounter,
    previousCounter: state.previousSendingCounter,
  };

  state.sendingCounter++;

  // Encrypt with AES-256-GCM
  const encrypted = encryptAesGcm(messageKey, plaintext, associatedData, header);

  // Wipe message key immediately after use
  secureWipeKey(messageKey);

  return encrypted;
}

// ── Decrypt ───────────────────────────────────────────

/**
 * Decrypt an incoming message using the Double Ratchet.
 * Handles DH ratchet steps and out-of-order messages.
 */
export function ratchetDecrypt(
  state: RatchetState,
  message: EncryptedMessage,
  associatedData: Uint8Array
): Uint8Array {
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
      skipMessageKeys(state, state.dhReceivingPublicKey!, message.header.previousCounter);
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

  // Decrypt
  const plaintext = decryptAesGcm(messageKey, message, associatedData);
  secureWipeKey(messageKey);

  return plaintext;
}

// ── DH Ratchet Step ───────────────────────────────────

/**
 * Perform a DH ratchet step.
 * Generates a new DH key pair and derives new root + chain keys.
 * This is what provides forward secrecy — old keys can't decrypt new messages.
 */
function dhRatchetStep(state: RatchetState, theirPublicKey: Uint8Array): void {
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

/**
 * Store skipped message keys for out-of-order delivery.
 * This allows decrypting messages that arrive out of sequence.
 */
function skipMessageKeys(
  state: RatchetState,
  theirPublicKey: Uint8Array | null,
  until: number
): void {
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

// ── KDF Functions ─────────────────────────────────────

/**
 * Root key KDF: derives new root key + chain key from DH output.
 * Uses HKDF with SHA-256.
 */
function kdfRootKey(
  rootKey: Uint8Array,
  dhOutput: Uint8Array
): [Uint8Array, Uint8Array] {
  const derived = hkdf(sha256, dhOutput, rootKey, RATCHET_INFO_ROOT, 64);
  const newRootKey = derived.slice(0, 32);
  const chainKey = derived.slice(32, 64);
  return [newRootKey, chainKey];
}

/**
 * Chain key KDF: derives new chain key + message key.
 * Uses HMAC-SHA256 with different constants to separate outputs.
 */
function kdfChainKey(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newChainKey = hmac(sha256, chainKey, CHAIN_KEY_SEED);
  const messageKey = hmac(sha256, chainKey, MESSAGE_KEY_SEED);
  return [newChainKey, messageKey];
}

// ── AES-GCM Encryption ───────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 * Nonce is randomly generated per message (96 bits).
 */
function encryptAesGcm(
  messageKey: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  header: RatchetHeader
): EncryptedMessage {
  const nonce = randomBytes(12); // 96-bit nonce for AES-GCM

  // Include header in AAD for authentication
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
function decryptAesGcm(
  messageKey: Uint8Array,
  message: EncryptedMessage,
  associatedData: Uint8Array
): Uint8Array {
  const nonce = base64ToUint8(message.nonce);
  const ciphertext = base64ToUint8(message.ciphertext);

  const headerBytes = new TextEncoder().encode(JSON.stringify(message.header));
  const aad = concatBytes(associatedData, headerBytes);

  const aes = gcm(messageKey, nonce, aad);
  return aes.decrypt(ciphertext);
}

// ── Utility Functions ─────────────────────────────────

function generateDHKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function makeSkipKey(publicKeyBase64: string, counter: number): string {
  return `${publicKeyBase64}:${counter}`;
}

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Serialize ratchet state for encrypted local storage.
 * NEVER send this to the server.
 */
export function serializeRatchetState(state: RatchetState): string {
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
export function deserializeRatchetState(json: string): RatchetState {
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
      (data.skipped as [string, string][]).map(([k, v]) => [k, base64ToUint8(v)])
    ),
  };
}
