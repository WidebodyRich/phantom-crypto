/**
 * PHANTOM — Session Manager (Web Port)
 *
 * Port of mobile/src/crypto/sessionManager.ts.
 * Manages Double Ratchet sessions for all conversations.
 * Sessions stored in encrypted local storage.
 *
 * Key difference from mobile: web doesn't have sealed sender yet,
 * so sender identity is extracted from the PreKey envelope or
 * from the Double Ratchet session lookup.
 */

import {
  initSenderRatchet,
  initReceiverRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
  uint8ToBase64,
  base64ToUint8,
  secureWipeKey,
} from './doubleRatchet.js';

// Storage interface — implement with your encrypted storage backend.
// Default: localStorage (for demo/testing only — use encrypted vault in production).
const vaultGet = async (key) => localStorage.getItem(key);
const vaultSet = async (key, value) => localStorage.setItem(key, value);
const vaultRemove = async (key) => localStorage.removeItem(key);

const SESSION_PREFIX = 'phantom_session_';

// ── Session State Validation ──────────────────────────

export function validateSerializedSessionData(data) {
  if (!data || typeof data !== 'object') return false;
  if (typeof data.recipientUserId !== 'string') return false;
  if (typeof data.ratchetState !== 'string') return false;
  if (typeof data.associatedData !== 'string') return false;
  if (typeof data.recipientIdentityKey !== 'string') return false;

  try {
    const ratchet = JSON.parse(data.ratchetState);
    if (typeof ratchet.dhSendPub !== 'string') return false;
    if (typeof ratchet.dhSendPriv !== 'string') return false;
    if (typeof ratchet.rootKey !== 'string') return false;
    if (typeof ratchet.sendCounter !== 'number') return false;
    if (typeof ratchet.recvCounter !== 'number') return false;
    return true;
  } catch {
    return false;
  }
}

// ── Stale Session Detection ───────────────────────────

const STALE_THRESHOLD = 3;
const decryptFailures = new Map();

export function recordDecryptFailure(userId) {
  const count = (decryptFailures.get(userId) || 0) + 1;
  decryptFailures.set(userId, count);
  return count >= STALE_THRESHOLD;
}

export function resetDecryptFailures(userId) {
  decryptFailures.delete(userId);
}

export function isSessionStale(userId) {
  return (decryptFailures.get(userId) || 0) >= STALE_THRESHOLD;
}

// ── Message Deduplication ─────────────────────────────

const processedIds = new Set();

export function isDuplicate(messageId) {
  return processedIds.has(messageId);
}

export function markProcessed(messageId) {
  processedIds.add(messageId);
  setTimeout(() => processedIds.delete(messageId), 5 * 60 * 1000);
}

// ── In-memory session cache ───────────────────────────

const sessions = new Map(); // userId → SessionInfo

/**
 * @typedef {Object} SessionInfo
 * @property {string} recipientUserId
 * @property {string} recipientUsername
 * @property {Object} state — RatchetState
 * @property {Uint8Array} associatedData
 * @property {Uint8Array} recipientIdentityKey
 */

// ── X3DH Integration ──────────────────────────────────
// These functions tie X3DH output to Double Ratchet initialization.
// They mirror mobile's sessionManager.ts initOutgoingSession / initIncomingSession.

/**
 * Initialize a new session as the sender (we initiated the conversation).
 *
 * @param {string} recipientUserId
 * @param {string} recipientUsername
 * @param {Uint8Array} sharedSecret — From X3DH (32 bytes)
 * @param {Uint8Array} associatedData — AD from X3DH (identity keys concat)
 * @param {Uint8Array} recipientSignedPreKey — Their signed prekey public key
 * @param {Uint8Array} recipientIdentityKey — Their identity public key
 */
export async function initOutgoingSession(
  recipientUserId,
  recipientUsername,
  sharedSecret,
  associatedData,
  recipientSignedPreKey,
  recipientIdentityKey
) {
  // Initialize Double Ratchet as sender
  const ratchetState = initSenderRatchet(sharedSecret, recipientSignedPreKey);

  // Wipe shared secret — it's now embedded in the ratchet
  secureWipeKey(sharedSecret);

  const session = {
    recipientUserId,
    recipientUsername,
    state: ratchetState,
    associatedData,
    recipientIdentityKey,
  };

  sessions.set(recipientUserId, session);
  await persistSession(recipientUserId);
}

/**
 * Initialize a session as the receiver (someone messaged us first).
 *
 * @param {string} senderUserId — Known from PreKey envelope or sealed sender
 * @param {string} senderUsername
 * @param {Uint8Array} sharedSecret — From X3DH receiver side (32 bytes)
 * @param {Uint8Array} associatedData — AD from X3DH
 * @param {Object} ourSignedPreKeyPair — Our signed prekey { publicKey, privateKey }
 * @param {Uint8Array} senderIdentityKey — Their identity public key
 */
export async function initIncomingSession(
  senderUserId,
  senderUsername,
  sharedSecret,
  associatedData,
  ourSignedPreKeyPair,
  senderIdentityKey
) {
  // Initialize Double Ratchet as receiver
  const ratchetState = initReceiverRatchet(sharedSecret, ourSignedPreKeyPair);

  secureWipeKey(sharedSecret);

  const session = {
    recipientUserId: senderUserId,
    recipientUsername: senderUsername,
    state: ratchetState,
    associatedData,
    recipientIdentityKey: senderIdentityKey,
  };

  sessions.set(senderUserId, session);
  await persistSession(senderUserId);
}

// ── Encrypt / Decrypt ─────────────────────────────────

/**
 * Encrypt a message for an existing session.
 *
 * @param {string} recipientUserId
 * @param {Uint8Array} plaintext
 * @returns {Object} EncryptedMessage { header, nonce, ciphertext }
 */
export async function encryptMessage(recipientUserId, plaintext) {
  const session = await getSession(recipientUserId);
  if (!session) throw new Error('NO_SESSION');

  const encrypted = ratchetEncrypt(
    session.state,
    plaintext,
    session.associatedData
  );

  await persistSession(recipientUserId);

  return encrypted;
}

/**
 * Decrypt an incoming message from an existing session.
 *
 * @param {string} senderUserId
 * @param {Object} encryptedMessage — { header, nonce, ciphertext }
 * @returns {Uint8Array} plaintext
 */
export async function decryptMessage(senderUserId, encryptedMessage) {
  const session = await getSession(senderUserId);
  if (!session) throw new Error('NO_SESSION');

  const plaintext = ratchetDecrypt(
    session.state,
    encryptedMessage,
    session.associatedData
  );

  await persistSession(senderUserId);

  return plaintext;
}

// ── Session Queries ───────────────────────────────────

export function hasSession(userId) {
  return sessions.has(userId);
}

export async function getSessionInfo(userId) {
  return getSession(userId);
}

export function getSessionIdentityKey(userId) {
  const session = sessions.get(userId);
  if (!session) return null;
  return session.recipientIdentityKey;
}

export function getAllSessionIds() {
  return [...sessions.keys()];
}

// ── Session Lifecycle ─────────────────────────────────

/**
 * Delete a session and wipe all key material.
 */
export async function deleteSession(userId) {
  const session = sessions.get(userId);
  if (session) {
    secureWipeKey(session.state.rootKey);
    if (session.state.sendingChainKey) secureWipeKey(session.state.sendingChainKey);
    if (session.state.receivingChainKey) secureWipeKey(session.state.receivingChainKey);
    secureWipeKey(session.state.dhSendingKeyPair.privateKey);
    session.state.skippedKeys.forEach((key) => secureWipeKey(key));
  }
  sessions.delete(userId);
  await vaultRemove(`${SESSION_PREFIX}${userId}`);
}

/**
 * Delete all sessions (panic wipe).
 */
export async function deleteAllSessions() {
  for (const [userId] of sessions) {
    await deleteSession(userId);
  }
}

/**
 * Load all sessions from vault into memory.
 * Called on app startup after authentication.
 */
export async function loadAllSessions() {
  // Scan vault keys for sessions
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(SESSION_PREFIX)) {
      const userId = key.slice(SESSION_PREFIX.length);
      await getSession(userId); // Loads into cache
    }
  }
}

// ── Private: Persistence ──────────────────────────────
// Format matches mobile's sessionManager.ts persistSession exactly.

async function getSession(userId) {
  const cached = sessions.get(userId);
  if (cached) return cached;

  const serialized = await vaultGet(`${SESSION_PREFIX}${userId}`);
  if (!serialized) return null;

  try {
    const data = JSON.parse(serialized);

    // Validate session state before using it
    if (!validateSerializedSessionData(data)) {
      process.stderr?.write?.('[session] Corrupted or incompatible session state detected\n');
      await vaultRemove(`${SESSION_PREFIX}${userId}`);
      return null;
    }

    const session = {
      recipientUserId: data.recipientUserId,
      recipientUsername: data.recipientUsername,
      state: deserializeRatchetState(data.ratchetState),
      associatedData: base64ToUint8(data.associatedData),
      recipientIdentityKey: base64ToUint8(data.recipientIdentityKey),
    };

    sessions.set(userId, session);
    return session;
  } catch (err) {
    // Log type only — never the error message (may contain session data)
    process.stderr?.write?.(`[session] Failed to load session: ${err.name}\n`);
    return null;
  }
}

async function persistSession(userId) {
  const session = sessions.get(userId);
  if (!session) return;

  const data = {
    recipientUserId: session.recipientUserId,
    recipientUsername: session.recipientUsername,
    ratchetState: serializeRatchetState(session.state),
    associatedData: uint8ToBase64(session.associatedData),
    recipientIdentityKey: uint8ToBase64(session.recipientIdentityKey),
  };

  await vaultSet(`${SESSION_PREFIX}${userId}`, JSON.stringify(data));
}
