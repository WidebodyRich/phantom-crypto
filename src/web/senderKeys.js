/**
 * Sender Keys (Group E2EE) -- PHANTOM MESSENGER v4.0
 * ===================================================
 * Signal Sender Keys protocol for efficient group messaging.
 *
 * Instead of encrypting once per member (O(n) per message),
 * each member has a "sender key" that the entire group shares.
 * When you send a message, you encrypt ONCE with your sender key.
 * All group members can decrypt because they have your sender key.
 *
 * Sender keys are distributed via 1:1 E2EE channels (pairwise).
 * The server never sees sender keys in plaintext.
 *
 * v4.0: Ed25519 signing via @noble/curves (matches mobile client)
 * - Ed25519 for message signing (replaces ECDSA P-256)
 * - AES-256-GCM for message encryption (Web Crypto -- unchanged)
 * - HMAC-SHA256 for chain key ratcheting (@noble/hashes)
 * - HKDF-SHA256 for key derivation (Web Crypto)
 * - Keys stored as raw Uint8Array, base64 encoded for JSON
 *
 * Persisted via vault (PBKDF2-encrypted localStorage).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
// Storage interface — implement with your encrypted storage backend.
const vaultGet = async (key) => localStorage.getItem(key);
const vaultSet = async (key, value) => localStorage.setItem(key, value);

const SENDER_KEY_VAULT_KEY = 'phantom_sender_keys_v1';
const SENDER_KEY_INFO = new TextEncoder().encode('PhantomSenderKey');
const CHAIN_SEED = new Uint8Array([0x01]);

// ── Helpers ──────────────────────────────────────────

function uint8ToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ── KDF Functions ───────────────────────────────────

/**
 * HKDF-SHA256: derive a message key from chain key + iteration.
 * Uses Web Crypto HKDF (algorithm-agnostic, no curve dependency).
 */
async function deriveMessageKey(chainKeyBytes, iteration) {
  const salt = new TextEncoder().encode(iteration.toString());

  const keyMaterial = await crypto.subtle.importKey(
    'raw', chainKeyBytes, 'HKDF', false, ['deriveBits']
  );

  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: SENDER_KEY_INFO },
    keyMaterial,
    256
  );

  return new Uint8Array(derived);
}

/**
 * Advance chain key using HMAC-SHA256(chainKey, 0x01).
 * Uses @noble/hashes for consistency with the rest of the crypto stack.
 */
function advanceChainKey(chainKeyBytes) {
  return hmac(sha256, chainKeyBytes, CHAIN_SEED);
}

// ── Ed25519 Signing ─────────────────────────────────

/**
 * Generate an Ed25519 signing key pair.
 * Returns { publicKey: Uint8Array(32), privateKey: Uint8Array(32) }
 */
function generateSigningKeyPair() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Sign data with Ed25519.
 * Returns Uint8Array (64 bytes signature).
 */
function sign(privateKey, data) {
  const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return ed25519.sign(dataBytes, privateKey);
}

/**
 * Verify an Ed25519 signature.
 * Returns boolean.
 */
function verify(publicKey, signature, data) {
  try {
    const sigBytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
    const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return ed25519.verify(sigBytes, dataBytes, publicKey);
  } catch {
    return false;
  }
}

// ── Sender Key Manager ───────────────────────────────

/**
 * In-memory state for a sender key. Chain keys are raw Uint8Array.
 * Signing keys are raw Uint8Array (Ed25519).
 */

class SenderKeyManager {
  constructor() {
    // Our sender key for each group: groupId -> state
    this.ourKeys = new Map();
    // Peer sender keys: "groupId:userId" -> state
    this.peerKeys = new Map();
  }

  /**
   * Create a new sender key for a group.
   * Returns a distribution object to send to group members via 1:1 E2EE.
   */
  createSenderKey(groupId, userId) {
    const chainKey = crypto.getRandomValues(new Uint8Array(32));
    const signingKeyPair = generateSigningKeyPair();

    const state = {
      chainKey: new Uint8Array(chainKey),
      signingPublicKey: signingKeyPair.publicKey,    // Uint8Array(32)
      signingPrivateKey: signingKeyPair.privateKey,   // Uint8Array(32)
      iteration: 0,
    };

    this.ourKeys.set(groupId, state);

    return {
      groupId,
      senderUserId: userId,
      chainKey: uint8ToBase64(chainKey),
      signingPublicKey: uint8ToBase64(signingKeyPair.publicKey),
      iteration: 0,
    };
  }

  /**
   * Process a received sender key distribution from another member.
   */
  receiveSenderKey(distribution) {
    const key = `${distribution.groupId}:${distribution.senderUserId}`;
    const publicKey = base64ToUint8(distribution.signingPublicKey);

    const state = {
      chainKey: base64ToUint8(distribution.chainKey),
      signingPublicKey: publicKey,     // Uint8Array(32)
      signingPrivateKey: null,          // We don't have their private key
      iteration: distribution.iteration,
    };

    this.peerKeys.set(key, state);
  }

  /**
   * Encrypt a message for a group using our sender key.
   */
  async encrypt(groupId, userId, plaintext) {
    const state = this.ourKeys.get(groupId);
    if (!state) throw new Error('NO_SENDER_KEY');

    // Derive message key from chain
    const messageKey = await deriveMessageKey(state.chainKey, state.iteration);

    // Advance chain (forward secrecy)
    const newChainKey = advanceChainKey(state.chainKey);
    // Wipe old chain key
    state.chainKey.fill(0);
    state.chainKey = newChainKey;

    const currentIteration = state.iteration;
    state.iteration++;

    // Encrypt with AES-256-GCM (Web Crypto)
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.importKey(
      'raw', messageKey, 'AES-GCM', false, ['encrypt']
    );
    const plaintextBytes = typeof plaintext === 'string'
      ? new TextEncoder().encode(plaintext)
      : plaintext;
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce }, aesKey, plaintextBytes
    );
    const ciphertext = new Uint8Array(ciphertextBuf);
    // Wipe message key
    messageKey.fill(0);

    // Sign the ciphertext with Ed25519 for sender authenticity
    const signature = sign(state.signingPrivateKey, ciphertext);

    return {
      senderKeyId: `${groupId}:${userId}`,
      iteration: currentIteration,
      nonce: uint8ToBase64(nonce),
      ciphertext: uint8ToBase64(ciphertext),
      signature: uint8ToBase64(signature),
    };
  }

  /**
   * Decrypt a group message using the sender's sender key.
   */
  async decrypt(message) {
    const state = this.peerKeys.get(message.senderKeyId);
    if (!state) throw new Error('NO_SENDER_KEY_FOR_PEER');

    // Verify Ed25519 signature first
    const ciphertextBytes = base64ToUint8(message.ciphertext);
    const signatureBytes = base64ToUint8(message.signature);

    const isValid = verify(state.signingPublicKey, signatureBytes, ciphertextBytes);
    if (!isValid) throw new Error('INVALID_SENDER_SIGNATURE');

    // Check for replay
    if (message.iteration < state.iteration) {
      throw new Error('MESSAGE_REPLAY_DETECTED');
    }

    // Fast-forward chain to match message iteration (handles out-of-order)
    let chainKey = state.chainKey;
    let currentIteration = state.iteration;
    let isTemp = false;

    while (currentIteration < message.iteration) {
      const newChainKey = advanceChainKey(chainKey);
      if (isTemp) chainKey.fill(0);
      chainKey = newChainKey;
      currentIteration++;
      isTemp = true;
    }

    // Derive message key
    const messageKey = await deriveMessageKey(chainKey, message.iteration);

    // Update state with advanced chain
    const nextChain = advanceChainKey(chainKey);
    if (isTemp) chainKey.fill(0);
    state.chainKey.fill(0);
    state.chainKey = nextChain;
    state.iteration = message.iteration + 1;

    // Decrypt with AES-256-GCM (Web Crypto)
    const nonce = base64ToUint8(message.nonce);
    const aesKey = await crypto.subtle.importKey(
      'raw', messageKey, 'AES-GCM', false, ['decrypt']
    );
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, aesKey, ciphertextBytes
    );
    messageKey.fill(0);

    return new Uint8Array(plaintextBuf);
  }

  /**
   * Rotate sender key for a group (e.g., when a member is removed).
   */
  rotateSenderKey(groupId, userId) {
    const oldState = this.ourKeys.get(groupId);
    if (oldState) {
      oldState.chainKey.fill(0);
    }
    return this.createSenderKey(groupId, userId);
  }

  /**
   * Remove all sender keys for a group (when leaving).
   */
  removeGroupKeys(groupId) {
    const ourKey = this.ourKeys.get(groupId);
    if (ourKey) {
      ourKey.chainKey.fill(0);
      this.ourKeys.delete(groupId);
    }

    for (const [key, state] of this.peerKeys) {
      if (key.startsWith(`${groupId}:`)) {
        state.chainKey.fill(0);
        this.peerKeys.delete(key);
      }
    }
  }

  /**
   * Wipe all keys (panic / logout).
   */
  wipeAll() {
    for (const [, state] of this.ourKeys) {
      state.chainKey.fill(0);
      if (state.signingPrivateKey) state.signingPrivateKey.fill(0);
    }
    for (const [, state] of this.peerKeys) {
      state.chainKey.fill(0);
    }
    this.ourKeys.clear();
    this.peerKeys.clear();
  }

  /**
   * Serialize to JSON for vault-encrypted localStorage.
   * Keys are stored as base64-encoded Uint8Array (no JWK/CryptoKey).
   */
  serialize() {
    const ourKeysArr = [];
    for (const [groupId, state] of this.ourKeys) {
      ourKeysArr.push({
        groupId,
        chainKey: uint8ToBase64(state.chainKey),
        signingPub: uint8ToBase64(state.signingPublicKey),
        signingPriv: state.signingPrivateKey
          ? uint8ToBase64(state.signingPrivateKey)
          : null,
        iteration: state.iteration,
      });
    }

    const peerKeysArr = [];
    for (const [key, state] of this.peerKeys) {
      peerKeysArr.push({
        key,
        chainKey: uint8ToBase64(state.chainKey),
        signingPub: uint8ToBase64(state.signingPublicKey),
        iteration: state.iteration,
      });
    }

    return JSON.stringify({ ourKeys: ourKeysArr, peerKeys: peerKeysArr });
  }

  /**
   * Deserialize from vault-encrypted localStorage.
   */
  static deserialize(json) {
    const manager = new SenderKeyManager();
    const data = JSON.parse(json);

    for (const entry of data.ourKeys || []) {
      manager.ourKeys.set(entry.groupId, {
        chainKey: base64ToUint8(entry.chainKey),
        signingPublicKey: base64ToUint8(entry.signingPub),
        signingPrivateKey: entry.signingPriv
          ? base64ToUint8(entry.signingPriv)
          : null,
        iteration: entry.iteration,
      });
    }

    for (const entry of data.peerKeys || []) {
      manager.peerKeys.set(entry.key, {
        chainKey: base64ToUint8(entry.chainKey),
        signingPublicKey: base64ToUint8(entry.signingPub),
        signingPrivateKey: null,
        iteration: entry.iteration,
      });
    }

    return manager;
  }
}

// ── Singleton Instance ───────────────────────────────

let instance = null;

export function getSenderKeyManager() {
  if (!instance) {
    instance = new SenderKeyManager();
  }
  return instance;
}

export async function saveSenderKeys() {
  if (!instance) return;
  const json = instance.serialize();
  await vaultSet(SENDER_KEY_VAULT_KEY, json);
}

export async function restoreSenderKeys() {
  const json = await vaultGet(SENDER_KEY_VAULT_KEY);
  if (!json) return false;
  try {
    instance = SenderKeyManager.deserialize(json);
    return true;
  } catch (err) {
    console.warn('[SenderKeys] Restore failed:', err.message);
    instance = new SenderKeyManager();
    return false;
  }
}

export function wipeSenderKeys() {
  if (instance) {
    instance.wipeAll();
    instance = null;
  }
  try { localStorage.removeItem(SENDER_KEY_VAULT_KEY); } catch {}
}

export { SenderKeyManager, uint8ToBase64, base64ToUint8 };
