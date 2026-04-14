// ═══════════════════════════════════════════════════════
// PHANTOM — Sender Keys (Group E2EE)
// ═══════════════════════════════════════════════════════
// Signal Sender Keys protocol for efficient group messaging.
//
// Instead of encrypting once per member (O(n) per message),
// each member has a "sender key" that the entire group shares.
// When you send a message, you encrypt ONCE with your sender key.
// All group members can decrypt because they have your sender key.
//
// Sender keys are distributed via 1:1 E2EE channels (pairwise).
// The server never sees sender keys in plaintext.

import { gcm } from '@noble/ciphers/aes';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes, concatBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import {
  KeyPair,
  uint8ToBase64,
  base64ToUint8,
  secureWipeKey,
} from './keyDerivation';

const SENDER_KEY_INFO = new TextEncoder().encode('PhantomSenderKey');
const CHAIN_SEED = new Uint8Array([0x01]);

// ── Types ─────────────────────────────────────────────

export interface SenderKeyState {
  chainKey: Uint8Array;          // Current chain key (ratchets forward)
  signingKeyPair: KeyPair;       // Ed25519 key for signing messages
  iteration: number;              // Current chain iteration
}

export interface SenderKeyDistribution {
  groupId: string;
  senderUserId: string;
  chainKey: string;               // base64
  signingPublicKey: string;       // base64
  iteration: number;
}

export interface GroupEncryptedMessage {
  senderKeyId: string;            // groupId:senderUserId
  iteration: number;
  nonce: string;                  // base64
  ciphertext: string;             // base64
  signature: string;              // base64 — proves sender authenticity
}

// ── Sender Key Manager ────────────────────────────────

export class SenderKeyManager {
  // Our sender key for each group we're in
  private ourKeys: Map<string, SenderKeyState> = new Map();
  // Other members' sender keys: groupId:userId → state
  private peerKeys: Map<string, SenderKeyState> = new Map();

  /**
   * Create a new sender key for a group.
   * Called when joining a group or when rotating keys.
   */
  createSenderKey(groupId: string, userId: string): SenderKeyDistribution {
    const chainKey = randomBytes(32);
    const signingPrivateKey = ed25519.utils.randomPrivateKey();
    const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);

    const state: SenderKeyState = {
      chainKey: new Uint8Array(chainKey),
      signingKeyPair: {
        publicKey: signingPublicKey,
        privateKey: signingPrivateKey,
      },
      iteration: 0,
    };

    this.ourKeys.set(groupId, state);

    return {
      groupId,
      senderUserId: userId,
      chainKey: uint8ToBase64(chainKey),
      signingPublicKey: uint8ToBase64(signingPublicKey),
      iteration: 0,
    };
  }

  /**
   * Process a received sender key distribution from another member.
   * This arrives via the 1:1 E2EE channel (already decrypted by Double Ratchet).
   */
  receiveSenderKey(distribution: SenderKeyDistribution): void {
    const key = `${distribution.groupId}:${distribution.senderUserId}`;

    const state: SenderKeyState = {
      chainKey: base64ToUint8(distribution.chainKey),
      signingKeyPair: {
        publicKey: base64ToUint8(distribution.signingPublicKey),
        privateKey: new Uint8Array(0), // We don't have their private signing key
      },
      iteration: distribution.iteration,
    };

    this.peerKeys.set(key, state);
  }

  /**
   * Encrypt a message for a group using our sender key.
   * One encryption serves all group members.
   */
  encrypt(
    groupId: string,
    userId: string,
    plaintext: Uint8Array
  ): GroupEncryptedMessage {
    const state = this.ourKeys.get(groupId);
    if (!state) throw new Error('NO_SENDER_KEY');

    // Derive message key from chain
    const messageKey = deriveMessageKey(state.chainKey, state.iteration);

    // Advance chain
    const newChainKey = advanceChainKey(state.chainKey);
    secureWipeKey(state.chainKey);
    state.chainKey = newChainKey;

    const currentIteration = state.iteration;
    state.iteration++;

    // Encrypt with AES-256-GCM
    const nonce = randomBytes(12);
    const aes = gcm(messageKey, nonce);
    const ciphertext = aes.encrypt(plaintext);
    secureWipeKey(messageKey);

    // Sign the ciphertext for sender authenticity
    const signature = ed25519.sign(ciphertext, state.signingKeyPair.privateKey);

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
  decrypt(message: GroupEncryptedMessage): Uint8Array {
    const state = this.peerKeys.get(message.senderKeyId);
    if (!state) throw new Error('NO_SENDER_KEY_FOR_PEER');

    // Verify signature
    const ciphertextBytes = base64ToUint8(message.ciphertext);
    const signatureBytes = base64ToUint8(message.signature);

    const isValid = ed25519.verify(
      signatureBytes,
      ciphertextBytes,
      state.signingKeyPair.publicKey
    );
    if (!isValid) throw new Error('INVALID_SENDER_SIGNATURE');

    // Fast-forward chain if needed (for out-of-order messages)
    let chainKey = state.chainKey;
    let currentIteration = state.iteration;

    if (message.iteration < currentIteration) {
      throw new Error('MESSAGE_REPLAY_DETECTED');
    }

    // Advance chain to match message iteration
    while (currentIteration < message.iteration) {
      const newChainKey = advanceChainKey(chainKey);
      if (chainKey !== state.chainKey) secureWipeKey(chainKey);
      chainKey = newChainKey;
      currentIteration++;
    }

    // Derive message key
    const messageKey = deriveMessageKey(chainKey, message.iteration);

    // Update state
    const nextChain = advanceChainKey(chainKey);
    if (chainKey !== state.chainKey) secureWipeKey(chainKey);
    secureWipeKey(state.chainKey);
    state.chainKey = nextChain;
    state.iteration = message.iteration + 1;

    // Decrypt
    const nonce = base64ToUint8(message.nonce);
    const aes = gcm(messageKey, nonce);
    const plaintext = aes.decrypt(ciphertextBytes);
    secureWipeKey(messageKey);

    return plaintext;
  }

  /**
   * Rotate sender key for a group (e.g., when a member is removed).
   * All remaining members get the new key via 1:1 E2EE channels.
   */
  rotateSenderKey(groupId: string, userId: string): SenderKeyDistribution {
    // Wipe old key
    const oldState = this.ourKeys.get(groupId);
    if (oldState) {
      secureWipeKey(oldState.chainKey);
      secureWipeKey(oldState.signingKeyPair.privateKey);
    }

    // Generate new key
    return this.createSenderKey(groupId, userId);
  }

  /**
   * Remove all sender keys for a group (when leaving).
   */
  removeGroupKeys(groupId: string): void {
    const ourKey = this.ourKeys.get(groupId);
    if (ourKey) {
      secureWipeKey(ourKey.chainKey);
      secureWipeKey(ourKey.signingKeyPair.privateKey);
      this.ourKeys.delete(groupId);
    }

    // Remove all peer keys for this group
    for (const [key, state] of this.peerKeys) {
      if (key.startsWith(`${groupId}:`)) {
        secureWipeKey(state.chainKey);
        this.peerKeys.delete(key);
      }
    }
  }

  /**
   * Wipe all keys (panic).
   */
  wipeAll(): void {
    for (const [, state] of this.ourKeys) {
      secureWipeKey(state.chainKey);
      secureWipeKey(state.signingKeyPair.privateKey);
    }
    for (const [, state] of this.peerKeys) {
      secureWipeKey(state.chainKey);
    }
    this.ourKeys.clear();
    this.peerKeys.clear();
  }

  /**
   * Serialize for encrypted local storage.
   */
  serialize(): string {
    const data = {
      ourKeys: Array.from(this.ourKeys.entries()).map(([groupId, state]) => ({
        groupId,
        chainKey: uint8ToBase64(state.chainKey),
        signingPub: uint8ToBase64(state.signingKeyPair.publicKey),
        signingPriv: uint8ToBase64(state.signingKeyPair.privateKey),
        iteration: state.iteration,
      })),
      peerKeys: Array.from(this.peerKeys.entries()).map(([key, state]) => ({
        key,
        chainKey: uint8ToBase64(state.chainKey),
        signingPub: uint8ToBase64(state.signingKeyPair.publicKey),
        iteration: state.iteration,
      })),
    };
    return JSON.stringify(data);
  }

  /**
   * Deserialize from encrypted local storage.
   */
  static deserialize(json: string): SenderKeyManager {
    const manager = new SenderKeyManager();
    const data = JSON.parse(json);

    for (const entry of data.ourKeys) {
      manager.ourKeys.set(entry.groupId, {
        chainKey: base64ToUint8(entry.chainKey),
        signingKeyPair: {
          publicKey: base64ToUint8(entry.signingPub),
          privateKey: base64ToUint8(entry.signingPriv),
        },
        iteration: entry.iteration,
      });
    }

    for (const entry of data.peerKeys) {
      manager.peerKeys.set(entry.key, {
        chainKey: base64ToUint8(entry.chainKey),
        signingKeyPair: {
          publicKey: base64ToUint8(entry.signingPub),
          privateKey: new Uint8Array(0),
        },
        iteration: entry.iteration,
      });
    }

    return manager;
  }
}

// ── KDF Helpers ───────────────────────────────────────

function deriveMessageKey(chainKey: Uint8Array, iteration: number): Uint8Array {
  const iterBytes = new TextEncoder().encode(iteration.toString());
  return hkdf(sha256, chainKey, iterBytes, SENDER_KEY_INFO, 32);
}

function advanceChainKey(chainKey: Uint8Array): Uint8Array {
  return hmac(sha256, chainKey, CHAIN_SEED);
}
