// ═══════════════════════════════════════════════════════
// PHANTOM — X3DH (Extended Triple Diffie-Hellman)
// ═══════════════════════════════════════════════════════
// Implements the Signal Protocol X3DH key agreement.
// All computation happens on-device. The server NEVER
// participates in or sees the shared secret.
//
// Protocol flow:
// 1. Alice fetches Bob's public key bundle from server
// 2. Alice performs 3-4 DH operations locally
// 3. Alice derives a shared secret
// 4. Alice sends initial message with her ephemeral public key
// 5. Bob performs the same DH operations to derive same secret

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { KeyPair, uint8ToBase64, base64ToUint8, secureWipeKey } from './keyDerivation';

const X3DH_INFO = new TextEncoder().encode('PhantomX3DH');
const PHANTOM_PROTOCOL_BYTES = new Uint8Array(32).fill(0xff); // 32 0xFF bytes per Signal spec

export interface X3DHPublicBundle {
  identityKey: string;       // base64 Ed25519 public key
  signedPreKey: string;      // base64 X25519 public key
  signedPreKeySignature: string; // base64
  oneTimePreKey?: string;    // base64 X25519 public key (may be absent)
}

export interface X3DHSenderResult {
  sharedSecret: Uint8Array;        // 32-byte shared secret for Double Ratchet
  ephemeralPublicKey: string;      // base64 — sent to recipient
  usedOneTimePreKey: boolean;
  associatedData: Uint8Array;      // AD for initial message encryption
}

export interface X3DHReceiverParams {
  identityKeyPair: KeyPair;        // Our identity key
  signedPreKeyPair: KeyPair;       // Our signed prekey
  oneTimePreKeyPair?: KeyPair;     // Our one-time prekey (if used)
  senderIdentityKey: Uint8Array;   // Sender's identity public key
  senderEphemeralKey: Uint8Array;  // Sender's ephemeral public key
}

/**
 * X3DH — Sender side (Alice initiating a conversation).
 *
 * Alice performs:
 *   DH1 = DH(IK_A, SPK_B)       — Alice's identity, Bob's signed prekey
 *   DH2 = DH(EK_A, IK_B)        — Alice's ephemeral, Bob's identity
 *   DH3 = DH(EK_A, SPK_B)       — Alice's ephemeral, Bob's signed prekey
 *   DH4 = DH(EK_A, OPK_B)       — Alice's ephemeral, Bob's one-time prekey (optional)
 *   SK  = HKDF(DH1 || DH2 || DH3 [|| DH4])
 */
export function x3dhSender(
  senderIdentityKeyPair: KeyPair,
  recipientBundle: X3DHPublicBundle
): X3DHSenderResult {
  // Generate ephemeral key pair for this session
  const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

  const recipientIdentityKey = base64ToUint8(recipientBundle.identityKey);
  const recipientSignedPreKey = base64ToUint8(recipientBundle.signedPreKey);

  // Convert sender's Ed25519 identity key to X25519 for DH
  // In practice, we store both Ed25519 (signing) and X25519 (DH) versions
  const senderIdentityDH = senderIdentityKeyPair.privateKey;

  // DH1: sender identity × recipient signed prekey
  const dh1 = x25519.getSharedSecret(senderIdentityDH, recipientSignedPreKey);

  // DH2: sender ephemeral × recipient identity key
  const dh2 = x25519.getSharedSecret(ephemeralPrivateKey, recipientIdentityKey);

  // DH3: sender ephemeral × recipient signed prekey
  const dh3 = x25519.getSharedSecret(ephemeralPrivateKey, recipientSignedPreKey);

  let dhConcat: Uint8Array;
  let usedOneTimePreKey = false;

  if (recipientBundle.oneTimePreKey) {
    // DH4: sender ephemeral × recipient one-time prekey
    const recipientOTPK = base64ToUint8(recipientBundle.oneTimePreKey);
    const dh4 = x25519.getSharedSecret(ephemeralPrivateKey, recipientOTPK);
    dhConcat = concatBytes(PHANTOM_PROTOCOL_BYTES, dh1, dh2, dh3, dh4);
    usedOneTimePreKey = true;

    // Wipe DH4 from memory
    secureWipeKey(dh4);
  } else {
    dhConcat = concatBytes(PHANTOM_PROTOCOL_BYTES, dh1, dh2, dh3);
  }

  // Derive shared secret via HKDF
  const sharedSecret = hkdf(sha256, dhConcat, new Uint8Array(32), X3DH_INFO, 32);

  // Associated data: sender identity || recipient identity
  const associatedData = concatBytes(
    senderIdentityKeyPair.publicKey,
    recipientIdentityKey
  );

  // Wipe intermediate secrets from memory
  secureWipeKey(dh1);
  secureWipeKey(dh2);
  secureWipeKey(dh3);
  secureWipeKey(dhConcat);
  secureWipeKey(ephemeralPrivateKey);

  return {
    sharedSecret,
    ephemeralPublicKey: uint8ToBase64(ephemeralPublicKey),
    usedOneTimePreKey,
    associatedData,
  };
}

/**
 * X3DH — Receiver side (Bob receiving initial message).
 *
 * Bob performs the same DH operations in reverse:
 *   DH1 = DH(SPK_B, IK_A)
 *   DH2 = DH(IK_B, EK_A)
 *   DH3 = DH(SPK_B, EK_A)
 *   DH4 = DH(OPK_B, EK_A)  (if one-time prekey was used)
 *   SK  = HKDF(DH1 || DH2 || DH3 [|| DH4])
 */
export function x3dhReceiver(params: X3DHReceiverParams): {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
} {
  const {
    identityKeyPair,
    signedPreKeyPair,
    oneTimePreKeyPair,
    senderIdentityKey,
    senderEphemeralKey,
  } = params;

  // DH1: our signed prekey × sender identity key
  const dh1 = x25519.getSharedSecret(signedPreKeyPair.privateKey, senderIdentityKey);

  // DH2: our identity key × sender ephemeral key
  const dh2 = x25519.getSharedSecret(identityKeyPair.privateKey, senderEphemeralKey);

  // DH3: our signed prekey × sender ephemeral key
  const dh3 = x25519.getSharedSecret(signedPreKeyPair.privateKey, senderEphemeralKey);

  let dhConcat: Uint8Array;

  if (oneTimePreKeyPair) {
    // DH4: our one-time prekey × sender ephemeral key
    const dh4 = x25519.getSharedSecret(oneTimePreKeyPair.privateKey, senderEphemeralKey);
    dhConcat = concatBytes(PHANTOM_PROTOCOL_BYTES, dh1, dh2, dh3, dh4);
    secureWipeKey(dh4);
    // One-time prekey is now consumed — delete it
    secureWipeKey(oneTimePreKeyPair.privateKey);
  } else {
    dhConcat = concatBytes(PHANTOM_PROTOCOL_BYTES, dh1, dh2, dh3);
  }

  // Derive shared secret via HKDF
  const sharedSecret = hkdf(sha256, dhConcat, new Uint8Array(32), X3DH_INFO, 32);

  // Associated data: sender identity || our identity
  const associatedData = concatBytes(senderIdentityKey, identityKeyPair.publicKey);

  // Wipe intermediates
  secureWipeKey(dh1);
  secureWipeKey(dh2);
  secureWipeKey(dh3);
  secureWipeKey(dhConcat);

  return { sharedSecret, associatedData };
}

/**
 * Generate an ephemeral X25519 key pair (used once per X3DH exchange).
 */
export function generateEphemeralKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}
