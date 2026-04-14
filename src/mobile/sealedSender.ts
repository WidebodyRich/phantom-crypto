// ═══════════════════════════════════════════════════════
// PHANTOM — Sealed Sender Protocol
// ═══════════════════════════════════════════════════════
// Eliminates message graph metadata entirely.
// The server CANNOT determine who sent a message to whom.
// Only the recipient can decrypt the sender certificate.
//
// How it works:
// 1. Sender creates a sender certificate (identity + timestamp)
// 2. Sender encrypts the certificate with recipient's identity key
// 3. Server sees only: encrypted blob + recipient ID
// 4. Server cannot correlate sender ↔ recipient
// 5. Recipient decrypts sender certificate to learn who sent it
//
// This makes traffic analysis and social graph construction
// impossible even with full server access.

import { x25519 } from '@noble/curves/ed25519';
import { ed25519 } from '@noble/curves/ed25519';
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';
import {
  KeyPair,
  uint8ToBase64,
  base64ToUint8,
  secureWipeKey,
} from './keyDerivation';
import { EncryptedMessage } from './doubleRatchet';

const SEALED_SENDER_INFO = new TextEncoder().encode('PhantomSealedSender');
const CERT_VERSION = 1;

// ── Types ─────────────────────────────────────────────

export interface SenderCertificate {
  version: number;
  senderUserId: string;
  senderUsername: string;
  senderIdentityKey: string; // base64
  timestamp: number;         // Unix ms — when the message was sealed
  signature: string;         // base64 — self-signed with sender's identity key
}

export interface SealedSenderMessage {
  version: number;
  ephemeralPublicKey: string;     // base64 — one-time key for this seal
  encryptedCertificate: string;   // base64 — sender cert encrypted to recipient
  certificateNonce: string;       // base64
  encryptedContent: string;       // base64 — the actual Double Ratchet message
  contentNonce: string;           // base64
}

// ── Seal (Sender Side) ───────────────────────────────

/**
 * Seal a message for a recipient using the Sealed Sender protocol.
 *
 * Steps:
 * 1. Create and sign a sender certificate
 * 2. Generate ephemeral X25519 key pair
 * 3. DH with ephemeral private + recipient's identity public key
 * 4. Derive encryption key via HKDF
 * 5. Encrypt sender certificate with derived key
 * 6. Encrypt the actual message content separately
 * 7. Bundle everything for transmission
 *
 * The server sees only the sealed blob — it cannot determine the sender.
 */
export function sealMessage(params: {
  senderUserId: string;
  senderUsername: string;
  senderIdentityKeyPair: KeyPair;
  recipientIdentityPublicKey: Uint8Array;
  ratchetMessage: EncryptedMessage;
}): SealedSenderMessage {
  const {
    senderUserId,
    senderUsername,
    senderIdentityKeyPair,
    recipientIdentityPublicKey,
    ratchetMessage,
  } = params;

  // Step 1: Create sender certificate
  const certificate: SenderCertificate = {
    version: CERT_VERSION,
    senderUserId,
    senderUsername,
    senderIdentityKey: uint8ToBase64(senderIdentityKeyPair.publicKey),
    timestamp: Date.now(),
    signature: '', // Will be set below
  };

  // Sign the certificate (excluding the signature field itself)
  const certDataToSign = serializeCertForSigning(certificate);
  const certSignature = ed25519.sign(certDataToSign, senderIdentityKeyPair.privateKey);
  certificate.signature = uint8ToBase64(certSignature);

  // Step 2: Generate ephemeral key pair for this seal
  const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

  // Step 3: DH with ephemeral + recipient identity
  const sharedDH = x25519.getSharedSecret(ephemeralPrivateKey, recipientIdentityPublicKey);

  // Step 4: Derive two keys — one for certificate, one for content
  const derived = hkdf(
    sha256,
    sharedDH,
    ephemeralPublicKey, // Use ephemeral public key as salt
    SEALED_SENDER_INFO,
    64
  );
  const certKey = derived.slice(0, 32);
  const contentKey = derived.slice(32, 64);

  // Wipe DH output
  secureWipeKey(sharedDH);
  secureWipeKey(ephemeralPrivateKey);

  // Step 5: Encrypt sender certificate
  const certNonce = randomBytes(12);
  const certPlaintext = new TextEncoder().encode(JSON.stringify(certificate));
  const certAes = gcm(certKey, certNonce);
  const encryptedCert = certAes.encrypt(certPlaintext);
  secureWipeKey(certKey);

  // Step 6: Encrypt message content
  const contentNonce = randomBytes(12);
  const contentPlaintext = new TextEncoder().encode(JSON.stringify(ratchetMessage));
  const contentAes = gcm(contentKey, contentNonce);
  const encryptedContent = contentAes.encrypt(contentPlaintext);
  secureWipeKey(contentKey);

  // Step 7: Bundle
  return {
    version: CERT_VERSION,
    ephemeralPublicKey: uint8ToBase64(ephemeralPublicKey),
    encryptedCertificate: uint8ToBase64(encryptedCert),
    certificateNonce: uint8ToBase64(certNonce),
    encryptedContent: uint8ToBase64(encryptedContent),
    contentNonce: uint8ToBase64(contentNonce),
  };
}

// ── Unseal (Recipient Side) ──────────────────────────

/**
 * Unseal a message — decrypt the sender certificate and content.
 *
 * Only the recipient (who holds the identity private key)
 * can perform this operation. The server cannot.
 */
export function unsealMessage(params: {
  sealed: SealedSenderMessage;
  recipientIdentityKeyPair: KeyPair;
}): {
  certificate: SenderCertificate;
  ratchetMessage: EncryptedMessage;
} {
  const { sealed, recipientIdentityKeyPair } = params;

  const ephemeralPublicKey = base64ToUint8(sealed.ephemeralPublicKey);

  // DH with our identity private key + sender's ephemeral public key
  const sharedDH = x25519.getSharedSecret(
    recipientIdentityKeyPair.privateKey,
    ephemeralPublicKey
  );

  // Derive the same two keys
  const derived = hkdf(
    sha256,
    sharedDH,
    ephemeralPublicKey,
    SEALED_SENDER_INFO,
    64
  );
  const certKey = derived.slice(0, 32);
  const contentKey = derived.slice(32, 64);
  secureWipeKey(sharedDH);

  // Decrypt sender certificate
  const certNonce = base64ToUint8(sealed.certificateNonce);
  const encryptedCert = base64ToUint8(sealed.encryptedCertificate);
  const certAes = gcm(certKey, certNonce);
  const certPlaintext = certAes.decrypt(encryptedCert);
  secureWipeKey(certKey);

  const certificate: SenderCertificate = JSON.parse(
    new TextDecoder().decode(certPlaintext)
  );

  // Verify sender certificate signature
  const certDataToVerify = serializeCertForSigning(certificate);
  const senderPubKey = base64ToUint8(certificate.senderIdentityKey);
  const certSig = base64ToUint8(certificate.signature);
  const isValid = ed25519.verify(certSig, certDataToVerify, senderPubKey);

  if (!isValid) {
    throw new Error('INVALID_SENDER_CERTIFICATE');
  }

  // Check certificate is not too old (24 hours max)
  const certAge = Date.now() - certificate.timestamp;
  if (certAge > 24 * 60 * 60 * 1000) {
    throw new Error('EXPIRED_SENDER_CERTIFICATE');
  }

  // Decrypt message content
  const contentNonce = base64ToUint8(sealed.contentNonce);
  const encryptedContent = base64ToUint8(sealed.encryptedContent);
  const contentAes = gcm(contentKey, contentNonce);
  const contentPlaintext = contentAes.decrypt(encryptedContent);
  secureWipeKey(contentKey);

  const ratchetMessage: EncryptedMessage = JSON.parse(
    new TextDecoder().decode(contentPlaintext)
  );

  return { certificate, ratchetMessage };
}

// ── Helpers ───────────────────────────────────────────

/**
 * Serialize certificate data for signing/verification.
 * Excludes the signature field itself.
 */
function serializeCertForSigning(cert: SenderCertificate): Uint8Array {
  const data = {
    version: cert.version,
    senderUserId: cert.senderUserId,
    senderUsername: cert.senderUsername,
    senderIdentityKey: cert.senderIdentityKey,
    timestamp: cert.timestamp,
  };
  return new TextEncoder().encode(JSON.stringify(data));
}

/**
 * Create a sealed sender blob string for sending to the server.
 * The server stores this as-is — it cannot decrypt any of it.
 */
export function serializeSealedMessage(sealed: SealedSenderMessage): string {
  return JSON.stringify(sealed);
}

/**
 * Parse a sealed sender blob string received from the server.
 */
export function deserializeSealedMessage(json: string): SealedSenderMessage {
  return JSON.parse(json);
}
