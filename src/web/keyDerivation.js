/**
 * PHANTOM — Key Derivation from BIP39 Mnemonic (Web)
 *
 * Derives ALL cryptographic keys from a single 12-word mnemonic:
 * - Ed25519 identity keypair (for signing, authentication)
 * - X25519 signed prekey pair (for X3DH key exchange)
 * - X25519 one-time prekeys (for forward secrecy)
 * - BIP84 Bitcoin wallet keys (separate derivation in btcWallet.js)
 *
 * This means ONE mnemonic backup recovers everything.
 * Same derivation paths as mobile/src/crypto/seedPhrase.ts.
 *
 * DERIVATION PATHS (must match mobile exactly):
 *   Identity:      m/44'/0'/0'
 *   Signed PreKey: m/44'/0'/1'
 *   One-Time PreKeys: m/44'/0'/2'/i (for i = 0..N)
 */

import { x25519 } from '@noble/curves/ed25519';
import { ed25519 } from '@noble/curves/ed25519';
import { HDKey } from '@scure/bip32';
import * as bip39 from 'bip39';

// Derivation paths — MUST match mobile seedPhrase.ts exactly
const IDENTITY_PATH = "m/44'/0'/0'";
const SIGNED_PREKEY_PATH = "m/44'/0'/1'";
const ONE_TIME_PREKEY_BASE_PATH = "m/44'/0'/2'";

/**
 * Generate a new 12-word BIP39 mnemonic.
 */
export function generateMnemonic() {
  return bip39.generateMnemonic(128); // 128 bits = 12 words
}

/**
 * Validate a BIP39 mnemonic (for recovery flow).
 */
export function validateMnemonic(mnemonic) {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * Convert mnemonic to 512-bit seed.
 */
export async function mnemonicToSeed(mnemonic) {
  const seedBuffer = await bip39.mnemonicToSeed(mnemonic);
  return new Uint8Array(seedBuffer);
}

/**
 * Derive Ed25519 keypair from a 32-byte private key.
 * The private key bytes are used as the Ed25519 seed.
 */
function deriveEd25519KeyPair(privateKeyBytes) {
  // Ed25519 uses 32-byte seed → derive public key
  const seed = new Uint8Array(privateKeyBytes.slice(0, 32));
  const publicKey = ed25519.getPublicKey(seed);
  return { publicKey, privateKey: seed };
}

/**
 * Derive X25519 keypair from a 32-byte private key.
 */
function deriveX25519KeyPair(privateKeyBytes) {
  const seed = new Uint8Array(privateKeyBytes.slice(0, 32));
  const publicKey = x25519.getPublicKey(seed);
  return { publicKey, privateKey: seed };
}

/**
 * Sign a public key with an Ed25519 private key.
 */
function signPublicKey(signingPrivateKey, publicKeyToSign) {
  return ed25519.sign(publicKeyToSign, signingPrivateKey);
}

/**
 * Derive all messaging keys from a BIP39 seed.
 * Returns the same key material as mobile's deriveKeyMaterial().
 *
 * @param {Uint8Array} seed — 512-bit seed from mnemonicToSeed()
 * @param {number} numOneTimePreKeys — number of OTPs to derive
 * @returns {{ identityKeyPair, signedPreKeyPair, signedPreKeySignature, oneTimePreKeyPairs }}
 */
export function deriveKeyMaterial(seed, numOneTimePreKeys = 20) {
  const master = HDKey.fromMasterSeed(seed);

  // Identity Key (Ed25519 for signing)
  const identityNode = master.derive(IDENTITY_PATH);
  const identityKeyPair = deriveEd25519KeyPair(identityNode.privateKey);

  // Signed PreKey (X25519 for key exchange)
  const signedPreKeyNode = master.derive(SIGNED_PREKEY_PATH);
  const signedPreKeyPair = deriveX25519KeyPair(signedPreKeyNode.privateKey);

  // Sign the signed prekey with identity key
  const signedPreKeySignature = signPublicKey(
    identityKeyPair.privateKey,
    signedPreKeyPair.publicKey
  );

  // One-Time PreKeys (X25519 for X3DH)
  const otpkBase = master.derive(ONE_TIME_PREKEY_BASE_PATH);
  const oneTimePreKeyPairs = [];

  for (let i = 0; i < numOneTimePreKeys; i++) {
    const otpkNode = otpkBase.deriveChild(i);
    oneTimePreKeyPairs.push(deriveX25519KeyPair(otpkNode.privateKey));
  }

  return {
    identityKeyPair,
    signedPreKeyPair,
    signedPreKeySignature,
    oneTimePreKeyPairs,
  };
}

/**
 * Derive additional one-time prekeys starting from a given index.
 */
export function deriveAdditionalPreKeys(seed, startIndex, count) {
  const master = HDKey.fromMasterSeed(seed);
  const otpkBase = master.derive(ONE_TIME_PREKEY_BASE_PATH);
  const keys = [];

  for (let i = startIndex; i < startIndex + count; i++) {
    const otpkNode = otpkBase.deriveChild(i);
    keys.push(deriveX25519KeyPair(otpkNode.privateKey));
  }

  return keys;
}

// Re-export base64 helpers for consistency
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
