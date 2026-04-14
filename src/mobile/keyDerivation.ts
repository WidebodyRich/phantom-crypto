// ═══════════════════════════════════════════════════════
// PHANTOM — BIP39 Seed Phrase + BIP32 Key Derivation
// ═══════════════════════════════════════════════════════
// Seed phrase is generated and used ONLY on device.
// It NEVER touches the network. NEVER sent to the server.
// All cryptographic keys are derived deterministically
// from the seed phrase, enabling full account recovery.

import * as bip39 from 'bip39';
import { HDKey } from '@scure/bip32';
import { ed25519 } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// ── Messaging Key Derivation Paths ────────────────────
// m/44'/0'/0' — identity key (Ed25519)
// m/44'/0'/1' — signed prekey base (X25519)
// m/44'/0'/2'/index — one-time prekeys (X25519)
const IDENTITY_PATH = "m/44'/0'/0'";
const SIGNED_PREKEY_PATH = "m/44'/0'/1'";
const ONE_TIME_PREKEY_BASE_PATH = "m/44'/0'/2'";

// ── Bitcoin Key Derivation Paths ──────────────────────
// BIP44: m/44'/0'/0'/0/index — Legacy P2PKH addresses
// BIP84: m/84'/0'/0'/0/index — Native SegWit P2WPKH addresses (bech32)
const BTC_BIP44_PATH = "m/44'/0'/0'";
const BTC_BIP84_PATH = "m/84'/0'/0'";

// Bech32 encoding alphabet
const BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

export interface PhantomKeyMaterial {
  identityKeyPair: KeyPair;
  signedPreKeyPair: KeyPair;
  signedPreKeySignature: string; // base64
  oneTimePreKeyPairs: KeyPair[];
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

// ── BTC Key Types ────────────────────────────────────

export interface BtcKeyPair {
  publicKey: Uint8Array;       // 33-byte compressed secp256k1 public key
  privateKey: Uint8Array;      // 32-byte private key
  address: string;             // Bitcoin address (P2PKH or P2WPKH)
  path: string;                // Derivation path used
}

export interface BtcKeyMaterial {
  bip44: BtcKeyPair;           // Legacy P2PKH (1...)
  bip84: BtcKeyPair;           // Native SegWit P2WPKH (bc1...)
  xpubBip44: string;           // Extended public key for BIP44 account
  xpubBip84: string;           // Extended public key for BIP84 account
}

/**
 * Generate a new BIP39 12-word mnemonic.
 * This happens ONLY on the device. The phrase is shown to the user
 * exactly once for backup, then stored in Secure Enclave.
 *
 * SECURITY: This seed phrase NEVER leaves the device.
 */
export function generateMnemonic(): string {
  return bip39.generateMnemonic(128); // 128 bits = 12 words
}

/**
 * Validate a BIP39 mnemonic (for recovery flow).
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * Derive the master seed from a mnemonic.
 * Uses BIP39 standard: mnemonic → 512-bit seed.
 */
export async function mnemonicToSeed(mnemonic: string): Promise<Uint8Array> {
  const seedBuffer = await bip39.mnemonicToSeed(mnemonic);
  return new Uint8Array(seedBuffer);
}

/**
 * Derive all key material from a BIP39 seed.
 * This is the core function that turns a seed phrase into
 * everything needed for the Signal Protocol.
 *
 * Identity Key — long-term Ed25519 key for signing
 * Signed PreKey — medium-term X25519 key, signed by identity key
 * One-Time PreKeys — ephemeral X25519 keys for X3DH
 *
 * All derived deterministically so recovery = re-derive.
 */
export function deriveKeyMaterial(
  seed: Uint8Array,
  numOneTimePreKeys: number = 20
): PhantomKeyMaterial {
  const master = HDKey.fromMasterSeed(seed);

  // ── Identity Key (Ed25519 for signing) ──
  const identityNode = master.derive(IDENTITY_PATH);
  const identityPrivateKey = identityNode.privateKey!;
  const identityKeyPair = deriveEd25519KeyPair(identityPrivateKey);

  // ── Signed PreKey (X25519 for key exchange) ──
  const signedPreKeyNode = master.derive(SIGNED_PREKEY_PATH);
  const signedPreKeyPrivate = signedPreKeyNode.privateKey!;
  const signedPreKeyPair = deriveX25519KeyPair(signedPreKeyPrivate);

  // Sign the signed prekey's public key with the identity key
  const signedPreKeySignature = signPublicKey(
    identityKeyPair.privateKey,
    signedPreKeyPair.publicKey
  );

  // ── One-Time PreKeys (X25519 for X3DH) ──
  const otpkBase = master.derive(ONE_TIME_PREKEY_BASE_PATH);
  const oneTimePreKeyPairs: KeyPair[] = [];

  for (let i = 0; i < numOneTimePreKeys; i++) {
    const otpkNode = otpkBase.deriveChild(i);
    const otpkPrivate = otpkNode.privateKey!;
    oneTimePreKeyPairs.push(deriveX25519KeyPair(otpkPrivate));
  }

  return {
    identityKeyPair,
    signedPreKeyPair,
    signedPreKeySignature: uint8ToBase64(signedPreKeySignature),
    oneTimePreKeyPairs,
  };
}

/**
 * Derive additional one-time prekeys starting from a given index.
 * Used when the server signals that prekeys are running low.
 */
export function deriveAdditionalPreKeys(
  seed: Uint8Array,
  startIndex: number,
  count: number
): KeyPair[] {
  const master = HDKey.fromMasterSeed(seed);
  const otpkBase = master.derive(ONE_TIME_PREKEY_BASE_PATH);
  const keys: KeyPair[] = [];

  for (let i = startIndex; i < startIndex + count; i++) {
    const otpkNode = otpkBase.deriveChild(i);
    const otpkPrivate = otpkNode.privateKey!;
    keys.push(deriveX25519KeyPair(otpkPrivate));
  }

  return keys;
}

/**
 * Derive an Ed25519 key pair from raw private key material.
 * Ed25519 is used for the identity key (signing).
 */
function deriveEd25519KeyPair(privateKeyBytes: Uint8Array): KeyPair {
  // Hash to get a uniform 32-byte private key
  const privateKey = sha256(privateKeyBytes);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Derive an X25519 key pair from raw private key material.
 * X25519 is used for Diffie-Hellman key exchange (prekeys).
 */
function deriveX25519KeyPair(privateKeyBytes: Uint8Array): KeyPair {
  const privateKey = sha256(privateKeyBytes);
  // Clamp the private key per X25519 spec
  const clamped = new Uint8Array(privateKey);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  const publicKey = x25519.getPublicKey(clamped);
  return { publicKey, privateKey: clamped };
}

/**
 * Sign a public key with the Ed25519 identity key.
 * Used to create the signed prekey signature.
 */
function signPublicKey(
  identityPrivateKey: Uint8Array,
  publicKeyToSign: Uint8Array
): Uint8Array {
  return ed25519.sign(publicKeyToSign, identityPrivateKey);
}

/**
 * Verify a signed prekey signature.
 */
export function verifyPreKeySignature(
  identityPublicKey: Uint8Array,
  signedPreKeyPublic: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, signedPreKeyPublic, identityPublicKey);
  } catch {
    return false;
  }
}

/**
 * Derive an encryption key from a password + salt (for email/phone auth).
 * Uses HKDF with SHA-256. This runs client-side only.
 */
export function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password);
  const ikm = sha256(passwordBytes);
  return hkdf(sha256, ikm, salt, 'phantom-key-derivation', 32);
}

// ═══════════════════════════════════════════════════════
// BTC KEY DERIVATION — V2
// ═══════════════════════════════════════════════════════
// Derives Bitcoin keys from the SAME seed phrase used for messaging.
// Two address types: BIP44 (legacy P2PKH) and BIP84 (native SegWit).
// Private keys NEVER leave the device.

/**
 * Derive Bitcoin key material from a BIP39 seed.
 * Returns both BIP44 (legacy) and BIP84 (native SegWit) key pairs
 * at index 0 (the primary receiving address).
 *
 * SECURITY: Private keys are derived and stored ONLY on-device.
 * The server only ever sees the public address.
 */
export function deriveBtcKeyMaterial(
  seed: Uint8Array,
  addressIndex: number = 0
): BtcKeyMaterial {
  const master = HDKey.fromMasterSeed(seed);

  // ── BIP44: m/44'/0'/0'/0/index — Legacy P2PKH ──
  const bip44Account = master.derive(BTC_BIP44_PATH);
  const bip44Node = bip44Account.deriveChild(0).deriveChild(addressIndex);
  const bip44PrivKey = bip44Node.privateKey!;
  const bip44PubKey = secp256k1.getPublicKey(bip44PrivKey, true); // compressed
  const bip44Address = pubKeyToP2PKH(bip44PubKey);

  // ── BIP84: m/84'/0'/0'/0/index — Native SegWit P2WPKH ──
  const bip84Account = master.derive(BTC_BIP84_PATH);
  const bip84Node = bip84Account.deriveChild(0).deriveChild(addressIndex);
  const bip84PrivKey = bip84Node.privateKey!;
  const bip84PubKey = secp256k1.getPublicKey(bip84PrivKey, true); // compressed
  const bip84Address = pubKeyToP2WPKH(bip84PubKey);

  return {
    bip44: {
      publicKey: bip44PubKey,
      privateKey: new Uint8Array(bip44PrivKey),
      address: bip44Address,
      path: `m/44'/0'/0'/0/${addressIndex}`,
    },
    bip84: {
      publicKey: bip84PubKey,
      privateKey: new Uint8Array(bip84PrivKey),
      address: bip84Address,
      path: `m/84'/0'/0'/0/${addressIndex}`,
    },
    xpubBip44: bip44Account.publicExtendedKey,
    xpubBip84: bip84Account.publicExtendedKey,
  };
}

/**
 * Derive a BTC key pair at a specific index for a given BIP path type.
 * Used to generate additional receiving addresses.
 */
export function deriveBtcAddress(
  seed: Uint8Array,
  type: 'bip44' | 'bip84',
  chain: 0 | 1, // 0 = external (receiving), 1 = internal (change)
  index: number
): BtcKeyPair {
  const master = HDKey.fromMasterSeed(seed);
  const basePath = type === 'bip44' ? BTC_BIP44_PATH : BTC_BIP84_PATH;
  const accountNode = master.derive(basePath);
  const node = accountNode.deriveChild(chain).deriveChild(index);

  const privKey = node.privateKey!;
  const pubKey = secp256k1.getPublicKey(privKey, true);
  const address = type === 'bip44' ? pubKeyToP2PKH(pubKey) : pubKeyToP2WPKH(pubKey);

  return {
    publicKey: pubKey,
    privateKey: new Uint8Array(privKey),
    address,
    path: `${basePath.replace("m/", "")}/${chain}/${index}`,
  };
}

/**
 * Sign a Bitcoin transaction hash (32 bytes) with a secp256k1 private key.
 * Returns a DER-encoded signature.
 */
export function signBtcTransaction(
  privateKey: Uint8Array,
  transactionHash: Uint8Array
): Uint8Array {
  const sig = secp256k1.sign(transactionHash, privateKey);
  return sig.toDERRawBytes();
}

/**
 * Verify a Bitcoin transaction signature.
 */
export function verifyBtcSignature(
  publicKey: Uint8Array,
  transactionHash: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    return secp256k1.verify(signature, transactionHash, publicKey);
  } catch {
    return false;
  }
}

// ── Bitcoin Address Encoding ──────────────────────────

/**
 * Convert a compressed public key to a P2PKH (legacy) address.
 * Hash160 = RIPEMD160(SHA256(pubkey)), then Base58Check with version 0x00.
 */
function pubKeyToP2PKH(compressedPubKey: Uint8Array): string {
  const hash160 = ripemd160(sha256(compressedPubKey));
  const versioned = new Uint8Array(1 + hash160.length);
  versioned[0] = 0x00; // mainnet P2PKH version
  versioned.set(hash160, 1);
  return base58CheckEncode(versioned);
}

/**
 * Convert a compressed public key to a P2WPKH (native SegWit bech32) address.
 * Witness program = Hash160(pubkey), encoded with bech32 + witness version 0.
 */
function pubKeyToP2WPKH(compressedPubKey: Uint8Array): string {
  const hash160 = ripemd160(sha256(compressedPubKey));
  return bech32Encode('bc', 0, hash160);
}

/**
 * Base58Check encoding for legacy Bitcoin addresses.
 */
function base58CheckEncode(payload: Uint8Array): string {
  // Double SHA-256 checksum
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const data = new Uint8Array(payload.length + 4);
  data.set(payload);
  data.set(checksum, payload.length);

  // Convert to BigInt for base58
  let num = BigInt(0);
  for (let i = 0; i < data.length; i++) {
    num = num * BigInt(256) + BigInt(data[i]);
  }

  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let encoded = '';
  while (num > BigInt(0)) {
    const remainder = Number(num % BigInt(58));
    num = num / BigInt(58);
    encoded = BASE58_ALPHABET[remainder] + encoded;
  }

  // Preserve leading zeros
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    encoded = '1' + encoded;
  }

  return encoded;
}

/**
 * Bech32 encoding for native SegWit addresses (BIP173).
 */
function bech32Encode(hrp: string, witnessVersion: number, witnessProgram: Uint8Array): string {
  // Convert witness program to 5-bit groups
  const data = convertBits(witnessProgram, 8, 5, true);
  const values = [witnessVersion, ...data];
  const checksum = bech32CreateChecksum(hrp, values);
  let result = hrp + '1';
  for (const v of [...values, ...checksum]) {
    result += BECH32_ALPHABET[v];
  }
  return result;
}

/**
 * Convert between bit groups for bech32 encoding.
 */
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const result: number[] = [];
  const maxV = (1 << toBits) - 1;

  for (let i = 0; i < data.length; i++) {
    acc = (acc << fromBits) | data[i];
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxV);
    }
  }

  if (pad && bits > 0) {
    result.push((acc << (toBits - bits)) & maxV);
  }

  return result;
}

/**
 * Compute bech32 checksum.
 */
function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const result: number[] = [];
  for (let i = 0; i < 6; i++) {
    result.push((polymod >> (5 * (5 - i))) & 31);
  }
  return result;
}

function bech32HrpExpand(hrp: string): number[] {
  const result: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) >> 5);
  }
  result.push(0);
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) & 31);
  }
  return result;
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) {
        chk ^= GEN[i];
      }
    }
  }
  return chk;
}

// ── Encoding utilities ────────────────────────────────

export function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToUint8(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function uint8ToHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function hexToUint8(hex: string): Uint8Array {
  return hexToBytes(hex);
}

/**
 * Securely wipe a key from memory by overwriting with zeros.
 * Call this after every cryptographic operation.
 */
export function secureWipeKey(key: Uint8Array): void {
  for (let i = 0; i < key.length; i++) {
    key[i] = 0;
  }
}
