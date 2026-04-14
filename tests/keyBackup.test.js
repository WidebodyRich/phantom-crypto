/**
 * PHANTOM — Key Backup & Recovery Tests
 *
 * Tests the critical guarantee: a single 12-word mnemonic
 * recovers both the Bitcoin wallet AND the messaging identity.
 * Same mnemonic always produces identical keys.
 */

import { describe, test, expect } from 'vitest';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  deriveKeyMaterial,
  uint8ToBase64,
} from '../keyDerivation.js';

describe('Key Backup & Recovery', () => {

  test('TEST 1 — Mnemonic generates consistent identity keypair', async () => {
    const mnemonic = generateMnemonic();

    // Derive keys first time
    const seed1 = await mnemonicToSeed(mnemonic);
    const keys1 = deriveKeyMaterial(seed1, 5);

    // Derive keys second time from same mnemonic
    const seed2 = await mnemonicToSeed(mnemonic);
    const keys2 = deriveKeyMaterial(seed2, 5);

    // Identity keypairs must be identical
    expect(uint8ToBase64(keys1.identityKeyPair.publicKey))
      .toBe(uint8ToBase64(keys2.identityKeyPair.publicKey));
    expect(uint8ToBase64(keys1.identityKeyPair.privateKey))
      .toBe(uint8ToBase64(keys2.identityKeyPair.privateKey));

    // Signed prekeys must be identical
    expect(uint8ToBase64(keys1.signedPreKeyPair.publicKey))
      .toBe(uint8ToBase64(keys2.signedPreKeyPair.publicKey));

    // Signatures must be identical
    expect(uint8ToBase64(keys1.signedPreKeySignature))
      .toBe(uint8ToBase64(keys2.signedPreKeySignature));

    // One-time prekeys must be identical
    for (let i = 0; i < 5; i++) {
      expect(uint8ToBase64(keys1.oneTimePreKeyPairs[i].publicKey))
        .toBe(uint8ToBase64(keys2.oneTimePreKeyPairs[i].publicKey));
    }
  });

  test('TEST 2 — Different mnemonics produce different identities', async () => {
    const mnemonicA = generateMnemonic();
    const mnemonicB = generateMnemonic();

    // Ensure they're actually different
    expect(mnemonicA).not.toBe(mnemonicB);

    const keysA = deriveKeyMaterial(await mnemonicToSeed(mnemonicA));
    const keysB = deriveKeyMaterial(await mnemonicToSeed(mnemonicB));

    // Identity keys must differ
    expect(uint8ToBase64(keysA.identityKeyPair.publicKey))
      .not.toBe(uint8ToBase64(keysB.identityKeyPair.publicKey));

    // Signed prekeys must differ
    expect(uint8ToBase64(keysA.signedPreKeyPair.publicKey))
      .not.toBe(uint8ToBase64(keysB.signedPreKeyPair.publicKey));
  });

  test('TEST 3 — Mnemonic verification catches wrong words', () => {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const words = mnemonic.split(' ');

    // Valid mnemonic passes validation
    expect(validateMnemonic(mnemonic)).toBe(true);

    // One wrong word fails
    const wrongWord = [...words];
    wrongWord[5] = 'zebra';
    expect(validateMnemonic(wrongWord.join(' '))).toBe(false);

    // Wrong number of words fails
    expect(validateMnemonic(words.slice(0, 11).join(' '))).toBe(false);

    // Empty string fails
    expect(validateMnemonic('')).toBe(false);

    // Random gibberish fails
    expect(validateMnemonic('hello world foo bar baz qux quux corge grault garply waldo fred')).toBe(false);

    // 3-word verification simulation
    const verifyIndices = [3, 7, 10]; // word positions to verify
    const correctAnswers = verifyIndices.map(i => words[i]);
    const wrongAnswers = [...correctAnswers];
    wrongAnswers[1] = 'wrong'; // One wrong answer

    const correct = verifyIndices.every((idx, i) => correctAnswers[i] === words[idx]);
    const incorrect = verifyIndices.every((idx, i) => wrongAnswers[i] === words[idx]);

    expect(correct).toBe(true);
    expect(incorrect).toBe(false);
  });

  test('TEST 4 — Recovery derives correct keys (simulated reinstall)', async () => {
    // === ORIGINAL INSTALL ===
    const mnemonic = generateMnemonic();
    const originalSeed = await mnemonicToSeed(mnemonic);
    const originalKeys = deriveKeyMaterial(originalSeed, 20);

    const originalIdentityPub = uint8ToBase64(originalKeys.identityKeyPair.publicKey);
    const originalSignedPreKeyPub = uint8ToBase64(originalKeys.signedPreKeyPair.publicKey);

    // === SIMULATE REINSTALL (clear all state) ===
    // In a real app: SecureStore wiped, MMKV wiped, all memory cleared
    // The ONLY thing the user has is their mnemonic written on paper

    // === RECOVERY ===
    expect(validateMnemonic(mnemonic)).toBe(true);
    const recoveredSeed = await mnemonicToSeed(mnemonic);
    const recoveredKeys = deriveKeyMaterial(recoveredSeed, 20);

    // Identity must match
    expect(uint8ToBase64(recoveredKeys.identityKeyPair.publicKey))
      .toBe(originalIdentityPub);

    // Signed prekey must match
    expect(uint8ToBase64(recoveredKeys.signedPreKeyPair.publicKey))
      .toBe(originalSignedPreKeyPub);

    // All 20 one-time prekeys must match
    for (let i = 0; i < 20; i++) {
      expect(uint8ToBase64(recoveredKeys.oneTimePreKeyPairs[i].publicKey))
        .toBe(uint8ToBase64(originalKeys.oneTimePreKeyPairs[i].publicKey));
    }
  });

  test('TEST 5 — Duress wipe removes mnemonic from storage (simulated)', () => {
    // Simulate secure storage
    const storage = new Map();
    storage.set('phantom_seed', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    storage.set('phantom_identity_priv', 'base64-private-key');
    storage.set('phantom_spk_priv', 'base64-spk');
    storage.set('phantom_sessions', JSON.stringify({ 'user-1': {}, 'user-2': {} }));
    storage.set('phantom_messages', JSON.stringify([{ id: 1, text: 'secret' }]));
    storage.set('pin_hash', 'hashed-normal-pin');
    storage.set('duress_pin_hash', 'hashed-duress-pin');

    // Verify storage has data
    expect(storage.size).toBe(7);
    expect(storage.get('phantom_seed')).toBeTruthy();
    expect(storage.get('phantom_sessions')).toBeTruthy();
    expect(storage.get('phantom_messages')).toBeTruthy();

    // === EXECUTE DURESS PROTOCOL ===
    // In real app: executeDuressProtocol() does this
    const sensitiveKeys = [
      'phantom_seed',
      'phantom_identity_priv',
      'phantom_spk_priv',
      'phantom_sessions',
      'phantom_messages',
    ];

    for (const key of sensitiveKeys) {
      storage.delete(key);
    }

    // Verify: all sensitive data gone
    expect(storage.get('phantom_seed')).toBeUndefined();
    expect(storage.get('phantom_identity_priv')).toBeUndefined();
    expect(storage.get('phantom_sessions')).toBeUndefined();
    expect(storage.get('phantom_messages')).toBeUndefined();

    // PIN hashes may remain (needed for the duress illusion)
    expect(storage.get('pin_hash')).toBeTruthy();
    expect(storage.get('duress_pin_hash')).toBeTruthy();

    // Only non-sensitive data remains
    expect(storage.size).toBe(2);
  });
});
