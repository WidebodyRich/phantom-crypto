# phantom-crypto

**Open source cryptographic layer for [Phantom Messenger](https://phantommessenger.app)**

End-to-end encryption implementation using Signal Protocol primitives. Independently auditable cryptographic code for privacy-first messaging.

## What's in here

This repository contains only the cryptographic layer of Phantom Messenger. The rest of the application (server, UI, wallet, marketplace) is proprietary.

### Protocols implemented

- **Double Ratchet Algorithm** — forward secrecy and break-in recovery for 1:1 messaging
- **X3DH Key Agreement** — asynchronous key exchange for session initialization
- **Sealed Sender** — metadata-hiding sender authentication (recipient learns sender identity only after decryption)
- **Sender Keys** — efficient group message encryption (one encrypt, N decrypt)
- **BIP39/BIP32 Key Derivation** — deterministic identity and wallet key generation from a single 12-word mnemonic

### Cryptographic primitives

| Primitive | Library | Usage |
|-----------|---------|-------|
| X25519 | `@noble/curves` | Diffie-Hellman key exchange |
| Ed25519 | `@noble/curves` | Digital signatures |
| AES-256-GCM | `@noble/ciphers` | Symmetric encryption |
| HKDF-SHA256 | `@noble/hashes` | Key derivation |
| HMAC-SHA256 | `@noble/hashes` | Chain key ratcheting |
| BIP39 | `bip39` | Mnemonic generation |
| BIP32 | `bip32` / `@scure/bip32` | HD key derivation |

## Cross-platform compatibility

Mobile (React Native / TypeScript) and web (JavaScript) clients use identical cryptographic implementations with matching constants. A test suite verifies byte-for-byte compatibility:

```
 ✓ Mobile sender, web receiver: 5 messages decrypt correctly
 ✓ Web sender, mobile receiver: 5 messages decrypt correctly
 ✓ Out of order delivery: messages 3,1,4,2,5 all decrypt
 ✓ Multi-turn conversation: 12 messages across 4 DH ratchet steps
 ✓ KDF constants byte-for-byte identical between platforms
 ✓ Session state serializes and deserializes correctly
```

## Directory structure

```
src/
  mobile/           TypeScript (React Native)
    doubleRatchet.ts    Full Signal Double Ratchet
    sessionManager.ts   Session lifecycle management
    x3dh.ts             X3DH key agreement
    sealedSender.ts     Metadata-hiding sealed sender
    senderKeys.ts       Group E2EE via Sender Keys
    keyDerivation.ts    BIP39/BIP32 key derivation

  web/              JavaScript (browser)
    doubleRatchet.js    Line-for-line port of mobile
    sessionManager.js   Session management for web
    keyDerivation.js    Web key derivation
    senderKeys.js       Web group E2EE

tests/
    crossPlatform.test.js       Cross-platform E2EE tests
    sessionResumption.test.js   Session persistence tests
    keyBackup.test.js           Key backup/recovery tests
```

## Running tests

```bash
npm install
npm test
```

## KDF Constants

These constants must be byte-for-byte identical across all platforms. Any deviation causes silent decryption failure.

| Constant | Value | Usage |
|----------|-------|-------|
| `RATCHET_INFO_ROOT` | `PhantomRootRatchet` | Root key HKDF info |
| `RATCHET_INFO_CHAIN` | `PhantomChainRatchet` | Chain key HKDF info |
| `MESSAGE_KEY_SEED` | `[0x01]` | HMAC seed for message keys |
| `CHAIN_KEY_SEED` | `[0x02]` | HMAC seed for chain advancement |
| `X3DH_INFO` | `PhantomX3DH` | X3DH HKDF info |
| `PROTOCOL_BYTES` | 32 bytes of `0xFF` | X3DH DH concatenation prefix |
| `MAX_SKIP` | `1000` | Max out-of-order messages |

## Security

**This code has not yet undergone independent professional security audit.**

We are actively pursuing audit through established security firms. Until an independent audit is completed, treat this as a reference implementation.

Known limitations:
- Session resumption after long offline periods may require re-establishment
- Group key rotation on member removal requires coordination (implemented but not independently verified)

## How Phantom Messenger uses this

1. **Account creation**: BIP39 mnemonic generates all keys deterministically
2. **Contact establishment**: X3DH key agreement via server-stored public key bundles
3. **1:1 messaging**: Double Ratchet with sealed sender for every message
4. **Group messaging**: Sender Keys with automatic rotation on member removal
5. **Key recovery**: Same mnemonic re-derives identical keys on any device

The server never sees private keys, message content, or sender/recipient linkage. Messages are stored in anonymous mailboxes — the server knows only "mailbox X has a message," not who owns it or who sent it.

## License

MIT License — see [LICENSE](LICENSE) file.

## About Phantom Messenger

Privacy-first encrypted messenger with:
- No phone number required
- Anonymous mailbox architecture
- Bitcoin-native payments
- End-to-end encrypted marketplace
- Single 12-word mnemonic recovers everything

Website: [phantommessenger.app](https://phantommessenger.app)
