// ═══════════════════════════════════════════════════════
// PHANTOM — Session Manager
// ═══════════════════════════════════════════════════════
// Manages Double Ratchet sessions for all conversations.
// Sessions are stored in encrypted local storage (SQLCipher).
// Each conversation has its own ratchet state.
// Session data NEVER leaves the device.

import {
  RatchetState,
  initSenderRatchet,
  initReceiverRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
  EncryptedMessage,
} from './doubleRatchet';
import { x3dhSender, x3dhReceiver, X3DHPublicBundle } from './x3dh';
import {
  sealMessage,
  unsealMessage,
  SealedSenderMessage,
  SenderCertificate,
  serializeSealedMessage,
  deserializeSealedMessage,
} from './sealedSender';
import { KeyPair, base64ToUint8, uint8ToBase64, secureWipeKey } from './keyDerivation';

// ── Types ─────────────────────────────────────────────

export interface SessionInfo {
  recipientUserId: string;
  recipientUsername: string;
  state: RatchetState;
  associatedData: Uint8Array;
  recipientIdentityKey: Uint8Array;
}

export interface DecryptedIncoming {
  senderId: string;
  senderUsername: string;
  plaintext: Uint8Array;
  timestamp: number;
}

/**
 * Storage interface — implemented by platform-specific secure storage.
 * All data stored via this interface is encrypted at rest.
 */
export interface SecureSessionStorage {
  getSession(recipientUserId: string): Promise<string | null>;
  saveSession(recipientUserId: string, serialized: string): Promise<void>;
  deleteSession(recipientUserId: string): Promise<void>;
  getAllSessionIds(): Promise<string[]>;
}

// ── Session Manager ───────────────────────────────────

export class SessionManager {
  private sessions: Map<string, SessionInfo> = new Map();

  constructor(
    private myUserId: string,
    private myUsername: string,
    private myIdentityKeyPair: KeyPair,
    private mySignedPreKeyPair: KeyPair,
    private storage: SecureSessionStorage
  ) {}

  /**
   * Initialize a new session as the sender (we're initiating the conversation).
   *
   * Flow:
   * 1. Fetch recipient's key bundle from server
   * 2. Perform X3DH key exchange locally
   * 3. Initialize Double Ratchet with the shared secret
   * 4. Store session in encrypted local storage
   */
  async initOutgoingSession(
    recipientUserId: string,
    recipientUsername: string,
    recipientBundle: X3DHPublicBundle
  ): Promise<void> {
    // Perform X3DH as sender
    const x3dhResult = x3dhSender(this.myIdentityKeyPair, recipientBundle);

    // Initialize Double Ratchet
    const recipientSignedPreKey = base64ToUint8(recipientBundle.signedPreKey);
    const ratchetState = initSenderRatchet(
      x3dhResult.sharedSecret,
      recipientSignedPreKey
    );

    // Wipe shared secret from X3DH — it's now embedded in the ratchet
    secureWipeKey(x3dhResult.sharedSecret);

    const session: SessionInfo = {
      recipientUserId,
      recipientUsername,
      state: ratchetState,
      associatedData: x3dhResult.associatedData,
      recipientIdentityKey: base64ToUint8(recipientBundle.identityKey),
    };

    this.sessions.set(recipientUserId, session);
    await this.persistSession(recipientUserId);
  }

  /**
   * Initialize a session as the receiver (someone messaged us first).
   *
   * Flow:
   * 1. Unseal the incoming message to learn who the sender is
   * 2. Perform X3DH as receiver
   * 3. Initialize Double Ratchet
   * 4. Decrypt the first message
   */
  async initIncomingSession(
    sealedJson: string,
    oneTimePreKeyPair?: KeyPair
  ): Promise<DecryptedIncoming> {
    const sealed = deserializeSealedMessage(sealedJson);

    // Unseal to get sender certificate and ratchet message
    const { certificate, ratchetMessage } = unsealMessage({
      sealed,
      recipientIdentityKeyPair: this.myIdentityKeyPair,
    });

    const senderIdentityKey = base64ToUint8(certificate.senderIdentityKey);

    // Perform X3DH as receiver
    const x3dhResult = x3dhReceiver({
      identityKeyPair: this.myIdentityKeyPair,
      signedPreKeyPair: this.mySignedPreKeyPair,
      oneTimePreKeyPair,
      senderIdentityKey,
      senderEphemeralKey: base64ToUint8(ratchetMessage.header.publicKey),
    });

    // Initialize Double Ratchet as receiver
    const ratchetState = initReceiverRatchet(
      x3dhResult.sharedSecret,
      this.mySignedPreKeyPair
    );
    secureWipeKey(x3dhResult.sharedSecret);

    const session: SessionInfo = {
      recipientUserId: certificate.senderUserId,
      recipientUsername: certificate.senderUsername,
      state: ratchetState,
      associatedData: x3dhResult.associatedData,
      recipientIdentityKey: senderIdentityKey,
    };

    // Decrypt the first message
    const plaintext = ratchetDecrypt(
      session.state,
      ratchetMessage,
      session.associatedData
    );

    this.sessions.set(certificate.senderUserId, session);
    await this.persistSession(certificate.senderUserId);

    return {
      senderId: certificate.senderUserId,
      senderUsername: certificate.senderUsername,
      plaintext,
      timestamp: certificate.timestamp,
    };
  }

  /**
   * Encrypt a message for an existing session.
   * Returns a sealed sender blob ready to send to the server.
   *
   * The server sees ONLY the sealed blob — it cannot determine
   * the sender, read the content, or correlate messages.
   */
  async encryptMessage(
    recipientUserId: string,
    plaintext: Uint8Array
  ): Promise<string> {
    const session = await this.getSession(recipientUserId);
    if (!session) {
      throw new Error('NO_SESSION');
    }

    // Encrypt with Double Ratchet
    const ratchetMessage = ratchetEncrypt(
      session.state,
      plaintext,
      session.associatedData
    );

    // Seal with Sealed Sender
    const sealed = sealMessage({
      senderUserId: this.myUserId,
      senderUsername: this.myUsername,
      senderIdentityKeyPair: this.myIdentityKeyPair,
      recipientIdentityPublicKey: session.recipientIdentityKey,
      ratchetMessage,
    });

    // Persist updated ratchet state
    await this.persistSession(recipientUserId);

    return serializeSealedMessage(sealed);
  }

  /**
   * Decrypt an incoming message from an existing session.
   */
  async decryptMessage(
    senderUserId: string,
    sealedJson: string
  ): Promise<DecryptedIncoming> {
    const session = await this.getSession(senderUserId);
    if (!session) {
      // New session from unknown sender — initialize as incoming
      return this.initIncomingSession(sealedJson);
    }

    const sealed = deserializeSealedMessage(sealedJson);

    // Unseal
    const { certificate, ratchetMessage } = unsealMessage({
      sealed,
      recipientIdentityKeyPair: this.myIdentityKeyPair,
    });

    // Verify sender identity matches session
    if (certificate.senderUserId !== senderUserId) {
      throw new Error('SENDER_MISMATCH');
    }

    // Decrypt with Double Ratchet
    const plaintext = ratchetDecrypt(
      session.state,
      ratchetMessage,
      session.associatedData
    );

    // Persist updated ratchet state
    await this.persistSession(senderUserId);

    return {
      senderId: certificate.senderUserId,
      senderUsername: certificate.senderUsername,
      plaintext,
      timestamp: certificate.timestamp,
    };
  }

  /**
   * Check if we have an active session with a user.
   */
  hasSession(recipientUserId: string): boolean {
    return this.sessions.has(recipientUserId);
  }

  /**
   * Delete a session (e.g., when blocking a user or wiping data).
   */
  async deleteSession(recipientUserId: string): Promise<void> {
    const session = this.sessions.get(recipientUserId);
    if (session) {
      // Wipe all key material from memory
      secureWipeKey(session.state.rootKey);
      if (session.state.sendingChainKey) secureWipeKey(session.state.sendingChainKey);
      if (session.state.receivingChainKey) secureWipeKey(session.state.receivingChainKey);
      secureWipeKey(session.state.dhSendingKeyPair.privateKey);
      session.state.skippedKeys.forEach((key) => secureWipeKey(key));
    }
    this.sessions.delete(recipientUserId);
    await this.storage.deleteSession(recipientUserId);
  }

  /**
   * Delete all sessions (panic wipe).
   */
  async deleteAllSessions(): Promise<void> {
    for (const [userId] of this.sessions) {
      await this.deleteSession(userId);
    }
  }

  /**
   * Load all sessions from encrypted storage into memory.
   * Called on app startup after authentication.
   */
  async loadAllSessions(): Promise<void> {
    const sessionIds = await this.storage.getAllSessionIds();
    for (const id of sessionIds) {
      await this.getSession(id);
    }
  }

  // ── Private helpers ─────────────────────────────────

  private async getSession(userId: string): Promise<SessionInfo | null> {
    // Check in-memory cache first
    const cached = this.sessions.get(userId);
    if (cached) return cached;

    // Load from encrypted storage
    const serialized = await this.storage.getSession(userId);
    if (!serialized) return null;

    const data = JSON.parse(serialized);
    const session: SessionInfo = {
      recipientUserId: data.recipientUserId,
      recipientUsername: data.recipientUsername,
      state: deserializeRatchetState(data.ratchetState),
      associatedData: base64ToUint8(data.associatedData),
      recipientIdentityKey: base64ToUint8(data.recipientIdentityKey),
    };

    this.sessions.set(userId, session);
    return session;
  }

  private async persistSession(userId: string): Promise<void> {
    const session = this.sessions.get(userId);
    if (!session) return;

    const data = {
      recipientUserId: session.recipientUserId,
      recipientUsername: session.recipientUsername,
      ratchetState: serializeRatchetState(session.state),
      associatedData: uint8ToBase64(session.associatedData),
      recipientIdentityKey: uint8ToBase64(session.recipientIdentityKey),
    };

    await this.storage.saveSession(userId, JSON.stringify(data));
  }
}
