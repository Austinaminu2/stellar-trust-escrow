/**
 * Chat Encryption Utilities
 *
 * Hybrid encryption for dispute chat:
 *   - AES-256-GCM for message encryption (symmetric, fast)
 *   - ECDH (P-256) for room key exchange (asymmetric)
 *
 * All crypto runs in the browser via the Web Crypto API — no plaintext
 * ever leaves the client.
 *
 * Key derivation from Stellar keypair:
 *   Stellar uses ed25519. We derive a P-256 key pair deterministically
 *   from the Stellar private key seed for ECDH key exchange.
 *   In production, use a dedicated encryption keypair stored in the wallet.
 */

const ALGO = 'AES-GCM';
const KEY_LENGTH = 256;

// ── Room key generation ───────────────────────────────────────────────────────

/**
 * Generates a new random AES-256-GCM room key.
 * @returns {Promise<CryptoKey>}
 */
export async function generateRoomKey() {
  return crypto.subtle.generateKey({ name: ALGO, length: KEY_LENGTH }, true, ['encrypt', 'decrypt']);
}

/**
 * Exports a CryptoKey to a raw ArrayBuffer.
 * @param {CryptoKey} key
 * @returns {Promise<ArrayBuffer>}
 */
export async function exportRoomKey(key) {
  return crypto.subtle.exportKey('raw', key);
}

/**
 * Imports a raw ArrayBuffer as an AES-256-GCM CryptoKey.
 * @param {ArrayBuffer} raw
 * @returns {Promise<CryptoKey>}
 */
export async function importRoomKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: ALGO, length: KEY_LENGTH }, false, ['encrypt', 'decrypt']);
}

// ── Room key encryption (ECDH P-256) ─────────────────────────────────────────

/**
 * Generates an ECDH P-256 key pair for a participant.
 * In production this should be derived from or stored alongside the wallet.
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateEncryptionKeyPair() {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
}

/**
 * Exports the public key as a base64 string for sharing.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('spki', publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

/**
 * Imports a base64 SPKI public key.
 * @param {string} b64
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('spki', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}

/**
 * Encrypts the room key for a recipient using ECDH + AES-KW.
 *
 * @param {CryptoKey} roomKey         — the AES room key to wrap
 * @param {CryptoKey} recipientPubKey — recipient's ECDH public key
 * @param {CryptoKey} senderPrivKey   — sender's ECDH private key
 * @returns {Promise<string>}         — base64 wrapped key
 */
export async function encryptRoomKeyForRecipient(roomKey, recipientPubKey, senderPrivKey) {
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPubKey },
    senderPrivKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey'],
  );
  const wrapped = await crypto.subtle.wrapKey('raw', roomKey, sharedKey, 'AES-KW');
  return btoa(String.fromCharCode(...new Uint8Array(wrapped)));
}

/**
 * Decrypts the room key using ECDH + AES-KW.
 *
 * @param {string} b64WrappedKey      — base64 wrapped key from server
 * @param {CryptoKey} senderPubKey    — sender's ECDH public key
 * @param {CryptoKey} recipientPrivKey — recipient's ECDH private key
 * @returns {Promise<CryptoKey>}      — the AES room key
 */
export async function decryptRoomKey(b64WrappedKey, senderPubKey, recipientPrivKey) {
  const wrapped = Uint8Array.from(atob(b64WrappedKey), c => c.charCodeAt(0));
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: senderPubKey },
    recipientPrivKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['unwrapKey'],
  );
  return crypto.subtle.unwrapKey(
    'raw', wrapped, sharedKey, 'AES-KW',
    { name: ALGO, length: KEY_LENGTH }, false, ['encrypt', 'decrypt'],
  );
}

// ── Message encryption ────────────────────────────────────────────────────────

/**
 * Encrypts a plaintext message with the room key.
 *
 * @param {string} plaintext
 * @param {CryptoKey} roomKey
 * @returns {Promise<{ ciphertext: string, iv: string, tag: string }>}
 */
export async function encryptMessage(plaintext, roomKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = await crypto.subtle.encrypt({ name: ALGO, iv }, roomKey, encoded);

  // AES-GCM appends the 16-byte auth tag to the ciphertext
  const ciphertextBytes = new Uint8Array(encrypted, 0, encrypted.byteLength - 16);
  const tagBytes = new Uint8Array(encrypted, encrypted.byteLength - 16);

  return {
    ciphertext: btoa(String.fromCharCode(...ciphertextBytes)),
    iv: btoa(String.fromCharCode(...iv)),
    tag: btoa(String.fromCharCode(...tagBytes)),
  };
}

/**
 * Decrypts an encrypted message with the room key.
 *
 * @param {{ ciphertext: string, iv: string, tag: string }} encrypted
 * @param {CryptoKey} roomKey
 * @returns {Promise<string>} plaintext
 */
export async function decryptMessage({ ciphertext, iv, tag }, roomKey) {
  const ciphertextBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  const tagBytes = Uint8Array.from(atob(tag), c => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));

  // Reassemble ciphertext + tag for AES-GCM
  const combined = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  combined.set(ciphertextBytes);
  combined.set(tagBytes, ciphertextBytes.length);

  const decrypted = await crypto.subtle.decrypt({ name: ALGO, iv: ivBytes }, roomKey, combined);
  return new TextDecoder().decode(decrypted);
}
