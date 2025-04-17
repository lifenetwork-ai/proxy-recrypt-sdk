import { gcm } from "@noble/ciphers/aes";

/**
 * Encrypts data using AES-GCM and prepends the nonce to the ciphertext.
 *
 * @param message Data to encrypt
 * @param key Encryption key (must be 16, 24, or 32 bytes)
 * @param nonce Optional 12-byte initialization vector
 *        NOTE: Only provide nonce for testing purposes. For security,
 *        allow the function to generate a random nonce in production.
 * @returns Combined nonce + ciphertext (first 12 bytes are the nonce)
 */
export async function encryptAESGCM(
  message: Uint8Array,
  key: Uint8Array,
  nonce?: Uint8Array
): Promise<Uint8Array> {
  // Validate key size
  if (![16, 24, 32].includes(key.length)) {
    throw new Error(`Invalid key size: ${key.length}`);
  }

  // Validate nonce if provided
  if (nonce && nonce.length !== 12) {
    throw new Error("Nonce must be 12 bytes");
  }

  // Generate random nonce if not provided
  if (!nonce) {
    nonce = crypto.getRandomValues(new Uint8Array(12));
  }

  // Use Noble Ciphers gcm for encryption
  const cipher = gcm(new Uint8Array(key), nonce);
  const ciphertext = cipher.encrypt(new Uint8Array(message));

  // Combine nonce and ciphertext
  const result = new Uint8Array(nonce.length + ciphertext.length);
  result.set(nonce);
  result.set(ciphertext, nonce.length);

  return Promise.resolve(result);
}

/**
 * Decrypts data that was encrypted using encryptAESGCM without using subarray.
 *
 * @param encrypted Combined nonce and ciphertext (as returned by encryptAESGCM)
 * @param key The same key used for encryption
 * @returns Decrypted data
 * @throws Error if ciphertext is too short or decryption fails
 */
export async function decryptAESGCM(
  encrypted: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  try {
    if (encrypted.length < 28) {
      // 12 (nonce) + 16 (minimum tag size)
      throw new Error("Ciphertext too short");
    }

    // Extract nonce and ciphertext manually without using subarray
    const nonce = new Uint8Array(12);
    for (let i = 0; i < 12; i++) {
      nonce[i] = encrypted[i];
    }

    const ciphertext = new Uint8Array(encrypted.length - 12);
    for (let i = 0; i < ciphertext.length; i++) {
      ciphertext[i] = encrypted[i + 12];
    }

    // Use Noble Ciphers gcm for decryption
    const cipher = gcm(key, nonce);
    const plaintext = cipher.decrypt(ciphertext);

    return Promise.resolve(plaintext);
  } catch (err: unknown) {
    if (err instanceof Error) {
      throw new Error(`Decryption failed: ${err.message}`);
    }
    // Handle unexpected errors
    throw new Error("Decryption failed: Unknown error");
  }
}
