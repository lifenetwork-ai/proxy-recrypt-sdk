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
export declare function encryptAESGCM(message: Uint8Array, key: Uint8Array, nonce?: Uint8Array): Promise<Uint8Array>;
/**
 * Decrypts data that was encrypted using encryptAESGCM.
 *
 * @param encrypted Combined nonce and ciphertext (as returned by encryptAESGCM)
 * @param key The same key used for encryption
 * @returns Decrypted data
 * @throws Error if ciphertext is too short or decryption fails
 */
export declare function decryptAESGCM(encrypted: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
