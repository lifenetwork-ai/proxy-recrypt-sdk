const crypto = globalThis.crypto;

export async function encryptAESGCM(
  message: string,
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

  // Convert message to bytes
  const msgBuffer = new TextEncoder().encode(message);

  // Generate random nonce if not provided
  if (!nonce) {
    nonce = crypto.getRandomValues(new Uint8Array(12));
  }

  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      tagLength: 128,
    },
    cryptoKey,
    msgBuffer
  );

  // Combine nonce and ciphertext
  const result = new Uint8Array(nonce.length + ciphertext.byteLength);
  result.set(nonce);
  result.set(new Uint8Array(ciphertext), nonce.length);

  return result;
}

export async function decryptAESGCM(
  encrypted: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> {
  try {
    if (encrypted.length < 28) {
      // 12 (nonce) + 16 (minimum tag size)
      throw new Error("Ciphertext too short");
    }

    // Extract nonce and ciphertext
    const nonce = encrypted.subarray(0, 12);
    const ciphertext = encrypted.subarray(12);

    // Import key
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Decrypt
    const plainBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128,
      },
      cryptoKey,
      ciphertext
    );

    return new Uint8Array(plainBuffer);
  } catch (err: any) {
    throw new Error(`Decryption failed: ${err.message}`);
  }
}
