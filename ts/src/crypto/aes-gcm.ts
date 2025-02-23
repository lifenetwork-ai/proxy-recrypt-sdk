import { webcrypto } from "crypto";

export async function encryptAESGCM(
  message: string,
  key: Uint8Array
): Promise<string> {
  // Validate key size
  if (![16, 24, 32].includes(key.length)) {
    throw new Error(`Invalid key size: ${key.length}`);
  }

  // Convert message to bytes
  const msgBuffer = new TextEncoder().encode(message);

  // Generate random nonce
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));

  // Import key
  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  // Encrypt
  const ciphertext = await webcrypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
    },
    cryptoKey,
    msgBuffer
  );

  // Combine nonce and ciphertext
  const result = new Uint8Array(nonce.length + ciphertext.byteLength);
  result.set(nonce);
  result.set(new Uint8Array(ciphertext), nonce.length);

  // Convert to base64
  return Buffer.from(result).toString("base64");
}

export async function decryptAESGCM(
  message: string,
  key: Uint8Array
): Promise<string> {
  try {
    // Decode base64
    const combined = Buffer.from(message, "base64");

    if (combined.length < 12) {
      throw new Error("Ciphertext too short");
    }

    // Extract nonce and ciphertext
    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    // Import key
    const cryptoKey = await webcrypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Decrypt
    const plainBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      cryptoKey,
      ciphertext
    );

    // Convert back to string
    return new TextDecoder().decode(plainBuffer);
  } catch (err: any) {
    throw new Error(`Decryption failed: ${err.message}`);
  }
}
