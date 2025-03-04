import { webcrypto } from "crypto";
import { decryptAESGCM, encryptAESGCM } from "./aes-gcm";
import {
  loadMessage,
  loadSymmetricKey,
  getMockNonce,
  loadEncryptedMessage,
} from "../utils/testUtils";

describe("Test AES-GCM", () => {
  test("Encrypt then decrypt", async () => {
    const message = Buffer.from("Hello, World!");
    const key = webcrypto.getRandomValues(new Uint8Array(32));
    const encrypted = await encryptAESGCM(message, key);
    const decrypted = await decryptAESGCM(encrypted, key);
    expect(Buffer.from(decrypted).toString()).toEqual(message.toString());
  });

  test("Encrypt with ../testdata", async () => {
    const message = await loadMessage();
    const key = await loadSymmetricKey();
    const mockNonce = getMockNonce();

    const encrypted = await encryptAESGCM(message, key, mockNonce);
    const expectedEncrypted = await loadEncryptedMessage();

    expect(Buffer.compare(encrypted, expectedEncrypted)).toBe(0);
  });
});

describe("AES-GCM edge cases", () => {
  test("should throw on invalid key size", async () => {
    const message = Buffer.from("test");
    const invalidKey = new Uint8Array(20); // Invalid size
    await expect(encryptAESGCM(message, invalidKey)).rejects.toThrow("Invalid key size");
  });

  test("should throw on invalid nonce size", async () => {
    const message = Buffer.from("test");
    const key = new Uint8Array(32);
    const invalidNonce = new Uint8Array(16); // Should be 12
    await expect(encryptAESGCM(message, key, invalidNonce)).rejects.toThrow("Nonce must be 12 bytes");
  });

  test("should throw on decryption with invalid data", async () => {
    const key = new Uint8Array(32);
    const invalidData = new Uint8Array(10); // Too short
    await expect(decryptAESGCM(invalidData, key)).rejects.toThrow();
  });
});