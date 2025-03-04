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
