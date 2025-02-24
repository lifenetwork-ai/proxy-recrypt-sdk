import { webcrypto } from "crypto";
import { decryptAESGCM, encryptAESGCM } from "./aes-gcm";

describe("Test AES-GCM", () => {
  test("Encrypt then decrypt", async () => {
    const message = "Life AI";
    const key = webcrypto.getRandomValues(new Uint8Array(32));
    const encrypted = await encryptAESGCM(message, key);

    const decrypted = await decryptAESGCM(encrypted, key);

    expect(Buffer.from(decrypted).toString()).toEqual(message);
  });
});
