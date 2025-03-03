import { webcrypto } from "crypto";
import { decryptAESGCM, encryptAESGCM } from "./aes-gcm";
import fs from "fs/promises";
describe("Test AES-GCM", () => {
  test("Encrypt then decrypt", async () => {
    const message = Buffer.from("Hello, World!");
    const key = webcrypto.getRandomValues(new Uint8Array(32));
    const encrypted = await encryptAESGCM(message, key);

    const decrypted = await decryptAESGCM(encrypted, key);

    expect(Buffer.from(decrypted).toString()).toEqual(message.toString());
  });

  test("Encrypt with ../testdata", async () => {
    const messageContent = await fs.readFile(
      "../testdata/data/message.txt",
      "utf-8"
    );
    const message = Buffer.from(messageContent, "base64");

    const keyContent = await fs.readFile("../testdata/symmetric_key.txt");
    const key = Buffer.from(keyContent.toString(), "base64");

    const encrypted = await encryptAESGCM(
      message,
      key,
      new Uint8Array([223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123]) // use fixed nonce for determinism
    );

    const encryptedContent = await fs.readFile(
      "../testdata/encrypted_message.txt",
      "utf-8"
    );
    const expectedEncrypted = Buffer.from(encryptedContent, "base64");
    expect(Buffer.compare(encrypted, expectedEncrypted)).toBe(0);
  });
});
