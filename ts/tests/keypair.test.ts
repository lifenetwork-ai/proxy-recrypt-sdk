import {
  loadKeyPairFromFile,
  base64BufferToBigInt,
  loadReKeyFromFile,
} from "../src/utils";
import { BN254CurveWrapper } from "../src/crypto";
import { PreSchemeImpl } from "../src/pre";
import fs from "fs/promises";
describe("PRE", () => {
  test("should calculate correct rekey", async () => {
    const aliceKeyPair = await loadKeyPairFromFile(
      "testdata/alice_keypair.json"
    );
    const bobKeyPair = await loadKeyPairFromFile("testdata/bob_keypair.json");

    const preScheme = new PreSchemeImpl();

    const reKey = preScheme.generateReEncryptionKey(
      aliceKeyPair.secretKey.first,
      bobKeyPair.publicKey.second
    );

    const expectedReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(await loadReKeyFromFile("testdata/rekey.txt"))
    ).toString("base64");

    const actualReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(reKey)
    ).toString("base64");

    expect(actualReKey).toBe(expectedReKey);
  });

  test("should generate encrypted data correctly", async () => {
    const message = await fs.readFile("testdata/data.txt");
    const randomScalarBuffer = await fs.readFile("testdata/random_scalar.txt");
    const randomScalar = base64BufferToBigInt(randomScalarBuffer);
    const aliceKeyPair = await loadKeyPairFromFile(
      "testdata/alice_keypair.json"
    );

    const keyGTBuffer = await fs.readFile(
      "testdata/symmetric_key_gt.txt",
      "utf-8"
    );
    const keyGT = BN254CurveWrapper.GTFromBytes(
      Buffer.from(keyGTBuffer.trim(), "base64")
    );

    const keyContent = await fs.readFile("testdata/symmetric_key.txt");

    const key = Buffer.from(keyContent.toString(), "base64");
    const preScheme = new PreSchemeImpl();

    const secondLevelCipherText = await preScheme.secondLevelEncryption(
      aliceKeyPair.secretKey,
      message.toString(),
      randomScalar,
      keyGT,
      key
    );

    const expectedSecondEncryptedKeyFirstBytes = await fs.readFile(
      "testdata/second_encrypted_key_first.txt"
    );

    const expectedSecondEncryptedKeyFirst =
      expectedSecondEncryptedKeyFirstBytes.toString();

    expect(
      Buffer.from(
        BN254CurveWrapper.G1ToBytes(secondLevelCipherText.encryptedKey.first)
      ).toString("base64")
    ).toBe(expectedSecondEncryptedKeyFirst);
  });
});
