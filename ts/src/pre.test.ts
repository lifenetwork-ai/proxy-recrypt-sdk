import {
  loadKeyPairFromFile,
  base64BufferToBigInt,
  loadReKeyFromFile,
} from "./utils";
import { BN254CurveWrapper } from "./crypto";
import { PreSchemeImpl } from "./pre";
import fs from "fs/promises";
import { FirstLevelSymmetricKey } from "./types";
describe("PRE", () => {
  test("confirm secret and public key relation", async () => {
    const aliceKeyPair = await loadKeyPairFromFile(
      "../testdata/alice_keypair.json"
    );

    const bobKeyPair = await loadKeyPairFromFile(
      "../testdata/bob_keypair.json"
    );
    const pubKeyAlice = aliceKeyPair.publicKey;
    const secretKeyAlice = aliceKeyPair.secretKey;

    console.log(bobKeyPair.secretKey.first);

    // try generate pubkey by exponentiation
    const pubKeyAliceGenerated = BN254CurveWrapper.gtPow(
      BN254CurveWrapper.pairing(
        BN254CurveWrapper.G1Generator(),
        BN254CurveWrapper.G2Generator()
      ),
      secretKeyAlice.first
    );

    const pubKeyAliceGeneratedBytes = Buffer.from(
      BN254CurveWrapper.GTToBytes(pubKeyAliceGenerated)
    ).toString("base64");

    const pubKeyAliceFirstBytes = Buffer.from(
      BN254CurveWrapper.GTToBytes(pubKeyAlice.first)
    ).toString("base64");

    expect(pubKeyAliceGeneratedBytes).toEqual(pubKeyAliceFirstBytes);
  });

  test("should calculate correct rekey", async () => {
    const aliceKeyPair = await loadKeyPairFromFile(
      "../testdata/alice_keypair.json"
    );
    const bobKeyPair = await loadKeyPairFromFile(
      "../testdata/bob_keypair.json"
    );

    const preScheme = new PreSchemeImpl();

    const reKey = preScheme.generateReEncryptionKey(
      aliceKeyPair.secretKey.first,
      bobKeyPair.publicKey.second
    );

    const expectedReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(
        await loadReKeyFromFile("../testdata/rekey.txt")
      )
    ).toString("base64");

    const actualReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(reKey)
    ).toString("base64");

    expect(actualReKey).toBe(expectedReKey);
  });

  test("should generate encrypted data correctly", async () => {
    const messageBuffer = await fs.readFile(
      "../testdata/data/message.txt",
      "utf-8"
    );
    const message = Buffer.from(messageBuffer.toString(), "base64");

    const encryptedMessageContent = await fs.readFile(
      "../testdata/encrypted_message.txt",
      "utf-8"
    );

    const encryptedMessage = Buffer.from(encryptedMessageContent, "base64");

    const randomScalarBuffer = await fs.readFile(
      "../testdata/random_scalar.txt"
    );
    const randomScalar = base64BufferToBigInt(randomScalarBuffer);
    const aliceKeyPair = await loadKeyPairFromFile(
      "../testdata/alice_keypair.json"
    );

    const bobKeyPair = await loadKeyPairFromFile(
      "../testdata/bob_keypair.json"
    );

    const keyGTBuffer = await fs.readFile(
      "../testdata/symmetric_key_gt.txt",
      "utf-8"
    );
    const keyGT = BN254CurveWrapper.GTFromBytes(
      Buffer.from(keyGTBuffer.trim(), "base64")
    );

    const keyContent = await fs.readFile("../testdata/symmetric_key.txt");

    const key = Buffer.from(keyContent.toString(), "base64");
    const preScheme = new PreSchemeImpl();
    const secondLevelResponse = await preScheme.secondLevelEncryption(
      aliceKeyPair.secretKey,
      message.toString(),
      randomScalar,
      keyGT,
      key,
      new Uint8Array([223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123]) // use fixed nonce for determinism
    );

    const expectedSecondEncryptedKeyFirstBytes = await fs.readFile(
      "../testdata/second_encrypted_key_first.txt"
    );

    const expectedSecondEncryptedKeyFirst =
      expectedSecondEncryptedKeyFirstBytes.toString();

    expect(
      Buffer.from(
        BN254CurveWrapper.G1ToBytes(secondLevelResponse.encryptedKey.first)
      ).toString("base64")
    ).toBe(expectedSecondEncryptedKeyFirst);

    // get the first level payload(proxy -> Bob payload)
    const firstLevelEncryptedKeyFirst = await fs.readFile(
      "../testdata/first_encrypted_key_first.txt",
      "utf-8"
    );

    const firstLevelEncryptedKeySecond = await fs.readFile(
      "../testdata/first_encrypted_key_second.txt",
      "utf-8"
    );

    const temp1 = BN254CurveWrapper.GTFromBytes(
      Buffer.from(firstLevelEncryptedKeyFirst.trim(), "base64")
    );
    const temp2 = BN254CurveWrapper.GTFromBytes(
      Buffer.from(firstLevelEncryptedKeySecond.trim(), "base64")
    );

    const firstLevelEncryptedKey: FirstLevelSymmetricKey = {
      first: temp1,
      second: temp2,
    };

    const resp = await preScheme.decryptFirstLevel(
      {
        encryptedKey: firstLevelEncryptedKey,
        encryptedMessage: encryptedMessage,
      },
      bobKeyPair.secretKey
    );

    expect(Buffer.compare(resp, message)).toBe(0);
  });
});
