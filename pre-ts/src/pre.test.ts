import { BN254CurveWrapper } from "./crypto";
import { PreClient } from "./pre";
import {
  loadAllTestData,
  loadAliceKeyPair,
  getFirstLevelEncryptedKeyFirst,
  getFirstLevelEncryptedKeySecond,
  getSecondLevelEncryptedKeyFirst,
  getSecondLevelEncryptedKeySecond,
} from "./utils/testUtils";
import { SecretKey } from "./types";

describe("PRE", () => {
  test("confirm secret and public key relation", async () => {
    const aliceKeyPair = await loadAliceKeyPair();
    const pubKeyAlice = aliceKeyPair.publicKey;
    const secretKeyAlice = aliceKeyPair.secretKey;

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
    const testData = await loadAllTestData();
    const preclient = new PreClient();

    const reKey = preclient.generateReEncryptionKey(
      testData.aliceKeyPair.secretKey.first,
      testData.bobKeyPair.publicKey.second
    );

    const expectedReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(testData.reKey)
    ).toString("base64");

    const actualReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(reKey)
    ).toString("base64");

    expect(actualReKey).toBe(expectedReKey);
  });

  test("should generate encrypted data correctly", async () => {
    const testData = await loadAllTestData();
    const client = new PreClient();

    const secondLevelResponse = await client.secondLevelEncryption(
      testData.aliceKeyPair.secretKey,
      testData.message,
      testData.randomScalar,
      testData.symmetricKeyGT,
      testData.symmetricKey,
      testData.mockNonce
    );

    const expectedFirst = await getSecondLevelEncryptedKeyFirst();
    const expectedSecond = await getSecondLevelEncryptedKeySecond();

    const actualFirst = Buffer.from(
      BN254CurveWrapper.G1ToBytes(secondLevelResponse.encryptedKey.first)
    ).toString("base64");

    expect(actualFirst).toBe(expectedFirst);

    expect(
      Buffer.compare(
        BN254CurveWrapper.GTToBytes(secondLevelResponse.encryptedKey.second),
        BN254CurveWrapper.GTToBytes(expectedSecond)
      )
    ).toBe(0);

    const resp = await client.decryptFirstLevel(
      {
        encryptedKey: {
          first: await getFirstLevelEncryptedKeyFirst(),
          second: await getFirstLevelEncryptedKeySecond(),
        },
        encryptedMessage: testData.encryptedMessage,
      },
      testData.bobKeyPair.secretKey
    );

    expect(Buffer.compare(resp, testData.message)).toBe(0);
  });
});

describe("PreclientImpl", () => {
  let client: PreClient;

  beforeEach(() => {
    client = new PreClient();
  });

  test("constructor initializes curve parameters correctly", () => {
    expect(client.G1).toBeDefined();
    expect(client.G2).toBeDefined();
    expect(client.Z).toBeDefined();

    // Verify Z = e(G1,G2)
    const computedZ = BN254CurveWrapper.pairing(client.G1, client.G2);
    expect(client.Z).toEqual(computedZ);
  });

  test("decryptFirstLevel should throw on invalid input", async () => {
    await expect(
      client.decryptFirstLevel(
        {
          encryptedKey: {
            first: BN254CurveWrapper.GTBase(),
            second: BN254CurveWrapper.GTBase(),
          },
          encryptedMessage: new Uint8Array(),
        },
        new SecretKey(0n, 0n)
      )
    ).rejects.toThrow();
  });

  test("secondLevelEncryption should throw on invalid scalar", async () => {
    const invalidScalar = 2n ** 256n; // Too large
    await expect(
      client.secondLevelEncryption(
        new SecretKey(0n, 0n),
        Buffer.from("tests"),
        invalidScalar
      )
    ).rejects.toThrow();
  });
});
