import fs from "fs/promises";
import { BN254CurveWrapper, G1Point, G2Point } from "../crypto/bn254";
import { base64BufferToBigInt, loadKeyPairFromFile } from "./index";
import { GTElement } from "../crypto/bn254";
import { KeyPair } from "../types";

export async function loadMessage(): Promise<Uint8Array> {
  const messageBuffer = await fs.readFile(
    "../testdata/data/message.txt",
    "utf-8"
  );
  return Buffer.from(messageBuffer.toString(), "base64");
}

export async function loadEncryptedMessage(): Promise<Uint8Array> {
  const content = await fs.readFile(
    "../testdata/encrypted_message.txt",
    "utf-8"
  );
  return Buffer.from(content, "base64");
}

export async function loadRandomScalar(): Promise<bigint> {
  const buffer = await fs.readFile("../testdata/random_scalar.txt");
  return base64BufferToBigInt(buffer);
}

export async function loadSymmetricKeyGT(): Promise<GTElement> {
  const buffer = await fs.readFile("../testdata/symmetric_key_gt.txt", "utf-8");
  return BN254CurveWrapper.GTFromBytes(Buffer.from(buffer.trim(), "base64"));
}

export async function loadSymmetricKey(): Promise<Uint8Array> {
  const content = await fs.readFile("../testdata/symmetric_key.txt");
  return Buffer.from(content.toString(), "base64");
}

export async function loadReKey(): Promise<G2Point> {
  const content = await fs.readFile("../testdata/rekey.txt", "utf-8");
  return BN254CurveWrapper.G2FromBytes(Buffer.from(content.trim(), "base64"));
}

export async function loadAliceKeyPair(): Promise<KeyPair> {
  return await loadKeyPairFromFile("../testdata/alice_keypair.json");
}

export async function loadBobKeyPair(): Promise<KeyPair> {
  return await loadKeyPairFromFile("../testdata/bob_keypair.json");
}

export const getMockNonce = (): Uint8Array => {
  return new Uint8Array([
    223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123,
  ]);
};

// get the first level payload(proxy -> Bob payload)

export const getFirstLevelEncryptedKeyFirst = async (): Promise<GTElement> => {
  const firstLevelEncryptedKeyFirst = await fs.readFile(
    "../testdata/first_encrypted_key_first.txt",
    "utf-8"
  );
  return BN254CurveWrapper.GTFromBytes(
    Buffer.from(firstLevelEncryptedKeyFirst.trim(), "base64")
  );
};

export const getFirstLevelEncryptedKeySecond = async (): Promise<GTElement> => {
  const firstLevelEncryptedKeySecond = await fs.readFile(
    "../testdata/first_encrypted_key_second.txt",
    "utf-8"
  );
  return BN254CurveWrapper.GTFromBytes(
    Buffer.from(firstLevelEncryptedKeySecond.trim(), "base64")
  );
};

// G1 from bytes not implemented, so we compare the string representation
export const getSecondLevelEncryptedKeyFirst = async (): Promise<string> => {
  const secondLevelEncryptedKeyFirst = await fs.readFile(
    "../testdata/second_encrypted_key_first.txt"
  );
  return secondLevelEncryptedKeyFirst.toString();
};

export const getSecondLevelEncryptedKeySecond =
  async (): Promise<GTElement> => {
    const secondLevelEncryptedKeySecond = await fs.readFile(
      "../testdata/second_encrypted_key_second.txt",
      "utf-8"
    );
    return BN254CurveWrapper.GTFromBytes(
      Buffer.from(secondLevelEncryptedKeySecond.trim(), "base64")
    );
  };

// Helper function to load all test data at once if needed
export async function loadAllTestData() {
  const [
    message,
    encryptedMessage,
    randomScalar,
    symmetricKeyGT,
    symmetricKey,
    reKey,
    aliceKeyPair,
    bobKeyPair,
  ] = await Promise.all([
    loadMessage(),
    loadEncryptedMessage(),
    loadRandomScalar(),
    loadSymmetricKeyGT(),
    loadSymmetricKey(),
    loadReKey(),
    loadAliceKeyPair(),
    loadBobKeyPair(),
  ]);

  return {
    message,
    encryptedMessage,
    randomScalar,
    symmetricKeyGT,
    symmetricKey,
    mockNonce: getMockNonce(),
    reKey,
    aliceKeyPair,
    bobKeyPair,
  };
}
