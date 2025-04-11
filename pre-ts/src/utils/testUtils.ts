import fs from "fs";
import { BN254CurveWrapper, G2Point } from "../crypto/bn254";
import { base64BufferToBigInt } from "./index";
import { GTElement } from "../crypto/bn254";
import { KeyPair, PublicKey, SecretKey } from "../types";
import crypto from "crypto";
// Interface for JSON serialization/deserialization
interface SerializableKeyPair {
  PublicKey: {
    First: string; // base64 encoded GT element
    Second: string; // base64 encoded G2 point
  };
  SecretKey: {
    First: string; // hex encoded bigint
    Second: string; // hex encoded bigint
  };
}

/**
 * Loads a keypair from a file
 * @param filename Path to the keypair file
 * @returns Promise resolving to the loaded KeyPair
 * @throws Error if file reading or parsing fails
 */
export async function loadKeyPairFromFile(filename: string): Promise<KeyPair> {
  // Read file
  let jsonData: Buffer;
  try {
    jsonData = await fs.readFileSync(filename);
  } catch (err) {
    throw new Error(`Failed to read keypair file: ${err}`);
  }

  // Parse JSON
  let serializable: SerializableKeyPair;
  try {
    serializable = JSON.parse(jsonData.toString());
  } catch (err) {
    throw new Error(`Failed to unmarshal keypair: ${err}`);
  }

  // Reconstruct KeyPair
  const keyPair: KeyPair = {
    publicKey: new PublicKey({
      first: BN254CurveWrapper.GTFromBytes(
        Uint8Array.from(atob(serializable.PublicKey.First), (c) =>
          c.charCodeAt(0)
        )
      ),
      second: BN254CurveWrapper.G2FromBytes(
        Uint8Array.from(atob(serializable.PublicKey.Second), (c) =>
          c.charCodeAt(0)
        )
      ),
    }),
    secretKey: new SecretKey(
      BigInt(`0x${serializable.SecretKey.First}`),
      BigInt(`0x${serializable.SecretKey.Second}`)
    ),
  };

  return keyPair;
}

export async function loadReKeyFromFile(filename: string): Promise<G2Point> {
  // Read file
  try {
    const jsonData = await fs.readFileSync(filename, "utf8");
    return BN254CurveWrapper.G2FromBytes(Buffer.from(jsonData, "base64"));
  } catch (err) {
    throw new Error(`Failed to read rekey file: ${err}`);
  }
}

export async function loadMessage(): Promise<Uint8Array> {
  const messageBuffer = await fs.readFileSync(
    "../testdata/data/message.txt",
    "utf-8"
  );
  return Buffer.from(messageBuffer.toString(), "base64");
}

export async function loadEncryptedMessage(): Promise<Uint8Array> {
  const content = await fs.readFileSync(
    "../testdata/encrypted_message.txt",
    "utf-8"
  );
  return Buffer.from(content, "base64");
}

export async function loadRandomScalar(): Promise<bigint> {
  const buffer = await fs.readFileSync("../testdata/random_scalar.txt");
  return base64BufferToBigInt(buffer);
}

export async function loadSymmetricKeyGT(): Promise<GTElement> {
  const buffer = await fs.readFileSync(
    "../testdata/symmetric_key_gt.txt",
    "utf-8"
  );
  return BN254CurveWrapper.GTFromBytes(
    new Uint8Array(Buffer.from(buffer.trim(), "base64"))
  );
}

export async function loadSymmetricKey(): Promise<Uint8Array> {
  const content = await fs.readFileSync("../testdata/symmetric_key.txt");
  return Buffer.from(content.toString(), "base64");
}

export async function loadReKey(): Promise<G2Point> {
  const content = await fs.readFileSync("../testdata/rekey.txt", "utf-8");
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
  const firstLevelEncryptedKeyFirst = await fs.readFileSync(
    "../testdata/first_encrypted_key_first.txt",
    "utf-8"
  );
  return BN254CurveWrapper.GTFromBytes(
    new Uint8Array(Buffer.from(firstLevelEncryptedKeyFirst.trim(), "base64"))
  );
};

export const getFirstLevelEncryptedKeySecond = async (): Promise<GTElement> => {
  const firstLevelEncryptedKeySecond = await fs.readFileSync(
    "../testdata/first_encrypted_key_second.txt",
    "utf-8"
  );
  return BN254CurveWrapper.GTFromBytes(
    new Uint8Array(Buffer.from(firstLevelEncryptedKeySecond.trim(), "base64"))
  );
};

// G1 from bytes not implemented, so we compare the string representation
export const getSecondLevelEncryptedKeyFirst = async (): Promise<string> => {
  const secondLevelEncryptedKeyFirst = await fs.readFileSync(
    "../testdata/second_encrypted_key_first.txt"
  );
  return secondLevelEncryptedKeyFirst.toString();
};

export const getSecondLevelEncryptedKeySecond =
  async (): Promise<GTElement> => {
    const secondLevelEncryptedKeySecond = await fs.readFileSync(
      "../testdata/second_encrypted_key_second.txt",
      "utf-8"
    );
    return BN254CurveWrapper.GTFromBytes(
      new Uint8Array(
        Buffer.from(secondLevelEncryptedKeySecond.trim(), "base64")
      )
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

export function createRandomHexString(length: number): string {
  const chars = "0123456789abcdef";
  return createRandomString(chars, length);
}

// Function to generate a random hex string of a given length using chunking
export function createRandomString(chars: string, length: number) {
  let result = "";
  const chunkSize = 10000; // Process 10000 characters at a time

  for (let i = 0; i < length; i += chunkSize) {
    const currentChunkSize = Math.min(chunkSize, length - i);
    const randomArray = new Uint8Array(currentChunkSize);
    crypto.getRandomValues(randomArray);

    let chunkResult = "";
    randomArray.forEach((number) => {
      chunkResult += chars[number % chars.length];
    });

    result += chunkResult;
  }

  return result;
}

// Function to generate random bytes for testing
export function generateRandomBytesForTesting(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
export function createRandomBase64String(length: number): string {
  // Constants for chunking
  const chunkSize = 30000; // Number of bytes per chunk
  let result = "";

  // Process in chunks to avoid memory issues with very large strings
  for (let processedLength = 0; processedLength < length; ) {
    // Calculate how many more Base64 characters we need
    const remainingLength = length - processedLength;

    // Calculate how many bytes to generate for this chunk
    // Base64 encoding: 3 bytes -> 4 Base64 chars
    // So multiply by 0.75 to get bytes needed
    const bytesToGenerate = Math.min(
      chunkSize,
      Math.ceil(remainingLength * 0.75) + 3 // +3 for potential padding
    );

    // Generate random bytes for this chunk
    const chunkBytes = new Uint8Array(bytesToGenerate);
    crypto.getRandomValues(chunkBytes);

    // Convert bytes to binary string
    const binaryString = Array.from(chunkBytes)
      .map((byte) => String.fromCharCode(byte))
      .join("");

    // Convert to Base64
    const chunkBase64 = btoa(binaryString);

    // Calculate how many Base64 chars to take from this chunk
    const charsToTake = Math.min(remainingLength, chunkBase64.length);

    // Add to result
    result += chunkBase64.substring(0, charsToTake);

    // Update processed length
    processedLength += charsToTake;
  }

  return result;
}

export function createRandomUTF8String(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  return createRandomString(chars, length);
}
