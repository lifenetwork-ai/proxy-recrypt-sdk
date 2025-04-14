import { describe, test, expect } from "@jest/globals";
import { BN254CurveWrapper } from "../crypto/bn254";
import { SecretKey, PublicKey } from ".";
import {
  bytesToHex,
  generateRandomScalar,
  generateRandomSecretKey,
  hexToBytes,
  secretToPubkey,
} from "../utils";
import { generateRandomSymmetricKeyFromGT } from "../crypto";

describe("SecretKey", () => {
  const createTestSecretKey = () => {
    return generateRandomSecretKey();
  };

  test("constructor should properly initialize the key", () => {
    const first = generateRandomScalar();
    const second = generateRandomScalar();

    const key = new SecretKey(first, second);

    expect(key.first).toBe(first);
    expect(key.second).toBe(second);
  });

  test("toBytes should return correct length", () => {
    const key = createTestSecretKey();
    const bytes = key.toBytes();
    expect(bytes.length).toBe(64); // 32 bytes for each bigint
  });

  test("toBytes and fromBytes should work correctly", () => {
    const key = createTestSecretKey();
    const bytes = key.toBytes();
    const newKey = SecretKey.fromBytes(bytes);

    expect(newKey.first).toBe(key.first);
    expect(newKey.second).toBe(key.second);
  });

  test("should handle zero values correctly", () => {
    const key = new SecretKey(BigInt(0), BigInt(0));
    const bytes = key.toBytes();
    const newKey = SecretKey.fromBytes(bytes);

    expect(newKey.first).toBe(BigInt(0));
    expect(newKey.second).toBe(BigInt(0));
  });

  test("multiple conversions should preserve data integrity", () => {
    const key = createTestSecretKey();

    const bytes1 = key.toBytes();
    const key1 = SecretKey.fromBytes(bytes1);
    const bytes2 = key1.toBytes();
    const key2 = SecretKey.fromBytes(bytes2);

    expect(key2.first).toBe(key.first);
    expect(key2.second).toBe(key.second);
    expect(bytes2).toEqual(bytes1);
  });
});

describe("PublicKey", () => {
  const createTestPublicKey = () => {
    return secretToPubkey(
      generateRandomSecretKey(),
      BN254CurveWrapper.G2Generator(),
      BN254CurveWrapper.GTBase()
    );
  };

  test("constructor should work with individual parameters", () => {
    const first = BN254CurveWrapper.GTBase();
    const second = BN254CurveWrapper.G2Generator();

    const key = new PublicKey(first, second);

    expect(key.first).toBe(first);
    expect(key.second).toBe(second);
  });

  test("constructor should work with object parameter", () => {
    const first = BN254CurveWrapper.GTBase();
    const second = BN254CurveWrapper.G2Generator();

    const key = new PublicKey({ first, second });

    expect(key.first).toBe(first);
    expect(key.second).toBe(second);
  });

  test("toBytes should return correct length", () => {
    const key = createTestPublicKey();
    const bytes = key.toBytes();
    expect(bytes.length).toBe(512); // 384 bytes for GT + 128 bytes for G2
  });

  test("toBytes and fromBytes should work correctly", () => {
    const key = createTestPublicKey();
    const bytes = key.toBytes();
    const newKey = PublicKey.fromBytes(bytes);

    expect(newKey.first).toEqual(key.first);
    expect(newKey.second).toEqual(key.second);
  });

  test("multiple conversions should preserve data integrity", () => {
    const key = createTestPublicKey();

    const bytes1 = key.toBytes();
    const key1 = PublicKey.fromBytes(bytes1);
    const bytes2 = key1.toBytes();
    const key2 = PublicKey.fromBytes(bytes2);

    expect(key2.first).toEqual(key.first);
    expect(key2.second).toEqual(key.second);
    expect(bytes2).toEqual(bytes1);
  });

  test("different keys should produce different byte representations", () => {
    const key1 = createTestPublicKey();
    const key2 = new PublicKey(
      BN254CurveWrapper.GTBase(),
      BN254CurveWrapper.G2Generator()
    );

    const bytes1 = key1.toBytes();
    const bytes2 = key2.toBytes();

    expect(bytes1).not.toEqual(bytes2);
  });

  test("fromBytes should correctly parse GT and G2 components", () => {
    const key = createTestPublicKey();
    const bytes = key.toBytes();

    // Get individual components
    const gtBytes = bytes.slice(0, 384);
    const g2Bytes = bytes.slice(384, 512);

    // Verify components can be parsed individually
    const parsedGT = BN254CurveWrapper.GTFromBytes(gtBytes);
    const parsedG2 = BN254CurveWrapper.G2FromBytes(g2Bytes);

    expect(parsedGT).toEqual(key.first);
    expect(parsedG2).toEqual(key.second);
  });

  test("should handle different GT and G2 values", () => {
    const testCases = [
      {
        first: BN254CurveWrapper.generateRandomGTElement(),
        second: BN254CurveWrapper.G2Generator(),
      },
      {
        first: BN254CurveWrapper.generateRandomGTElement(),
        second: BN254CurveWrapper.G2Generator(),
      },
    ];

    testCases.forEach(({ first, second }) => {
      const key = new PublicKey(first, second);
      const bytes = key.toBytes();
      const newKey = PublicKey.fromBytes(bytes);

      expect(newKey.first).toEqual(first);
      expect(newKey.second).toEqual(second);
    });
  });
});
