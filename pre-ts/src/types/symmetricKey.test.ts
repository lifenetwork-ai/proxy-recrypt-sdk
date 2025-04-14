import { describe, test, expect } from "@jest/globals";
import { BN254CurveWrapper } from "../crypto";
import { SecondLevelSymmetricKey } from "./symmetricKey";

describe("SecondLevelSymmetricKey", () => {
  // Helper function to create a random key
  const createRandomKey = () => {
    const first = BN254CurveWrapper.G1Generator();

    // second is different for each createRandomKey call
    const second = BN254CurveWrapper.generateRandomGTElement();
    return new SecondLevelSymmetricKey(first, second);
  };

  test("constructor should properly initialize the key", () => {
    const first = BN254CurveWrapper.G1Generator();
    const second = BN254CurveWrapper.GTBase();

    const key = new SecondLevelSymmetricKey(first, second);

    expect(key.first).toBe(first);
    expect(key.second).toBe(second);
  });

  test("toBytes should return correct length", () => {
    const key = createRandomKey();
    const bytes = key.toBytes();
    expect(bytes.length).toBe(448);
  });

  test("toBytes and fromBytes should work correctly", () => {
    const first = BN254CurveWrapper.G1Generator();
    const second = BN254CurveWrapper.GTBase();
    const key = new SecondLevelSymmetricKey(first, second);

    const bytes = key.toBytes();
    const newKey = SecondLevelSymmetricKey.fromBytes(bytes);

    expect(newKey.first).toEqual(first);
    expect(newKey.second).toEqual(second);
  });

  test("fromBytes should throw error for invalid length", () => {
    const invalidBytes = new Uint8Array(100); // Wrong length

    expect(() => {
      SecondLevelSymmetricKey.fromBytes(invalidBytes);
    }).toThrow(
      "Invalid byte length for SecondLevelSymmetricKey: expected 448, got 100"
    );
  });

  test("multiple conversions should preserve data integrity", () => {
    const key = createRandomKey();

    // Convert to bytes and back multiple times
    const bytes1 = key.toBytes();
    const key1 = SecondLevelSymmetricKey.fromBytes(bytes1);
    const bytes2 = key1.toBytes();
    const key2 = SecondLevelSymmetricKey.fromBytes(bytes2);

    // Compare original key with final key
    expect(key2.first).toEqual(key.first);
    expect(key2.second).toEqual(key.second);

    // Compare intermediate byte arrays
    expect(bytes2).toEqual(bytes1);
  });

  test("different keys should produce different byte representations", () => {
    const key1 = createRandomKey();
    const key2 = createRandomKey();

    const bytes1 = key1.toBytes();
    const bytes2 = key2.toBytes();

    console.log("Key 1 bytes:", bytes1);
    console.log("Key 2 bytes:", bytes2);

    // Check that the byte representations are different
    expect(bytes1).not.toEqual(bytes2);
  });

  test("fromBytes should correctly parse G1 and GT components", () => {
    const key = createRandomKey();
    const bytes = key.toBytes();

    // Get individual components
    const g1Bytes = bytes.slice(0, 64);
    const gtBytes = bytes.slice(64, 448);

    // Verify components can be parsed individually
    const parsedG1 = BN254CurveWrapper.G1FromBytes(g1Bytes);
    const parsedGT = BN254CurveWrapper.GTFromBytes(gtBytes);

    expect(parsedG1).toEqual(key.first);
    expect(parsedGT).toEqual(key.second);
  });
});
