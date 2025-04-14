import { describe, test, expect } from "@jest/globals";
import { Fp, Fp12, Fp6, Fp2 } from "@noble/curves/abstract/tower";
import { Buffer } from "buffer";
import {
  g1FromBytes,
  g1ToBytes,
  g2FromBytes,
  g2ToBytes,
  bytesToBigInt,
  bigIntToBytes,
  base64BufferToBigInt,
  fp12ToBytes,
  fp12FromBytes,
} from ".";
import { bn254 } from "@noble/curves/bn254";

describe("G1 Point Conversion", () => {
  const sampleG1Point = {
    x: BigInt(
      "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
    ),
    y: BigInt(
      "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    ),
  };

  test("g1ToBytes should produce correct length output", () => {
    const bytes = g1ToBytes(sampleG1Point);
    expect(bytes.length).toBe(64);
  });

  test("g1ToBytes and g1FromBytes should be inverse operations", () => {
    const bytes = g1ToBytes(sampleG1Point);
    const reconstructed = g1FromBytes(bytes);

    expect(reconstructed.x).toBe(sampleG1Point.x);
    expect(reconstructed.y).toBe(sampleG1Point.y);
  });

  test("g1FromBytes should throw error for invalid length", () => {
    const invalidBytes = new Uint8Array(63);
    expect(() => g1FromBytes(invalidBytes)).toThrow("Invalid G1 point size");
  });
});

describe("G2 Point Conversion", () => {
  const sampleG2Point = {
    x: {
      c0: BigInt(
        "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
      ),
      c1: BigInt(
        "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
      ),
    },
    y: {
      c0: BigInt(
        "0xaabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011"
      ),
      c1: BigInt(
        "0x1122334455667788112233445566778811223344556677881122334455667788"
      ),
    },
  };

  test("g2ToBytes should produce correct length output", () => {
    const bytes = g2ToBytes(sampleG2Point);
    expect(bytes.length).toBe(128);
  });

  test("g2ToBytes and g2FromBytes should be inverse operations", () => {
    const bytes = g2ToBytes(sampleG2Point);
    const reconstructed = g2FromBytes(bytes);

    expect(reconstructed.x.c0).toBe(sampleG2Point.x.c0);
    expect(reconstructed.x.c1).toBe(sampleG2Point.x.c1);
    expect(reconstructed.y.c0).toBe(sampleG2Point.y.c0);
    expect(reconstructed.y.c1).toBe(sampleG2Point.y.c1);
  });

  test("g2FromBytes should throw error for invalid length", () => {
    const invalidBytes = new Uint8Array(127);
    expect(() => g2FromBytes(invalidBytes)).toThrow(
      "Invalid point encoding: expected 128 bytes"
    );
  });

  test("g2FromBytes should throw error for infinity point", () => {
    const infinityBytes = new Uint8Array(128);
    expect(() => g2FromBytes(infinityBytes)).toThrow(
      "Infinity point not supported"
    );
  });
});

describe("BigInt Conversion Utilities", () => {
  test("bytesToBigInt should correctly convert bytes to BigInt", () => {
    const bytes = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const result = bytesToBigInt(bytes);
    expect(result).toBe(BigInt("0x12345678"));
  });

  test("bigIntToBytes should correctly convert BigInt to bytes", () => {
    const value = BigInt("0x12345678");
    const target = new Uint8Array(4);
    bigIntToBytes(value, target);
    expect([...target]).toEqual([0x12, 0x34, 0x56, 0x78]);
  });

  test("base64BufferToBigInt should correctly convert base64 to BigInt", () => {
    const base64Str = "EjRWeA=="; // Base64 for [0x12, 0x34, 0x56, 0x78]
    const buffer = Buffer.from(base64Str);
    const result = base64BufferToBigInt(buffer);
    expect(result).toBe(BigInt("0x12345678"));
  });
});

describe("Fp12 Element Conversion", () => {
  // Mock Fp field implementation for testing
  const mockFp = bn254.fields.Fp;
  const mockFp2 = bn254.fields.Fp2;
  const mockFp6 = bn254.fields.Fp6;
  const mockFp12 = bn254.fields.Fp12;
  // Create a sample Fp12 element
  const sampleFp12 = {
    c0: {
      c0: { c0: BigInt(1), c1: BigInt(2) },
      c1: { c0: BigInt(3), c1: BigInt(4) },
      c2: { c0: BigInt(5), c1: BigInt(6) },
    },
    c1: {
      c0: { c0: BigInt(7), c1: BigInt(8) },
      c1: { c0: BigInt(9), c1: BigInt(10) },
      c2: { c0: BigInt(11), c1: BigInt(12) },
    },
  };

  test("fp12ToBytes should produce correct length output", () => {
    const bytes = fp12ToBytes(sampleFp12 as Fp12, mockFp);
    expect(bytes.length).toBe(12 * mockFp.BYTES);
  });

  test("fp12FromBytes should throw error for invalid length", () => {
    const invalidBytes = new Uint8Array(383); // Not 12 * BYTES
    expect(() =>
      fp12FromBytes(invalidBytes, mockFp, mockFp2, mockFp6, mockFp12)
    ).toThrow("Invalid byte length");
  });

  // Note: A complete round-trip test would require proper Fp12 field implementation
  // This test verifies the basic structure
  test("fp12ToBytes should maintain correct byte ordering", () => {
    const bytes = fp12ToBytes(sampleFp12 as Fp12, mockFp);
    expect(bytes.length).toBe(384); // 12 * 32 bytes

    // Verify some known byte positions based on the structure
    const firstElement = bytesToBigInt(bytes.slice(0, 32));
    const lastElement = bytesToBigInt(bytes.slice(352, 384));

    // In the byte ordering, c1.c2.c1 should be first and c0.c0.c0 should be last
    expect(firstElement).toBe(BigInt(12)); // c1.c2.c1
    expect(lastElement).toBe(BigInt(1)); // c0.c0.c0
  });
});
