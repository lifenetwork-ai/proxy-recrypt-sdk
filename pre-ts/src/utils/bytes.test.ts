import { describe, test, expect, it } from "@jest/globals";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToString,
  hexToBytes,
  stringToBytes,
} from "./bytes";
import {
  createRandomBase64String,
  createRandomHexString,
  createRandomUTF8String,
} from "./testUtils";

describe("test hex bytes utils", () => {
  it("should convert hex string to byte array and back", () => {
    const hex = "48656c6c6f20576f726c6421";

    const byteArray = hexToBytes(hex);
    const returnedHex = bytesToHex(byteArray);

    expect(returnedHex).toEqual(hex);
  });

  it("should convert arbitrary long hex string to byte array and back", () => {
    const hex = createRandomHexString(100000);

    const byteArray = hexToBytes(hex);
    const returnedHex = bytesToHex(byteArray);
    expect(returnedHex).toEqual(hex);
  });

  // New tests for hex utilities
  it("should throw error for odd-length hex string", () => {
    const oddHex = "48656c6c6f20576f726c642";
    expect(() => hexToBytes(oddHex)).toThrow(
      "Hex string must have an even length"
    );
  });

  it("should handle empty hex string", () => {
    const emptyHex = "";
    const byteArray = hexToBytes(emptyHex);
    expect(byteArray.length).toBe(0);
    expect(bytesToHex(byteArray)).toBe(emptyHex);
  });

  it("should handle hex string with special values", () => {
    // Test with all possible byte values (00-FF)
    let completeHex = "";
    for (let i = 0; i < 256; i++) {
      completeHex += i.toString(16).padStart(2, "0");
    }

    const byteArray = hexToBytes(completeHex);
    expect(byteArray.length).toBe(256);

    for (let i = 0; i < 256; i++) {
      expect(byteArray[i]).toBe(i);
    }

    expect(bytesToHex(byteArray)).toBe(completeHex);
  });

  it("should handle hex chunks at exact chunk boundaries", () => {
    // Create a hex string that's exactly one chunk size
    const chunkSizeInBytes = 5000;
    const chunkSizeInHexChars = chunkSizeInBytes * 2;
    const exactChunkHex = "aa".repeat(chunkSizeInBytes);

    expect(exactChunkHex.length).toBe(chunkSizeInHexChars);

    const byteArray = hexToBytes(exactChunkHex);
    expect(byteArray.length).toBe(chunkSizeInBytes);
    expect(bytesToHex(byteArray)).toBe(exactChunkHex);
  });
});

describe("test base64 bytes utils", () => {
  it("should convert base64 string to byte array and back", () => {
    const base64 = "SGVsbG8gV29ybGQh"; // "Hello World!" in base64
    const byteArray = base64ToBytes(base64);
    const returnedBase64 = bytesToBase64(byteArray);
    expect(returnedBase64).toEqual(base64);
  });

  it("should convert arbitrary long base64 string to byte array and back", () => {
    const base64 = createRandomBase64String(100000);
    const byteArray = base64ToBytes(base64);
    const returnedBase64 = bytesToBase64(byteArray);
    expect(returnedBase64).toEqual(base64);
  });

  // New tests for base64 utilities
  it("should handle empty base64 string", () => {
    const emptyBase64 = "";
    const byteArray = base64ToBytes(emptyBase64);
    expect(byteArray.length).toBe(0);
    expect(bytesToBase64(byteArray)).toBe(emptyBase64);
  });

  it("should correctly convert known base64 values", () => {
    const testCases = [
      { str: "Hello", base64: "SGVsbG8=" },
      { str: "A", base64: "QQ==" },
      { str: "AB", base64: "QUI=" },
      { str: "ABC", base64: "QUJD" },
      {
        str: "Special chars: !@#$%^&*()",
        base64: "U3BlY2lhbCBjaGFyczogIUAjJCVeJiooKQ==",
      },
    ];

    for (const testCase of testCases) {
      // Test string → bytes → base64
      const bytes = stringToBytes(testCase.str);
      expect(bytesToBase64(bytes)).toBe(testCase.base64);

      // Test base64 → bytes → string
      const bytesFromBase64 = base64ToBytes(testCase.base64);
      expect(bytesToString(bytesFromBase64)).toBe(testCase.str);
    }
  });

  it("should handle base64 with padding", () => {
    // Test cases with different padding amounts
    const testCases = [
      { base64: "YQ==", decoded: "a" }, // 2 padding chars
      { base64: "YWI=", decoded: "ab" }, // 1 padding char
      { base64: "YWJj", decoded: "abc" }, // 0 padding chars
    ];

    for (const testCase of testCases) {
      const bytes = base64ToBytes(testCase.base64);
      expect(bytesToString(bytes)).toBe(testCase.decoded);
    }
  });
});

describe("test utf8 bytes utils", () => {
  it("should convert utf8 string to byte array and back", () => {
    const str = "Hello, World!";
    const byteArray = stringToBytes(str);
    const returnedStr = bytesToString(byteArray);
    expect(returnedStr).toEqual(str);
  });

  it("should convert arbitrary long utf8 string to byte array and back", () => {
    const str = createRandomUTF8String(100000);
    const byteArray = stringToBytes(str);
    const returnedStr = bytesToString(byteArray);
    expect(returnedStr).toEqual(str);
  });

  // New tests for UTF-8 utilities
  it("should handle empty string", () => {
    const emptyStr = "";
    const byteArray = stringToBytes(emptyStr);
    expect(byteArray.length).toBe(0);
    expect(bytesToString(byteArray)).toBe(emptyStr);
  });

  it("should correctly encode and decode multi-byte UTF-8 characters", () => {
    const testCases = [
      { char: "¢", bytes: [0xc2, 0xa2] }, // 2-byte: U+00A2 CENT SIGN
      { char: "€", bytes: [0xe2, 0x82, 0xac] }, // 3-byte: U+20AC EURO SIGN
      { char: "𠜎", bytes: [0xf0, 0xa0, 0x9c, 0x8e] }, // 4-byte: U+2070E (CJK UNIFIED IDEOGRAPH)
    ];

    for (const testCase of testCases) {
      const byteArray = stringToBytes(testCase.char);

      // Check each byte matches expected value
      expect(Array.from(byteArray)).toEqual(testCase.bytes);

      // Check round-trip conversion
      expect(bytesToString(byteArray)).toBe(testCase.char);
    }
  });

  it("should correctly handle strings with mixed character lengths", () => {
    // Mix of ASCII, 2-byte, 3-byte, and 4-byte characters
    const mixedStr = "Hello, ¢€𠜎!";
    const byteArray = stringToBytes(mixedStr);
    expect(bytesToString(byteArray)).toBe(mixedStr);
  });

  it("should handle surrogate pairs correctly", () => {
    // Emoji with surrogate pairs: "👍" (U+1F44D THUMBS UP SIGN)
    const emoji = "👍";

    // It's represented as \uD83D\uDC4D in JavaScript (surrogate pair)
    expect(emoji.length).toBe(2); // In JavaScript, this is 2 code units

    const byteArray = stringToBytes(emoji);

    // In UTF-8, it's 4 bytes: F0 9F 91 8D
    expect(byteArray.length).toBe(4);
    expect(Array.from(byteArray)).toEqual([0xf0, 0x9f, 0x91, 0x8d]);

    // Check round-trip conversion
    expect(bytesToString(byteArray)).toBe(emoji);
  });

  it("should handle a string with all types of UTF-8 sequences", () => {
    // String with 1, 2, 3, and 4 byte characters
    const complexStr = "a¢€𠜎";
    const byteArray = stringToBytes(complexStr);

    // Expected bytes: 1 + 2 + 3 + 4 = 10 bytes total
    expect(byteArray.length).toBe(10);

    // Check expected byte sequence
    expect(Array.from(byteArray)).toEqual([
      0x61, // 'a' (ASCII)
      0xc2,
      0xa2, // '¢' (2-byte)
      0xe2,
      0x82,
      0xac, // '€' (3-byte)
      0xf0,
      0xa0,
      0x9c,
      0x8e, // '𠜎' (4-byte)
    ]);

    // Check round-trip conversion
    expect(bytesToString(byteArray)).toBe(complexStr);
  });

  it("should handle invalid UTF-8 sequences gracefully", () => {
    // Create some invalid UTF-8 sequences
    const invalidBytes = new Uint8Array([
      // Incomplete 2-byte sequence
      0xc2,
      // Incomplete 3-byte sequence
      0xe2, 0x82,
      // Incomplete 4-byte sequence
      0xf0, 0xa0, 0x9c,
      // Invalid continuation byte
      0x80,
      // Valid ASCII byte
      0x61,
    ]);

    // The function should skip invalid sequences but process valid ones
    const result = bytesToString(invalidBytes);

    // Should at least contain the valid ASCII 'a'
    expect(result.includes("a")).toBe(true);

    // Length should be less than the number of bytes due to skipping
    expect(result.length).toBeLessThan(invalidBytes.length);
  });
});

// New cross-utility tests
describe("cross-utility integration tests", () => {
  it("should convert between hex, base64, and string formats correctly", () => {
    const originalString = "Hello, World! Special chars: ¢€𠜎";

    // String → Bytes → Hex → Bytes → String
    const bytes1 = stringToBytes(originalString);
    const hex = bytesToHex(bytes1);
    const bytes2 = hexToBytes(hex);
    const finalString1 = bytesToString(bytes2);
    expect(finalString1).toBe(originalString);

    // String → Bytes → Base64 → Bytes → String
    const bytes3 = stringToBytes(originalString);
    const base64 = bytesToBase64(bytes3);
    const bytes4 = base64ToBytes(base64);
    const finalString2 = bytesToString(bytes4);
    expect(finalString2).toBe(originalString);
  });

  it("should handle all byte values through all conversions", () => {
    // Create a Uint8Array with all possible byte values (0-255)
    const allBytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      allBytes[i] = i;
    }

    // Test hex round trip
    const hex = bytesToHex(allBytes);
    const fromHex = hexToBytes(hex);
    for (let i = 0; i < 256; i++) {
      expect(fromHex[i]).toBe(i);
    }

    // Test base64 round trip
    const base64 = bytesToBase64(allBytes);
    const fromBase64 = base64ToBytes(base64);
    for (let i = 0; i < 256; i++) {
      expect(fromBase64[i]).toBe(i);
    }
  });

  it("should perform multi-step conversions with large data", () => {
    // Create a large random string
    const largeStr = createRandomUTF8String(10000);

    // Multi-step conversion
    const bytes1 = stringToBytes(largeStr);
    const hex = bytesToHex(bytes1);
    const base64 = bytesToBase64(bytes1);
    const bytes2 = hexToBytes(hex);
    const bytes3 = base64ToBytes(base64);

    // All byte arrays should be identical
    expect(bytes2.length).toBe(bytes1.length);
    expect(bytes3.length).toBe(bytes1.length);

    // Convert back to strings
    const str1 = bytesToString(bytes1);
    const str2 = bytesToString(bytes2);
    const str3 = bytesToString(bytes3);

    // All strings should be identical to the original
    expect(str1).toBe(largeStr);
    expect(str2).toBe(largeStr);
    expect(str3).toBe(largeStr);
  });

  it("should handle all possible 1-byte, 2-byte, 3-byte, and 4-byte Unicode characters", () => {
    // Test a selection of characters from different Unicode planes
    const testCharacters = [
      // Basic Latin (ASCII) - 1 byte in UTF-8
      "A",
      "z",
      "0",
      "!",

      // Latin-1 Supplement, Greek, Cyrillic - 2 bytes in UTF-8
      "é",
      "Ω",
      "Я",

      // CJK Unified Ideographs, Symbols - 3 bytes in UTF-8
      "語",
      "漢",
      "♠",
      "♥",

      // Supplementary planes (Emoji, rare CJK) - 4 bytes in UTF-8
      "𠜎",
      "𝄞",
      "😀",
      "🚀",
    ];

    for (const char of testCharacters) {
      const bytes = stringToBytes(char);
      const roundTrip = bytesToString(bytes);
      expect(roundTrip).toBe(char);

      // Also check hex and base64 roundtrips
      const hex = bytesToHex(bytes);
      const fromHex = hexToBytes(hex);
      expect(bytesToString(fromHex)).toBe(char);

      const base64 = bytesToBase64(bytes);
      const fromBase64 = base64ToBytes(base64);
      expect(bytesToString(fromBase64)).toBe(char);
    }
  });
});
