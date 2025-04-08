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
  createRandomString,
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
});

describe("test utf8 bytes utils", () => {
  it("should convert utf8 string to byte array and back", () => {
    const str = "Hello, World!";
    const byteArray = new TextEncoder().encode(str);
    const returnedStr = new TextDecoder().decode(byteArray);
    expect(returnedStr).toEqual(str);
  });

  it("should convert arbitrary long utf8 string to byte array and back", () => {
    const str = createRandomUTF8String(100000);
    const byteArray = stringToBytes(str);
    const returnedStr = bytesToString(byteArray);
    expect(returnedStr).toEqual(str);
  });
});
