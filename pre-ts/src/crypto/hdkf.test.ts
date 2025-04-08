import { BN254CurveWrapper } from "./bn254";
import { deriveKeyFromGT, generateRandomSymmetricKeyFromGT } from "./hdkf";
import { describe, test, expect } from "@jest/globals";

describe("HDKF", () => {
  test("HDKF derive", async () => {
    const { keyGT, key } = await generateRandomSymmetricKeyFromGT(32);

    expect(keyGT).toBeDefined();
    expect(key).toBeDefined();
    expect(key.length).toBe(32);

    const derivedKey = await deriveKeyFromGT(keyGT, 32);
    expect(derivedKey).toBeDefined();

    expect(key).toEqual(derivedKey);
  });
});

describe("HKDF edge cases", () => {
  test("should throw on invalid key size", async () => {
    const gtElement = BN254CurveWrapper.generateRandomGTElement();
    const testFunc = async () => await deriveKeyFromGT(gtElement, 15);
    await expect(testFunc).rejects.toThrow("Invalid key size");
  });

  test("should generate different keys for different GT elements", async () => {
    const gt1 = BN254CurveWrapper.generateRandomGTElement();
    const gt2 = BN254CurveWrapper.generateRandomGTElement();

    const key1 = await deriveKeyFromGT(gt1, 32);
    const key2 = await deriveKeyFromGT(gt2, 32);

    expect(Buffer.compare(key1, key2)).not.toBe(0);
  });
});
