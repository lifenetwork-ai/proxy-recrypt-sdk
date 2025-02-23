import { deriveKeyFromGT, generateRandomSymmetricKeyFromGT } from "./hdkf";

describe("HDKF", () => {
  test("HDKF derive", () => {
    const { keyGT, key } = generateRandomSymmetricKeyFromGT(32);

    expect(keyGT).toBeDefined();
    expect(key).toBeDefined();
    expect(key.length).toBe(32);

    const derivedKey = deriveKeyFromGT(keyGT, 32);
    expect(derivedKey).toBeDefined();

    expect(key).toEqual(derivedKey);
  });
});
