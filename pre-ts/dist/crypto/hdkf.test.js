import { BN254CurveWrapper } from "./bn254";
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
describe("HKDF edge cases", () => {
    test("should throw on invalid key size", () => {
        const gtElement = BN254CurveWrapper.generateRandomGTElement();
        expect(() => deriveKeyFromGT(gtElement, 15)).toThrow("Invalid key size");
    });
    test("should generate different keys for different GT elements", () => {
        const gt1 = BN254CurveWrapper.generateRandomGTElement();
        const gt2 = BN254CurveWrapper.generateRandomGTElement();
        const key1 = deriveKeyFromGT(gt1, 32);
        const key2 = deriveKeyFromGT(gt2, 32);
        expect(Buffer.compare(key1, key2)).not.toBe(0);
    });
});
