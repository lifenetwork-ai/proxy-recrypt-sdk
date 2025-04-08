import { describe, test, expect, it } from "@jest/globals";
import {
  generateRandomSecretKey,
  generateRandomScalar,
} from "../utils/keypair";
import { SecretKey } from "../types";
import { bn254 } from "@noble/curves/bn254";

describe("Secret Key Generation", () => {
  describe("generateRandomScalar", () => {
    it("should generate a scalar within the valid range", () => {
      const order = bn254.fields.Fr.ORDER;
      const scalar = generateRandomScalar();

      expect(scalar >= 0n).toBeTruthy();
      expect(scalar < order).toBeTruthy();
    });

    it("should generate different scalars on subsequent calls", () => {
      const scalar1 = generateRandomScalar();
      const scalar2 = generateRandomScalar();

      expect(scalar1).not.toEqual(scalar2);
    });
  });

  describe("generateRandomSecretKey", () => {
    it("should create a valid SecretKey instance", () => {
      const secretKey = generateRandomSecretKey();

      expect(secretKey).toBeInstanceOf(SecretKey);
    });

    it("should contain two different random scalars", () => {
      const secretKey = generateRandomSecretKey();

      // Assuming SecretKey has a way to access its scalar components
      // This will need to be adjusted based on the actual implementation of SecretKey
      const scalar1 = secretKey.first; // Adjust method name as needed
      const scalar2 = secretKey.second; // Adjust method name as needed

      expect(scalar1).not.toEqual(scalar2);
    });

    it("should generate different secret keys on subsequent calls", () => {
      const secretKey1 = generateRandomSecretKey();
      const secretKey2 = generateRandomSecretKey();

      // Assuming SecretKey has a method to compare equality
      // Adjust based on actual implementation
      expect(secretKey1).not.toEqual(secretKey2);
    });
  });

  describe("SecretKey properties", () => {
    it("should contain valid scalars within the field order", () => {
      const order = bn254.fields.Fr.ORDER;
      const secretKey = generateRandomSecretKey();

      // Adjust method names based on actual implementation
      const scalar1 = secretKey.first;
      const scalar2 = secretKey.second;

      expect(scalar1 >= 0n).toBeTruthy();
      expect(scalar1 < order).toBeTruthy();
      expect(scalar2 >= 0n).toBeTruthy();
      expect(scalar2 < order).toBeTruthy();
    });
  });
});
