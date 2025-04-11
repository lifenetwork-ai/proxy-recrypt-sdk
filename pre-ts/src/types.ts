import { BN254CurveWrapper, G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bytesToHex, hexToBytes } from "./utils";

export interface KeyPair {
  secretKey: SecretKey;
  publicKey: PublicKey;
}

export class SecretKey {
  first: bigint; // First component of secret key
  second: bigint; // Second component of secret key

  constructor(first: bigint, second: bigint) {
    this.first = first;
    this.second = second;
  }

  toBytes(): Uint8Array {
    // Convert bigints to hex strings
    const firstHex = this.first.toString(16).padStart(64, "0");
    const secondHex = this.second.toString(16).padStart(64, "0");

    // Convert combined hex string to Uint8Array
    return hexToBytes(firstHex + secondHex);
  }

  static fromBytes(bytes: Uint8Array): SecretKey {
    const hex = bytesToHex(bytes);
    return new SecretKey(
      BigInt("0x" + hex.slice(0, 64)),
      BigInt("0x" + hex.slice(64, 128))
    );
  }
}

export class PublicKey {
  first: GTElement; // Element in GT group
  second: G2Point; // Point in G2 group

  // These are just signatures (declarations without implementation)
  constructor(params: { first: GTElement; second: G2Point });
  constructor(first: GTElement, second: G2Point);

  constructor(
    firstOrParams: GTElement | { first: GTElement; second: G2Point },
    secondParam?: G2Point
  ) {
    if (
      firstOrParams &&
      typeof firstOrParams === "object" &&
      "first" in firstOrParams
    ) {
      // Object parameter overload
      this.first = firstOrParams.first;
      this.second = firstOrParams.second;
    } else {
      // Individual parameters overload
      this.first = firstOrParams as GTElement;
      this.second = secondParam as G2Point;
    }
  }

  toBytes(): Uint8Array {
    // Convert GTElement to bytes
    const firstBytes = BN254CurveWrapper.GTToBytes(this.first);
    // Convert G2Point to bytes
    const secondBytes = BN254CurveWrapper.G2ToBytes(this.second);

    // Concatenate the two byte arrays
    return new Uint8Array([...firstBytes, ...secondBytes]);
  }

  static fromBytes(pubkeyBytes: Uint8Array): PublicKey {
    // Convert bytes back to GTElement and G2Point
    const first = BN254CurveWrapper.GTFromBytes(pubkeyBytes.slice(0, 96));
    const second = BN254CurveWrapper.G2FromBytes(pubkeyBytes.slice(96, 224));
    return new PublicKey(first, second);
  }
}

// Cipher text structures
export interface FirstLevelSymmetricKey {
  first: GTElement; // First component in GT group
  second: GTElement; // Second component in GT group
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export function parseFirstLevelSymmetricKey(data: any): FirstLevelSymmetricKey {
  // Function to convert B0/B1/B2 to c0/c1/c2 and A0/A1 to c0/c1
  // Also converts string values to bigint
  const processThirdLevel = (element: any) => {
    const result: any = {};

    // Map B0/B1/B2 fields to c0/c1/c2 and convert to bigint
    if (element.B0)
      result.c0 = {
        c0: BigInt(element.B0.A0),
        c1: BigInt(element.B0.A1),
      };

    if (element.B1)
      result.c1 = {
        c0: BigInt(element.B1.A0),
        c1: BigInt(element.B1.A1),
      };

    if (element.B2)
      result.c2 = {
        c0: BigInt(element.B2.A0),
        c1: BigInt(element.B2.A1),
      };

    return result;
  };

  // Process each level
  const result: FirstLevelSymmetricKey = {
    first: {
      c0: processThirdLevel(data.first.c0 || data.first.C0),
      c1: processThirdLevel(data.first.c1 || data.first.C1),
    },
    second: {
      c0: processThirdLevel(data.second.c0 || data.second.C0),
      c1: processThirdLevel(data.second.c1 || data.second.C1),
    },
  };

  return result;
}

export class SecondLevelSymmetricKey {
  first: G1Point; // First component in G1 group
  second: GTElement; // Second component in GT group

  constructor(first: G1Point, second: GTElement) {
    this.first = first;
    this.second = second;
  }

  toBytes(): Uint8Array {
    // Convert G1Point to bytes
    const firstBytes = BN254CurveWrapper.G1ToBytes(this.first);
    // Convert GTElement to bytes
    const secondBytes = BN254CurveWrapper.GTToBytes(this.second);

    // Concatenate the two byte arrays
    return new Uint8Array([...firstBytes, ...secondBytes]);
  }

  static fromBytes(keyBytes: Uint8Array): SecondLevelSymmetricKey {
    if (keyBytes.length !== 448) {
      throw new Error(
        `Invalid byte length for SecondLevelSymmetricKey: expected 448, got ${keyBytes.length}`
      );
    }
    // Convert bytes back to G1Point and GTElement
    const first = BN254CurveWrapper.G1FromBytes(keyBytes.slice(0, 64));
    const second = BN254CurveWrapper.GTFromBytes(keyBytes.slice(64, 448));
    return new SecondLevelSymmetricKey(first, second);
  }
}

export interface FirstLevelEncryptionResponse {
  encryptedKey: FirstLevelSymmetricKey;
  encryptedMessage: Uint8Array;
}

export interface SecondLevelEncryptionResponse {
  encryptedKey: SecondLevelSymmetricKey;
  encryptedMessage: Uint8Array;
}
