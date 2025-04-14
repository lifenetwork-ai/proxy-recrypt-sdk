import { BN254CurveWrapper, G1Point, GTElement } from "../crypto";

// Cipher text structures
export interface FirstLevelSymmetricKey {
  first: GTElement; // First component in GT group
  second: GTElement; // Second component in GT group
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

// /* eslint-disable @typescript-eslint/no-explicit-any */
// function parseFirstLevelSymmetricKey(data: any): FirstLevelSymmetricKey {
//   // Function to convert B0/B1/B2 to c0/c1/c2 and A0/A1 to c0/c1
//   // Also converts string values to bigint
//   const processThirdLevel = (element: any) => {
//     const result: any = {};

//     // Map B0/B1/B2 fields to c0/c1/c2 and convert to bigint
//     if (element.B0)
//       result.c0 = {
//         c0: BigInt(element.B0.A0),
//         c1: BigInt(element.B0.A1),
//       };

//     if (element.B1)
//       result.c1 = {
//         c0: BigInt(element.B1.A0),
//         c1: BigInt(element.B1.A1),
//       };

//     if (element.B2)
//       result.c2 = {
//         c0: BigInt(element.B2.A0),
//         c1: BigInt(element.B2.A1),
//       };

//     return result;
//   };

//   // Process each level
//   const result: FirstLevelSymmetricKey = {
//     first: {
//       c0: processThirdLevel(data.first.c0 || data.first.C0),
//       c1: processThirdLevel(data.first.c1 || data.first.C1),
//     },
//     second: {
//       c0: processThirdLevel(data.second.c0 || data.second.C0),
//       c1: processThirdLevel(data.second.c1 || data.second.C1),
//     },
//   };

//   return result;
// }
