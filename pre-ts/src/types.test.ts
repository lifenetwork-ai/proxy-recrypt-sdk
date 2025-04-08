// export class SecondLevelSymmetricKey {
//     first: G1Point; // First component in G1 group
//     second: GTElement; // Second component in GT group
import { describe, test, expect } from "@jest/globals";
import { BN254CurveWrapper } from "./crypto";
import { SecondLevelSymmetricKey } from "./types";

//     constructor(first: G1Point, second: GTElement) {
//         this.first = first;
//         this.second = second;
//     }

//     toBytes(): Uint8Array {
//         // Convert G1Point to bytes
//         const firstBytes = BN254CurveWrapper.G1ToBytes(this.first);
//         // Convert GTElement to bytes
//         const secondBytes = BN254CurveWrapper.GTToBytes(this.second);

//         // Concatenate the two byte arrays
//         return new Uint8Array([...firstBytes, ...secondBytes]);
//     }

//     static fromBytes(keyBytes: Uint8Array): SecondLevelSymmetricKey {
//         if (keyBytes.length !== 448) {
//             throw new Error(
//                 `Invalid byte length for SecondLevelSymmetricKey: expected 448, got ${keyBytes.length}`
//             );
//         }
//         // Convert bytes back to G1Point and GTElement
//         const first = BN254CurveWrapper.G1FromBytes(keyBytes.slice(0, 64));
//         const second = BN254CurveWrapper.GTFromBytes(keyBytes.slice(64, 448));
//         return new SecondLevelSymmetricKey(first, second);
//     }
// }

describe("test SecondLevelSymmetricKey", () => {
  test("toBytes and fromBytes should work correctly", () => {
    const first = BN254CurveWrapper.G1Generator();
    const second = BN254CurveWrapper.GTBase();
    const key = new SecondLevelSymmetricKey(first, second);

    const bytes = key.toBytes();
    const newKey = SecondLevelSymmetricKey.fromBytes(bytes);

    expect(newKey.first).toEqual(first);
    expect(newKey.second).toEqual(second);
  });
});
