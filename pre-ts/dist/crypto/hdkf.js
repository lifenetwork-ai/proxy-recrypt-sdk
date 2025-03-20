import { BN254CurveWrapper } from "./bn254";
import * as crypto from "crypto";
// Default key size for symmetric encryption
const DEFAULT_KEY_SIZE = 32;
export function generateRandomSymmetricKeyFromGT(keySize = DEFAULT_KEY_SIZE) {
    const randomGT = BN254CurveWrapper.generateRandomGTElement();
    const key = deriveKeyFromGT(randomGT, keySize);
    return { keyGT: randomGT, key };
}
export function deriveKeyFromGT(gtElement, keySize = DEFAULT_KEY_SIZE) {
    // Validate inputs
    if (![16, 24, 32].includes(keySize)) {
        throw new Error("Invalid key size: must be 16, 24, or 32 bytes");
    }
    // Get bytes from GT element
    const gtBytes = BN254CurveWrapper.GTToBytes(gtElement);
    if (!gtBytes.length) {
        throw new Error("Failed to get bytes from GT element");
    }
    // Use HKDF to derive the key
    const buffer = crypto.hkdfSync("sha256", // hash function
    gtBytes, // input key material
    Buffer.from("PRE_derive_key"), // optional salt
    Buffer.from("PRE_symmetric_key"), // info (context)
    keySize // required key length
    );
    return new Uint8Array(buffer);
}
