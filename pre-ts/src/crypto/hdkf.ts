import { stringToBytes } from "../utils";
import { BN254CurveWrapper, GTElement } from "./bn254";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";

// Default key size for symmetric encryption
const DEFAULT_KEY_SIZE = 32;

export async function generateRandomSymmetricKeyFromGT(
  keySize: number = DEFAULT_KEY_SIZE
): Promise<
  Required<{
    keyGT: GTElement;
    key: Uint8Array;
  }>
> {
  const randomGT = BN254CurveWrapper.generateRandomGTElement();
  const key = deriveKeyFromGT(randomGT, keySize);

  return { keyGT: randomGT, key };
}

export function deriveKeyFromGT(
  gtElement: GTElement,
  keySize: number = DEFAULT_KEY_SIZE
): Uint8Array {
  // Validate inputs
  if (![16, 24, 32].includes(keySize)) {
    throw new Error("Invalid key size: must be 16, 24, or 32 bytes");
  }

  // Get bytes from GT element
  const gtBytes = BN254CurveWrapper.GTToBytes(gtElement);
  if (!gtBytes.length) {
    throw new Error("Failed to get bytes from GT element");
  }

  // Use HKDF to derive the key with the updated Noble implementation
  const salt = stringToBytes("PRE_derive_key");
  const info = stringToBytes("PRE_symmetric_key");

  const derivedKey = hkdf(sha256, gtBytes, salt, info, keySize);

  return derivedKey;
}
