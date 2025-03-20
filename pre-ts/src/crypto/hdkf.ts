import { stringToBytes } from "../utils";
import { BN254CurveWrapper, GTElement } from "./bn254";
import { Crypto } from "@peculiar/webcrypto";
import hkdf from "js-crypto-hkdf";

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
  const key = await deriveKeyFromGT(randomGT, keySize);

  return { keyGT: randomGT, key };
}

export async function deriveKeyFromGT(
  gtElement: GTElement,
  keySize: number = DEFAULT_KEY_SIZE
): Promise<Uint8Array> {
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
  const buffer = await hkdf.compute(
    gtBytes, // input key material,
    "SHA-256", // hash function
    keySize, // required key length
    "PRE_symmetric_key", // info (context)
    stringToBytes("PRE_derive_key") // optional salt
  );

  return new Uint8Array(buffer.key);
}
