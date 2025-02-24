import { BN254CurveWrapper, G2Point, GTElement } from "./crypto";
import { KeyPair, PublicKey, SecretKey } from "./types";
import { Fp12, Fp2 } from "@noble/curves/abstract/tower";
import { IField } from "@noble/curves/abstract/modular";
export function secretToPubkey(
  secret: SecretKey,
  g: G2Point,
  Z: GTElement
): PublicKey {
  return {
    first: BN254CurveWrapper.gtPow(Z, secret.first),
    second: BN254CurveWrapper.g2ScalarMul(g, secret.second),
  };
}

import fs from "fs/promises";
import { Buffer } from "buffer";
// Interface for JSON serialization/deserialization
interface SerializableKeyPair {
  PublicKey: {
    First: string; // base64 encoded GT element
    Second: string; // base64 encoded G2 point
  };
  SecretKey: {
    First: string; // hex encoded bigint
    Second: string; // hex encoded bigint
  };
}
/**
 * Loads a keypair from a file
 * @param filename Path to the keypair file
 * @returns Promise resolving to the loaded KeyPair
 * @throws Error if file reading or parsing fails
 */
export async function loadKeyPairFromFile(filename: string): Promise<KeyPair> {
  // Read file
  let jsonData: Buffer;
  try {
    jsonData = await fs.readFile(filename);
  } catch (err) {
    throw new Error(`Failed to read keypair file: ${err}`);
  }

  // Parse JSON
  let serializable: SerializableKeyPair;
  try {
    serializable = JSON.parse(jsonData.toString());
  } catch (err) {
    throw new Error(`Failed to unmarshal keypair: ${err}`);
  }

  // Reconstruct KeyPair
  const keyPair: KeyPair = {
    publicKey: {
      first: BN254CurveWrapper.GTFromBytes(
        Buffer.from(serializable.PublicKey.First, "base64")
      ),
      second: BN254CurveWrapper.G2FromBytes(
        Buffer.from(serializable.PublicKey.Second, "base64")
      ),
    },
    secretKey: {
      first: BigInt(`0x${serializable.SecretKey.First}`),
      second: BigInt(`0x${serializable.SecretKey.Second}`),
    },
  };

  return keyPair;
}

export async function loadReKeyFromFile(filename: string): Promise<G2Point> {
  // Read file
  try {
    let jsonData = await fs.readFile(filename, "utf8");
    return BN254CurveWrapper.G2FromBytes(Buffer.from(jsonData, "base64"));
  } catch (err) {
    throw new Error(`Failed to read rekey file: ${err}`);
  }
}

export function g2FromBytes(bytes: Uint8Array): { x: Fp2; y: Fp2 } {
  if (bytes.length !== 128) {
    throw new Error("Invalid point encoding: expected 128 bytes");
  }

  // Check if the point is compressed and get the mask
  const mask = bytes[0] & 0b11100000; // Get top 3 bits
  if (mask !== 0x00) {
    // mUncompressed in Go code
    throw new Error("Invalid point encoding: expected uncompressed format");
  }

  // Extract x coordinate (X.A1 | X.A0)
  const x1 = bytesToBigInt(bytes.slice(0, 32)); // X.A1 comes first
  const x0 = bytesToBigInt(bytes.slice(32, 64)); // Then X.A0
  const x = { c0: x0, c1: x1 };

  // Extract y coordinate (Y.A1 | Y.A0)
  const y1 = bytesToBigInt(bytes.slice(64, 96)); // Y.A1 comes first
  const y0 = bytesToBigInt(bytes.slice(96, 128)); // Then Y.A0
  const y = { c0: y0, c1: y1 };

  // Check for infinity point
  if (x.c0 === 0n && x.c1 === 0n && y.c0 === 0n && y.c1 === 0n) {
    // Handle infinity point case if needed
    throw new Error("Infinity point not supported");
  }

  return { x, y };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return BigInt("0x" + hex);
}
export function g2ToBytes(point: { x: Fp2; y: Fp2 }): Uint8Array {
  // Create a buffer of 128 bytes
  const res = new Uint8Array(128);

  // Check if point is infinity (all coordinates are zero)
  if (
    point.x.c0 === 0n &&
    point.x.c1 === 0n &&
    point.y.c0 === 0n &&
    point.y.c1 === 0n
  ) {
    res[0] = 0x00; // Updated mask value
    return res;
  }

  // Convert coordinates to bytes and place them in the correct order
  // X coordinates: X.A1 | X.A0
  bigIntToBytes(point.x.c1, res.subarray(0, 32)); // X.A1
  bigIntToBytes(point.x.c0, res.subarray(32, 64)); // X.A0

  // Y coordinates: Y.A1 | Y.A0
  bigIntToBytes(point.y.c1, res.subarray(64, 96)); // Y.A1
  bigIntToBytes(point.y.c0, res.subarray(96, 128)); // Y.A0

  // Set the uncompressed flag in the most significant byte
  res[0] |= 0x00; // Updated mask value to match expected output

  return res;
}

function bigIntToBytes(value: bigint, target: Uint8Array): void {
  let tempValue = value;
  for (let i = target.length - 1; i >= 0; i--) {
    target[i] = Number(tempValue & 0xffn);
    tempValue >>= 8n;
  }
}

export function base64BufferToBigInt(buffer: Buffer): bigint {
  // Buffer contains base64 string, so first convert to string
  const base64Str = buffer.toString("utf8");

  // Decode base64 to bytes
  const bytes = Buffer.from(base64Str, "base64");

  // Convert bytes to BigInt
  return BigInt("0x" + bytes.toString("hex"));
}

// Constants
const G1_POINT_SIZE = 64; // Size in bytes for uncompressed G1 point

/**
 * Converts a G1 point to its raw bytes representation
 * Following the Go implementation format
 */

export function g1ToBytes(point: { x: bigint; y: bigint }): Uint8Array {
  // Allocate buffer for uncompressed point
  const result = new Uint8Array(G1_POINT_SIZE);

  // Store Y coordinate in the second 32 bytes
  bigIntToBytes(point.y, result.subarray(32, 64));

  // Store X coordinate in the first 32 bytes
  bigIntToBytes(point.x, result.subarray(0, 32));

  // Set the uncompressed flag in the first byte
  result[0] |= 0x00;

  return result;
}
