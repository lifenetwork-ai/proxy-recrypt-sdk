import { G2Point, GTElement } from "../crypto";
import { KeyPair, PublicKey, SecretKey } from "../types";
import { Fp, Fp12, Fp6, Fp2 } from "@noble/curves/abstract/tower";
export declare function secretToPubkey(secret: SecretKey, g: G2Point, Z: GTElement): PublicKey;
import { Buffer } from "buffer";
import { IField } from "@noble/curves/abstract/modular";
/**
 * Loads a keypair from a file
 * @param filename Path to the keypair file
 * @returns Promise resolving to the loaded KeyPair
 * @throws Error if file reading or parsing fails
 */
export declare function loadKeyPairFromFile(filename: string): Promise<KeyPair>;
export declare function loadReKeyFromFile(filename: string): Promise<G2Point>;
export declare function g2FromBytes(bytes: Uint8Array): {
    x: Fp2;
    y: Fp2;
};
export declare function bytesToBigInt(bytes: Uint8Array): bigint;
export declare function g2ToBytes(point: {
    x: Fp2;
    y: Fp2;
}): Uint8Array;
export declare function base64BufferToBigInt(buffer: Buffer): bigint;
/**
 * Converts a G1 point to its raw bytes representation
 * Following the Go implementation format
 */
export declare function g1ToBytes(point: {
    x: bigint;
    y: bigint;
}): Uint8Array;
/**
 * Converts an Fp12 element to bytes in the order matching the Go implementation.
 * The result is a big-endian byte array.
 *
 * @param {Fp12} fp12Element - The Fp12 element to convert
 * @param {Object} Fp - The base field implementation with toBytes method
 * @returns {Uint8Array} - Byte representation in the same order as Go implementation
 */
export declare function fp12ToBytes(fp12Element: Fp12, Fp: IField<Fp>): Uint8Array;
/**
 * Create a Fp12 element from bytes in the order matching the Go implementation.
 *
 * @param {Uint8Array} bytes - The bytes to convert
 * @param {Object} Fp - The base field implementation with fromBytes method
 * @param {Object} Fp2 - The quadratic extension field constructor
 * @param {Object} Fp6 - The sextic extension field constructor
 * @param {Object} Fp12 - The dodecic extension field constructor
 * @returns {Fp12} - The reconstructed Fp12 element
 */
export declare function fp12FromBytes(bytes: Uint8Array, Fp: IField<Fp>, Fp2: IField<Fp2>, Fp6: IField<Fp6>, Fp12: IField<Fp12>): Fp12;
