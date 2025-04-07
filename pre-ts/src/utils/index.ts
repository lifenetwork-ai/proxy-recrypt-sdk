export * from "./bytes";
export * from "./keypair";
import { BN254CurveWrapper, G2Point, GTElement } from "../crypto";
import { PublicKey, SecretKey } from "../types";
import { Fp, Fp12, Fp6, Fp2 } from "@noble/curves/abstract/tower";
import { Buffer } from "buffer";
import { IField } from "@noble/curves/abstract/modular";

export function secretToPubkey(
    secret: SecretKey,
    g: G2Point,
    Z: GTElement
): PublicKey {
    return new PublicKey(
        BN254CurveWrapper.gtPow(Z, secret.first),
        BN254CurveWrapper.g2ScalarMul(g, secret.second)
    );
}

export function g2FromBytes(bytes: Uint8Array): { x: Fp2; y: Fp2 } {
    if (bytes.length !== 128) {
        throw new Error("Invalid point encoding: expected 128 bytes");
    }

    // Check if the point is compressed and get the mask
    const mask = bytes[0] & (0b11 << 6); // Get top 3 bits
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

export function bytesToBigInt(bytes: Uint8Array): bigint {
    const hex = Array.from(bytes)
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

export function g1FromBytes(bytes: Uint8Array): { x: bigint; y: bigint } {
    // Check that the input has the correct size
    if (bytes.length !== G1_POINT_SIZE) {
        throw new Error(
            `Invalid G1 point size: expected ${G1_POINT_SIZE}, got ${bytes.length}`
        );
    }

    // Check the uncompressed flag in the first byte (optional, depending on your requirements)
    if ((bytes[0] & 0xff) !== 0x00) {
        throw new Error("Invalid G1 point: not in uncompressed format");
    }

    // Extract X coordinate from the first 32 bytes
    const x = bytesToBigInt(bytes.subarray(0, 32));

    // Extract Y coordinate from the second 32 bytes
    const y = bytesToBigInt(bytes.subarray(32, 64));

    return { x, y };
}

/**
 * Converts an Fp12 element to bytes in the order matching the Go implementation.
 * The result is a big-endian byte array.
 *
 * @param {Fp12} fp12Element - The Fp12 element to convert
 * @param {Object} Fp - The base field implementation with toBytes method
 * @returns {Uint8Array} - Byte representation in the same order as Go implementation
 */
export function fp12ToBytes(fp12Element: Fp12, Fp: IField<Fp>): Uint8Array {
    const { c0, c1 } = fp12Element;
    const bytesPerElement = Fp.BYTES;
    const result = new Uint8Array(12 * bytesPerElement);

    // Write in reverse order from Go's implementation (to match BigEndian)
    // z.C1.B2.A1 (highest memory address in Go)
    const c1b2a1 = Fp.toBytes(c1.c2.c1);
    result.set(c1b2a1, 0);

    // z.C1.B2.A0
    const c1b2a0 = Fp.toBytes(c1.c2.c0);
    result.set(c1b2a0, bytesPerElement);

    // z.C1.B1.A1
    const c1b1a1 = Fp.toBytes(c1.c1.c1);
    result.set(c1b1a1, 2 * bytesPerElement);

    // z.C1.B1.A0
    const c1b1a0 = Fp.toBytes(c1.c1.c0);
    result.set(c1b1a0, 3 * bytesPerElement);

    // z.C1.B0.A1
    const c1b0a1 = Fp.toBytes(c1.c0.c1);
    result.set(c1b0a1, 4 * bytesPerElement);

    // z.C1.B0.A0
    const c1b0a0 = Fp.toBytes(c1.c0.c0);
    result.set(c1b0a0, 5 * bytesPerElement);

    // z.C0.B2.A1
    const c0b2a1 = Fp.toBytes(c0.c2.c1);
    result.set(c0b2a1, 6 * bytesPerElement);

    // z.C0.B2.A0
    const c0b2a0 = Fp.toBytes(c0.c2.c0);
    result.set(c0b2a0, 7 * bytesPerElement);

    // z.C0.B1.A1
    const c0b1a1 = Fp.toBytes(c0.c1.c1);
    result.set(c0b1a1, 8 * bytesPerElement);

    // z.C0.B1.A0
    const c0b1a0 = Fp.toBytes(c0.c1.c0);
    result.set(c0b1a0, 9 * bytesPerElement);

    // z.C0.B0.A1
    const c0b0a1 = Fp.toBytes(c0.c0.c1);
    result.set(c0b0a1, 10 * bytesPerElement);

    // z.C0.B0.A0 (lowest memory address in Go)
    const c0b0a0 = Fp.toBytes(c0.c0.c0);
    result.set(c0b0a0, 11 * bytesPerElement);

    return result;
}

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
export function fp12FromBytes(
    bytes: Uint8Array,
    Fp: IField<Fp>,
    Fp2: IField<Fp2>,
    Fp6: IField<Fp6>,
    Fp12: IField<Fp12>
) {
    if (bytes.length !== 12 * Fp.BYTES) {
        throw new Error(
            `Invalid byte length: expected ${12 * Fp.BYTES}, got ${
                bytes.length
            }`
        );
    }

    const bytesPerElement = Fp.BYTES;

    // Parse in reverse order to match the Go implementation
    const c1b2a1 = Fp.fromBytes(bytes.slice(0, bytesPerElement));
    const c1b2a0 = Fp.fromBytes(
        bytes.slice(bytesPerElement, 2 * bytesPerElement)
    );
    const c1b1a1 = Fp.fromBytes(
        bytes.slice(2 * bytesPerElement, 3 * bytesPerElement)
    );
    const c1b1a0 = Fp.fromBytes(
        bytes.slice(3 * bytesPerElement, 4 * bytesPerElement)
    );
    const c1b0a1 = Fp.fromBytes(
        bytes.slice(4 * bytesPerElement, 5 * bytesPerElement)
    );
    const c1b0a0 = Fp.fromBytes(
        bytes.slice(5 * bytesPerElement, 6 * bytesPerElement)
    );
    const c0b2a1 = Fp.fromBytes(
        bytes.slice(6 * bytesPerElement, 7 * bytesPerElement)
    );
    const c0b2a0 = Fp.fromBytes(
        bytes.slice(7 * bytesPerElement, 8 * bytesPerElement)
    );
    const c0b1a1 = Fp.fromBytes(
        bytes.slice(8 * bytesPerElement, 9 * bytesPerElement)
    );
    const c0b1a0 = Fp.fromBytes(
        bytes.slice(9 * bytesPerElement, 10 * bytesPerElement)
    );
    const c0b0a1 = Fp.fromBytes(
        bytes.slice(10 * bytesPerElement, 11 * bytesPerElement)
    );
    const c0b0a0 = Fp.fromBytes(
        bytes.slice(11 * bytesPerElement, 12 * bytesPerElement)
    );

    // Construct the element
    return Fp12.create({
        c0: Fp6.create({
            c0: Fp2.create({ c0: c0b0a0, c1: c0b0a1 }),
            c1: Fp2.create({ c0: c0b1a0, c1: c0b1a1 }),
            c2: Fp2.create({ c0: c0b2a0, c1: c0b2a1 }),
        }),
        c1: Fp6.create({
            c0: Fp2.create({ c0: c1b0a0, c1: c1b0a1 }),
            c1: Fp2.create({ c0: c1b1a0, c1: c1b1a1 }),
            c2: Fp2.create({ c0: c1b2a0, c1: c1b2a1 }),
        }),
    });
}
