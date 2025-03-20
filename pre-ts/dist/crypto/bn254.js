// Core types from the library
import { bn254 } from "@noble/curves/bn254";
import { bytesToBigInt, fp12FromBytes, fp12ToBytes, g1ToBytes, g2FromBytes, g2ToBytes, } from "../utils";
// Example implementation showing the types
export class BN254CurveWrapper {
    // Generator element in G1 group
    static G1Generator() {
        return bn254.G1.ProjectivePoint.BASE;
    }
    // Generator element in G2 group
    static G2Generator() {
        return bn254.G2.ProjectivePoint.BASE;
    }
    // Generator element in GT(Fp12) group
    static GTBase() {
        return bn254.fields.Fp12.ONE;
    }
    // Generate a random GT element
    static generateRandomGTElement() {
        const randomBytes = new Uint8Array(32); // 256 bits
        crypto.getRandomValues(randomBytes);
        const randomScalar = bytesToBigInt(randomBytes);
        return bn254.fields.Fp12.mul(bn254.fields.Fp12.ONE, randomScalar);
    }
    // Perform pairing e(P,Q) -> GT
    static pairing(P, Q) {
        return bn254.pairing(P, Q);
    }
    // G1 point operations
    static g1ScalarMul(P, scalar) {
        return P.multiply(scalar);
    }
    // G2 point operations
    static g2ScalarMul(Q, scalar) {
        return Q.multiply(scalar);
    }
    // GT element operations
    static gtPow(a, b) {
        return bn254.fields.Fp12.pow(a, b);
    }
    static gtMul(a, b) {
        return bn254.fields.Fp12.mul(a, b);
    }
    static gtDiv(a, b) {
        return bn254.fields.Fp12.div(a, b);
    }
    static G1ToBytes(P) {
        return g1ToBytes(P);
    }
    static G2ToBytes(Q) {
        return g2ToBytes(Q);
    }
    static G2FromBytes(bytes) {
        let a = g2FromBytes(bytes);
        let c = bn254.G2.ProjectivePoint;
        return c.fromAffine(a);
    }
    static GTToBytes(e) {
        return fp12ToBytes(e, bn254.fields.Fp);
    }
    static GTFromBytes(bytes) {
        return fp12FromBytes(bytes, bn254.fields.Fp, bn254.fields.Fp2, bn254.fields.Fp6, bn254.fields.Fp12);
    }
}
