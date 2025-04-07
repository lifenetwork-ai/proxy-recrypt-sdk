import { bn254 } from "@noble/curves/bn254";
import { Fp, Fp12, Fp2 } from "@noble/curves/abstract/tower";
import {
    ProjConstructor,
    ProjPointType,
} from "@noble/curves/abstract/weierstrass";
import {
    bytesToBigInt,
    fp12FromBytes,
    fp12ToBytes,
    g1FromBytes,
    g1ToBytes,
    g2FromBytes,
    g2ToBytes,
} from "../utils";

// G1 is a point on the base field (Fp)
export type G1Point = ProjPointType<Fp>;
// G2 is a point on the extension field (Fp2)
export type G2Point = ProjPointType<Fp2>;
// GT is an element in Fp12 (target group from pairing)
export type GTElement = Fp12;

// Example implementation showing the types
export class BN254CurveWrapper {
    // Generator element in G1 group
    static G1Generator(): G1Point {
        return bn254.G1.ProjectivePoint.BASE;
    }

    // Generator element in G2 group
    static G2Generator(): G2Point {
        return bn254.G2.ProjectivePoint.BASE;
    }

    // Generator element in GT(Fp12) group
    static GTBase(): GTElement {
        return bn254.fields.Fp12.ONE;
    }

    // Generate a random GT element
    static generateRandomGTElement(): GTElement {
        const randomBytes = new Uint8Array(32); // 256 bits

        crypto.getRandomValues(randomBytes);
        const randomScalar = bytesToBigInt(randomBytes);

        return bn254.fields.Fp12.mul(bn254.fields.Fp12.ONE, randomScalar);
    }

    // Perform pairing e(P,Q) -> GT
    static pairing(P: G1Point, Q: G2Point): GTElement {
        return bn254.pairing(P, Q);
    }

    // G1 point operations
    static g1ScalarMul(P: G1Point, scalar: bigint): G1Point {
        return P.multiply(scalar);
    }

    // G2 point operations
    static g2ScalarMul(Q: G2Point, scalar: bigint): G2Point {
        return Q.multiply(scalar);
    }

    // GT element operations
    static gtPow(a: GTElement, b: bigint): GTElement {
        return bn254.fields.Fp12.pow(a, b);
    }

    static gtMul(a: GTElement, b: GTElement | bigint): GTElement {
        return bn254.fields.Fp12.mul(a, b);
    }

    static gtDiv(a: GTElement, b: GTElement): GTElement {
        return bn254.fields.Fp12.div(a, b);
    }

    static G1ToBytes(P: G1Point): Uint8Array {
        return g1ToBytes(P);
    }

    static G2ToBytes(Q: G2Point): Uint8Array {
        return g2ToBytes(Q);
    }

    static G1FromBytes(bytes: Uint8Array): G1Point {
        const a = g1FromBytes(bytes);
        const c: ProjConstructor<Fp> = bn254.G1.ProjectivePoint;
        return c.fromAffine(a);
    }

    static G2FromBytes(bytes: Uint8Array): G2Point {
        const a = g2FromBytes(bytes);
        const c: ProjConstructor<Fp2> = bn254.G2.ProjectivePoint;
        return c.fromAffine(a);
    }

    static GTToBytes(e: GTElement): Uint8Array {
        return fp12ToBytes(e, bn254.fields.Fp);
    }

    static GTFromBytes(bytes: Uint8Array): GTElement {
        return fp12FromBytes(
            bytes,
            bn254.fields.Fp,
            bn254.fields.Fp2,
            bn254.fields.Fp6,
            bn254.fields.Fp12
        );
    }
}
