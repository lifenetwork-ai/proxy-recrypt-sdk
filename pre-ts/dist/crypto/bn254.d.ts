import { Fp, Fp12, Fp2 } from "@noble/curves/abstract/tower";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
export type G1Point = ProjPointType<Fp>;
export type G2Point = ProjPointType<Fp2>;
export type GTElement = Fp12;
export declare class BN254CurveWrapper {
    static G1Generator(): G1Point;
    static G2Generator(): G2Point;
    static GTBase(): GTElement;
    static generateRandomGTElement(): GTElement;
    static pairing(P: G1Point, Q: G2Point): GTElement;
    static g1ScalarMul(P: G1Point, scalar: bigint): G1Point;
    static g2ScalarMul(Q: G2Point, scalar: bigint): G2Point;
    static gtPow(a: GTElement, b: bigint): GTElement;
    static gtMul(a: GTElement, b: GTElement | bigint): GTElement;
    static gtDiv(a: GTElement, b: GTElement): GTElement;
    static G1ToBytes(P: G1Point): Uint8Array;
    static G2ToBytes(Q: G2Point): Uint8Array;
    static G2FromBytes(bytes: Uint8Array): G2Point;
    static GTToBytes(e: GTElement): Uint8Array;
    static GTFromBytes(bytes: Uint8Array): GTElement;
}
