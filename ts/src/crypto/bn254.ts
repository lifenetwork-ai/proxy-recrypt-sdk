// Core types from the library
import { bn254 } from "@noble/curves/bn254";
import { Fp, Fp12, Fp12Bls, Fp2 } from "@noble/curves/abstract/tower";
import random from "crypto-random-bigint";
import {
  AffinePoint,
  ProjConstructor,
  ProjPointType,
  weierstrassPoints,
} from "@noble/curves/abstract/weierstrass";
import * as bigintModArith from "bigint-mod-arith";
import { g1ToBytes, g2FromBytes, g2ToBytes } from "../utils";

// G1 is a point on the base field (Fp)
export type G1Point = ProjPointType<Fp>;
// G2 is a point on the extension field (Fp2)
export type G2Point = ProjPointType<Fp2>;
// GT is an element in Fp12 (target group from pairing)
export type GTElement = Fp12;

// Example implementation showing the types
export class BN254CurveWrapper {
  // Generators
  static G1Generator(): G1Point {
    return bn254.G1.ProjectivePoint.BASE;
  }

  static G2Generator(): G2Point {
    return bn254.G2.ProjectivePoint.BASE;
  }

  // Generate a new element in GT
  static GTBase(): GTElement {
    return bn254.fields.Fp12.ONE;
  }

  // Generate a random GT element
  static generateRandomGTElement(): GTElement {
    const randomScalar = random(32);
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

  static G2FromBytes(bytes: Uint8Array): G2Point {
    let a = g2FromBytes(bytes);
    let c: ProjConstructor<Fp2> = bn254.G2.ProjectivePoint;
    return c.fromAffine(a);
  }

  static GTToBytes(e: GTElement): Uint8Array {
    return bn254.fields.Fp12.toBytes(e);
  }

  static GTFromBytes(bytes: Uint8Array): GTElement {
    const Fp6 = bn254.fields.Fp6;
    return {
      c0: Fp6.fromBytes(bytes.subarray(0, Fp6.BYTES)),
      c1: Fp6.fromBytes(bytes.subarray(Fp6.BYTES)),
    };
  }
}
