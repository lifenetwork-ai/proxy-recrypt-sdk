import { BN254CurveWrapper, G2Point, GTElement } from "../crypto/bn254";
import { bytesToHex, hexToBytes } from "../utils";

export interface KeyPair {
  secretKey: SecretKey;
  publicKey: PublicKey;
}

export class SecretKey {
  first: bigint; // First component of secret key
  second: bigint; // Second component of secret key

  constructor(first: bigint, second: bigint) {
    this.first = first;
    this.second = second;
  }

  toBytes(): Uint8Array {
    // Convert bigints to hex strings
    const firstHex = this.first.toString(16).padStart(64, "0");
    const secondHex = this.second.toString(16).padStart(64, "0");

    // Convert combined hex string to Uint8Array
    return hexToBytes(firstHex + secondHex);
  }

  static fromBytes(bytes: Uint8Array): SecretKey {
    const hex = bytesToHex(bytes);
    return new SecretKey(
      BigInt("0x" + hex.slice(0, 64)),
      BigInt("0x" + hex.slice(64, 128))
    );
  }
}

export class PublicKey {
  first: GTElement; // Element in GT group
  second: G2Point; // Point in G2 group

  // These are just signatures (declarations without implementation)
  constructor(params: { first: GTElement; second: G2Point });
  constructor(first: GTElement, second: G2Point);

  constructor(
    firstOrParams: GTElement | { first: GTElement; second: G2Point },
    secondParam?: G2Point
  ) {
    if (
      firstOrParams &&
      typeof firstOrParams === "object" &&
      "first" in firstOrParams
    ) {
      // Object parameter overload
      this.first = firstOrParams.first;
      this.second = firstOrParams.second;
    } else {
      // Individual parameters overload
      this.first = firstOrParams as GTElement;
      this.second = secondParam as G2Point;
    }
  }

  toBytes(): Uint8Array {
    // Convert GTElement to bytes
    const firstBytes = BN254CurveWrapper.GTToBytes(this.first);
    // Convert G2Point to bytes
    const secondBytes = BN254CurveWrapper.G2ToBytes(this.second);

    // Concatenate the two byte arrays
    return new Uint8Array([...firstBytes, ...secondBytes]);
  }

  static fromBytes(pubkeyBytes: Uint8Array): PublicKey {
    // Convert bytes back to GTElement and G2Point
    const first = BN254CurveWrapper.GTFromBytes(pubkeyBytes.slice(0, 384));
    const second = BN254CurveWrapper.G2FromBytes(pubkeyBytes.slice(384, 512));
    return new PublicKey(first, second);
  }
}
