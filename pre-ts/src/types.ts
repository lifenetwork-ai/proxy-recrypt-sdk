import { G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bytesToHex, hexToBytes } from "./utils";

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

export interface PublicKey {
  first: GTElement; // Element in GT group
  second: G2Point; // Point in G2 group
}

// Cipher text structures
export interface FirstLevelSymmetricKey {
  first: GTElement; // First component in GT group
  second: GTElement; // Second component in GT group
}

export interface SecondLevelSymmetricKey {
  first: G1Point; // First component in G1 group
  second: GTElement; // Second component in GT group
}

export interface FirstLevelEncryptionResponse {
  encryptedKey: FirstLevelSymmetricKey;
  encryptedMessage: Uint8Array;
}

export interface SecondLevelEncryptionResponse {
  encryptedKey: SecondLevelSymmetricKey;
  encryptedMessage: Uint8Array;
}
