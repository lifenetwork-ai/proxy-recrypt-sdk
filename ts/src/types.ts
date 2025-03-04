import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { G1Point, G2Point, GTElement } from "./crypto/bn254";

export interface KeyPair {
  secretKey: SecretKey;
  publicKey: PublicKey;
}

export interface SecretKey {
  first: bigint; // First component of secret key
  second: bigint; // Second component of secret key
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
