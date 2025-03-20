import { G1Point, G2Point, GTElement } from "./crypto/bn254";
export interface KeyPair {
    secretKey: SecretKey;
    publicKey: PublicKey;
}
export declare class SecretKey {
    first: bigint;
    second: bigint;
    constructor(first: bigint, second: bigint);
    toBytes(): Uint8Array;
    static fromBytes(bytes: Uint8Array): SecretKey;
}
export interface PublicKey {
    first: GTElement;
    second: G2Point;
}
export interface FirstLevelSymmetricKey {
    first: GTElement;
    second: GTElement;
}
export interface SecondLevelSymmetricKey {
    first: G1Point;
    second: GTElement;
}
export interface FirstLevelEncryptionResponse {
    encryptedKey: FirstLevelSymmetricKey;
    encryptedMessage: Uint8Array;
}
export interface SecondLevelEncryptionResponse {
    encryptedKey: SecondLevelSymmetricKey;
    encryptedMessage: Uint8Array;
}
