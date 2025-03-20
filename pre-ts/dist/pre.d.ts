import { SecretKey, PublicKey, FirstLevelEncryptionResponse, SecondLevelEncryptionResponse, SecondLevelSymmetricKey, FirstLevelSymmetricKey, KeyPair } from "./types";
import { G1Point, G2Point, GTElement } from "./crypto/bn254";
export declare class PreClient {
    G1: G1Point;
    G2: G2Point;
    Z: GTElement;
    constructor();
    generateReEncryptionKey(secretA: bigint, publicB: G2Point): G2Point;
    secondLevelEncryption(secretA: SecretKey, message: Uint8Array, scalar: bigint, keyGT?: GTElement, key?: Uint8Array, nonce?: Uint8Array): Promise<SecondLevelEncryptionResponse>;
    secretToPubkey(secret: SecretKey): PublicKey;
    decryptFirstLevel(payload: FirstLevelEncryptionResponse, secretKey: SecretKey): Promise<Uint8Array>;
    decryptFirstLevelKey(encryptedKey: FirstLevelSymmetricKey, secretKey: SecretKey): Uint8Array;
    decryptSecondLevel(encryptedKey: SecondLevelSymmetricKey, encryptedMessage: Uint8Array, secretKey: SecretKey): Promise<Uint8Array>;
    decryptSecondLevelKey(encryptedKey: SecondLevelSymmetricKey, secretKey: SecretKey): Uint8Array;
    generateRandomKeyPair(): KeyPair;
}
