import { PreClient } from "./pre";
import { KeyPair, SecretKey, FirstLevelSymmetricKey, SecondLevelEncryptionResponse } from "./types";
export interface IPreClient {
    generateKeys(): Promise<Array<Uint8Array>>;
    encryptData(secret: SecretKey, data: Uint8Array): Promise<SecondLevelEncryptionResponse>;
    decryptData(encryptedKey: FirstLevelSymmetricKey, encryptedData: Uint8Array, secret: SecretKey): Promise<Uint8Array>;
    storeShare(): void;
}
export declare class PreSdk implements IPreClient {
    preClient: PreClient;
    constructor();
    generateRandomKeyPair(): KeyPair;
    generateKeys(): Promise<Array<Uint8Array>>;
    encryptData(secret: SecretKey, data: Uint8Array): Promise<SecondLevelEncryptionResponse>;
    decryptData(encryptedKey: FirstLevelSymmetricKey, encryptedData: Uint8Array, secret: SecretKey): Promise<Uint8Array>;
    storeShare(): void;
}
export type { KeyPair, PublicKey, FirstLevelSymmetricKey, SecondLevelSymmetricKey, FirstLevelEncryptionResponse, SecondLevelEncryptionResponse, } from "./types";
export * from "./crypto";
export * from "./shamir";
export * from "./utils";
