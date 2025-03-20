import { PreClient } from "./pre";
import {
  KeyPair,
  SecretKey,
  FirstLevelSymmetricKey,
  SecondLevelEncryptionResponse,
} from "./types";

import { generateRandomSymmetricKeyFromGT } from "./crypto";
import { combineSecret, splitSecret } from "./shamir";
import { generateRandomScalar } from "./utils/keypair";
export interface IPreClient {
  // Generate a random secret key, then split it into n shares
  generateKeys(): Promise<Array<Uint8Array>>;
  encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse>;
  decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array>;
  storeShare(): void;
}

export class PreSdk implements IPreClient {
  preClient: PreClient;

  constructor() {
    this.preClient = new PreClient();
  }

  generateRandomKeyPair(): KeyPair {
    console.log("Generating key pair in PreSdk...");
    const keyPair = this.preClient.generateRandomKeyPair();
    console.log("Key pair generated:", keyPair);
    return keyPair;
  }

  async generateKeys(): Promise<Array<Uint8Array>> {
    console.log("Generating keys in PreSdk...");
    const secretKey = this.preClient.generateRandomKeyPair().secretKey;
    const bytes = secretKey.toBytes();
    const shares = await splitSecret(bytes, 2, 3);
    return shares;
  }

  async encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse> {
    console.log("Encrypting data in PreSdk...");
    const randomScalar = generateRandomScalar();
    const encryptedData = await this.preClient.secondLevelEncryption(
      secret,
      data,
      randomScalar
    );
    return encryptedData;
  }

  async decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array> {
    console.log("Decrypting data in PreSdk...");
    const decryptedData = await this.preClient.decryptFirstLevel(
      {
        encryptedKey,
        encryptedMessage: encryptedData,
      },
      secret
    );
    console.log("Data decrypted:", decryptedData);
    return decryptedData;
  }

  storeShare(): void {
    console.log("Storing share in PreSdk...");
    // super.storeShare();
    console.log("Share stored.");
  }
}

export type{
  KeyPair,
  PublicKey,
  FirstLevelSymmetricKey,
  SecondLevelSymmetricKey,
  FirstLevelEncryptionResponse,
  SecondLevelEncryptionResponse,
} from "./types"

export * from "./crypto";

export * from "./shamir";

export * from "./utils";
