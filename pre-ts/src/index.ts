import { PreClient } from "./pre";
import {
  KeyPair,
  SecretKey,
  FirstLevelSymmetricKey,
  SecondLevelEncryptionResponse,
  parseFirstLevelSymmetricKey,
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

import { G2Point, GTElement, G1Point, BN254CurveWrapper } from "./crypto/bn254";
import { SecondLevelSymmetricKey } from "./types";

// Types for the PRE server interactions
export interface StoredData {
  reencryption_key: string; // Base64 encoded G2Affine point
  encrypted_key: {
    ephemeral_public_key: string;
    encrypted_key: string;
    nonce: string;
  };
  encrypted_data: Uint8Array;
}

export interface StoreRequest {
  reencryption_key: string; // Base64 encoded G2Point
  encrypted_key: {
    first: string; // Base64 encoded G1Point
    second: string; // Base64 encoded GTElement
  };
  encrypted_data: Array<number>;
  user_id: string;
}

export interface ProxyRequest {
  request_id: string;
}

export interface StoreResponse {
  status: string;
  id: string;
}

export interface RequestResponse {
  first_level_key: {
    first: GTElement; // Serialized GTElement
    second: GTElement; // Serialized GTElement
  };
  encrypted_data: Uint8Array;
}

export class ProxyClient {
  private baseUrl: string;

  constructor(baseUrl: string = "http://localhost:8080") {
    this.baseUrl = baseUrl;
  }

  /**
   * Store encrypted data and re-encryption key on the proxy server
   * @param reencryptionKey The re-encryption key (G2Point)
   * @param encryptedKey The encrypted symmetric key
   * @param encryptedData The encrypted data
   * @param userId The user ID
   * @returns Promise with the store response
   */
  async store(
    reencryptionKey: G2Point,
    encryptedKey: SecondLevelSymmetricKey,
    encryptedData: Uint8Array,
    userId: string
  ): Promise<StoreResponse> {
    // Use btoa for base64 encoding of byte arrays
    const request: StoreRequest = {
      reencryption_key: btoa(
        String.fromCharCode(...BN254CurveWrapper.G2ToBytes(reencryptionKey))
      ),
      encrypted_key: {
        first: btoa(
          String.fromCharCode(
            ...BN254CurveWrapper.G1ToBytes(encryptedKey.first)
          )
        ),
        second: btoa(
          String.fromCharCode(
            ...BN254CurveWrapper.GTToBytes(encryptedKey.second)
          )
        ),
      },
      encrypted_data: Array.from(encryptedData),
      user_id: userId,
    };

    const response = await fetch(`${this.baseUrl}/store`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store request failed: ${error.error}`);
    }

    return response.json();
  }

  /**
   * Request re-encrypted data from the proxy server
   * @param requestId The ID of the data to re-encrypt
   * @returns Promise with the re-encrypted data and first level key
   */
  async request(requestId: string): Promise<{
    firstLevelKey: FirstLevelSymmetricKey;
    encryptedData: Uint8Array;
  }> {
    const response = await fetch(`${this.baseUrl}/request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ request_id: requestId }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Request failed: ${error.error}`);
    }

    const result: RequestResponse = await response.json();
    // Convert the serialized response back to the proper types
    return {
      firstLevelKey: parseFirstLevelSymmetricKey(result.first_level_key),
      encryptedData: result.encrypted_data,
    };
  }

  /**
   * Helper method to convert Uint8Array to Base64 string
   */
  static toBase64(data: Uint8Array): string {
    return btoa(String.fromCharCode(...data));
  }

  /**
   * Helper method to convert Base64 string to Uint8Array
   */
  static fromBase64(base64: string): Uint8Array {
    return new Uint8Array([...atob(base64)].map((c) => c.charCodeAt(0)));
  }
}

// Example usage:
/*
const client = new ProxyClient();

// Assuming you have these values from your PRE operations:
const reencryptionKey: G2Point = ...;
const encryptedKey: SecondLevelSymmetricKey = {
  first: ..., // G1Point
  second: ..., // GTElement
};
const encryptedData = new Uint8Array([...]); // Your encrypted data
const userId = "user123";

try {
  const storeResult = await client.store(
    reencryptionKey,
    encryptedKey,
    encryptedData,
    userId
  );
  console.log('Store successful:', storeResult);

  // Request re-encrypted data
  const { firstLevelKey, encryptedData } = await client.request(storeResult.id);
  console.log('Re-encryption successful');
  
  // firstLevelKey is now a FirstLevelSymmetricKey object that can be used
  // to decrypt the encryptedData
} catch (error) {
  console.error('Error:', error);
}
*/

export type {
  KeyPair,
  PublicKey,
  FirstLevelSymmetricKey,
  SecondLevelSymmetricKey,
  FirstLevelEncryptionResponse,
  SecondLevelEncryptionResponse,
} from "./types";

export * from "./crypto";

export * from "./shamir";

export * from "./utils";
