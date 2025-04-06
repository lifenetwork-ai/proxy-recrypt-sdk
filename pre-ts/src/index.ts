import { PreClient } from "./pre";
import {
  KeyPair,
  SecretKey,
  FirstLevelSymmetricKey,
  SecondLevelEncryptionResponse,
  parseFirstLevelSymmetricKey,
  PublicKey,
} from "./types";

import { splitSecret } from "./shamir";
import { generateRandomScalar } from "./utils/keypair";
import { G2Point, GTElement, BN254CurveWrapper } from "./crypto/bn254";
import { SecondLevelSymmetricKey } from "./types";

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

export interface StoreShareRequest {
  shared_key: string; // Base64 encoded share
  public_key: string; // Base64 encoded public key
}

export interface GetShareResponse {
  data: {
    shared_key: string; // Base64 encoded share
    updated_at: string; // Timestamp of the last update
  }
}

export interface UploadFileRequest {
  file_content: string; // Base64 encoded file content
  file_type: string; // MIME type of the file
  file_name: string; // Name of the file
  file_size: number; // Size of the file in bytes
}

export interface UploadFileResponse {
  data: {
    errors: Array<string>;
    id: string;
    message: string;
    mime_type: string;
    name: string;
    size: number;
    status_code: number;
  };
}

// {
//   "id": "5dd48e38-5f90-445f-abdb-1eb61c1c7e16",
//   "name": "file",
//   "size": 58465,
//   "mime_type": "application/octet-stream",
//   "object_url": "https://storage.googleapis.com/human-network-storage-testnet/e2c7b9b8aa5e419389a25c7c605cebe7-file?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=life-ai-dev-deployment%40lifeai-438107.iam.gserviceaccount.com%2F20250403%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20250403T075128Z&X-Goog-Expires=899&X-Goog-Signature=4f996a3be327e64e138704ad8b80f4d51a1731b801cbc11b6a2473fbbf941ba23558d05f9ea3e82780aaf6213f490e1d20a611a98fc3d524025f63c8a14cabfbb0bdea9ed22a8e3f909f06c4109ac66146de7de8ea91ff22751e05301bd4534e7bc615684a3a0e3d077ca7e0d677495eb8dc4db84050a448f50cf6f56c9a653fe0d8da737d13b5c72a59a878b5c31394421080de48accca4db12c37a604e54983f0be7e7392e8bea174c7232673b61cf490c774715ba97952af7cc4cba08951fa0133bb55bc3d1977528d92b3e1ff6911bf911fdde8e6d6313508ed3890459740361e39d64b5d2d35c42431513ba6318a296255fa7ba6725e7d6fcf1651664e7&X-Goog-SignedHeaders=host",
//   "owner_id": "b1e6e3f1-78da-4e63-991b-44b069988c7a",
//   "crypto_info": {
//       "id": "5dd48e38-5f90-445f-abdb-1eb61c1c7e16",
//       "type": "",
//       "algorithm": "",
//       "timestamp": "0001-01-01T00:00:00Z",
//       "capsule": "",
//       "metadata": "",
//       "created_at": "2025-04-03T07:51:14Z",
//       "updated_at": "2025-04-03T07:51:14Z"
//   },
//   "created_at": "2025-04-03T07:51:14Z",
//   "updated_at": "2025-04-03T07:51:14Z"
// }

export interface GetStoredFileResponse {
    id: string;
    name: string;
    size: number;
    mime_type: string;
    object_url: string;
    // owner_id: string;
    // crypto_info: {
    //   id: string;
    //   type: string;
    //   algorithm: string;
    //   timestamp: string;
    //   capsule: string;
    //   metadata: string;
    //   created_at: string;
    //   updated_at: string;
    // };
    created_at: string;
    updated_at: string;
}

export class ProxyClient {
  private baseUrl: string;

  private endpoints = {
    uploadKeys: "/upload-keys",
    uploadFile: "/upload-file",
    request: "/request",
    getSharedKey: "/shared-key",
    getUploadedFiles: "/uploaded-files",
    getUploadedFile: (fileID: string) => `/file-object/${fileID}`,
  }

  // TODO: fix hardcoded organization ID
  // This should be passed in the constructor or set via a method
  // to avoid hardcoding it in the class
  private headers = {
    "X-Organization-Id": "5030a202-d52f-4a51-8d53-f776974f52ee",
    "Authorization": "",
  }

  constructor(baseUrl: string = "http://localhost:8080", organizationId: string = "5030a202-d52f-4a51-8d53-f776974f52ee", authToken: string = "") {
    this.baseUrl = baseUrl;
    this.headers["X-Organization-Id"] = organizationId;
    if (authToken) {
      this.headers["Authorization"] = `Bearer ${authToken}`;
    }
  }

  /// Store key share on the proxy server
  async uploadKey(share: Uint8Array, pubkey: PublicKey): Promise<void> {
    const request: StoreShareRequest = {
      shared_key: bytesToBase64(share),
      public_key: bytesToBase64(pubkey.toBytes()),

    };

    const response = await fetch(`${this.baseUrl}${this.endpoints.uploadKeys}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...this.headers,
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store share request failed: ${error.error}`);
    }

    console.log("Key share uploaded successfully");
  }

  async getKeyShare(): Promise<Uint8Array> {
    const response = await fetch(`${this.baseUrl}${this.endpoints.getSharedKey}`, {
      method: "GET",
      headers: {
        ...this.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get key share request failed: ${error.error}`);
    }

    const result: GetShareResponse = await response.json();
    // Convert the base64 encoded string back to Uint8Array
    return Uint8Array.from(atob(result.data.shared_key), (c) => c.charCodeAt(0));
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
   * Store encrypted data and re-encryption key on the proxy server
   * @param reencryptionKey The re-encryption key (G2Point)
   * @param encryptedKey The encrypted symmetric key
   * @param encryptedData The encrypted data
   * @param userId The user ID
   * @returns Promise with the store response
   */
    async storeFile(
      encryptedData: Uint8Array,
    ): Promise<StoreResponse> {

      const formDataRequest: FormData = new FormData();
      // Use btoa for base64 encoding of byte arrays
      // formDataRequest.append("file", new Blob([encryptedData]), "file");

      formDataRequest.append("file", new Blob([encryptedData]), "file");
  
      const response = await fetch(`${this.baseUrl}${this.endpoints.uploadFile}`, {
        method: "POST",
        headers: {
          ...this.headers,
        },
        body: formDataRequest
      });
  
      if (!response.ok) {
        const error = await response.json();
        throw new Error(`Store request failed: ${error.error}`);
      }

      const result: UploadFileResponse = await response.json();
      
      return {
        status: "success",
        id: result.data.id,
      }
    }

    async getStoredFile(fileID: string): Promise<GetStoredFileResponse> {
      const response = await fetch(`${this.baseUrl}${this.endpoints.getUploadedFile(fileID)}`, {
        method: "GET",
        headers: {
          ...this.headers,
        },
      });
  
      if (!response.ok) {
        const error = await response.json();
        throw new Error(`Get stored file request failed: ${error.error}`);
      }
  
      const result: GetStoredFileResponse = await response.json();
      return {
        id: result.id,
        name: result.name,
        size: result.size,
        mime_type: result.mime_type,
        object_url: result.object_url,
        created_at: result.created_at,
        updated_at: result.updated_at,
      }
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
