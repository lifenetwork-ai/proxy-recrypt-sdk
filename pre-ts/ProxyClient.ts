import { G2Point, GTElement, G1Point, BN254CurveWrapper } from './src/crypto/bn254';
import { SecondLevelSymmetricKey, FirstLevelSymmetricKey } from './src/types';

// Helper functions for Uint8Array serialization
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}

export interface StoreRequest {
  reencryption_key: string; // Base64 encoded G2Point
  encrypted_key: {
    first: string; // Base64 encoded G1Point
    second: string; // Base64 encoded GTElement
  };
  encrypted_data: string; // Base64 encoded data
  user_id: string;
}

export interface StoreResponse {
  status: string;
  id: string;
}

export interface RequestResponse {
  first_level_key: {
    first: string; // Base64 encoded GTElement
    second: string; // Base64 encoded GTElement
  };
  encrypted_data: string; // Base64 encoded data
}

export class ProxyClient {
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:8080') {
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
    const request: StoreRequest = {
      reencryption_key: arrayBufferToBase64(BN254CurveWrapper.G2ToBytes(reencryptionKey)),
      encrypted_key: {
        first: arrayBufferToBase64(BN254CurveWrapper.G1ToBytes(encryptedKey.first)),
        second: arrayBufferToBase64(BN254CurveWrapper.GTToBytes(encryptedKey.second)),
      },
      encrypted_data: arrayBufferToBase64(encryptedData),
      user_id: userId,
    };

    const response = await fetch(`${this.baseUrl}/store`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
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
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
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
      firstLevelKey: {
        first: BN254CurveWrapper.GTFromBytes(base64ToArrayBuffer(result.first_level_key.first)),
        second: BN254CurveWrapper.GTFromBytes(base64ToArrayBuffer(result.first_level_key.second)),
      },
      encryptedData: base64ToArrayBuffer(result.encrypted_data),
    };
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