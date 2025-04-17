// DAMClient is a client for the Data Access Management (DAM) service.

import {
  PublicKey,
  GetShareResponse,
  GetStoredFileResponse,
  GetStoredFilesResponse,
  StoreResponse,
  StoreShareRequest,
  UploadFileResponse,
} from "../types";
import { base64ToBytes, bytesToBase64 } from "../utils";

// It provides methods to upload keys, store encrypted data, and retrieve stored files.
export class DAMClient {
  private baseUrl: string;

  private endpoints = {
    uploadKeys: "/upload-keys",
    uploadFile: "/upload-file",
    request: "/request",
    getSharedKey: "/shared-key",
    getUploadedFiles: "/uploaded-files",
    getUploadedFile: (fileID: string) => `/file-object/${fileID}`,
  };

  private headers = {
    "X-Organization-Id": "",
    Authorization: "",
  };

  constructor(
    baseUrl: string = "http://localhost:8080",
    organizationId: string = "",
    authToken: string = ""
  ) {
    this.baseUrl = baseUrl;
    this.headers["X-Organization-Id"] = organizationId;
    if (authToken) {
      this.headers["Authorization"] = `${authToken}`;
    }
  }

  /// Store key share on the proxy server
  async uploadKey(share: Uint8Array, pubkey: PublicKey): Promise<void> {
    const request: StoreShareRequest = {
      shared_key: bytesToBase64(share),
      public_key: bytesToBase64(pubkey.toBytes()),
    };

    const response = await fetch(
      `${this.baseUrl}${this.endpoints.uploadKeys}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
        },
        body: JSON.stringify(request),
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store share request failed: ${error.error}`);
    }
  }

  async getKeyShare(): Promise<Uint8Array> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getSharedKey}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
        },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get key share request failed: ${error.error}`);
    }

    const result: GetShareResponse = await response.json();
    // Convert the base64 encoded string back to Uint8Array
    return base64ToBytes(result.data.shared_key);
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
    filename?: string,
    customHeader: HeadersInit = {}
  ): Promise<StoreResponse> {
    const formDataRequest: FormData = new FormData();

    formDataRequest.append(
      "file",
      new Blob([encryptedData]),
      Date.now().toString() + "_encrypted_file" + ".enc"
    );

    const response = await fetch(
      `${this.baseUrl}${this.endpoints.uploadFile}`,
      {
        method: "POST",
        headers: {
          ...this.headers,
          ...customHeader,
        },
        body: formDataRequest,
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Store request failed: ${error.error}`);
    }

    const result: UploadFileResponse = await response.json();

    return {
      status: "success",
      id: result.data.id,
    };
  }

  async getStoredFile(
    fileID: string,
    customHeader: HeadersInit = {}
  ): Promise<GetStoredFileResponse> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getUploadedFile(fileID)}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
          ...customHeader,
        },
      }
    );

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
    };
  }

  async getStoredFiles(
    page?: number,
    size?: number,
    customHeader: HeadersInit = {}
  ): Promise<GetStoredFilesResponse> {
    const response = await fetch(
      `${this.baseUrl}${this.endpoints.getUploadedFiles}?page=${page}&size=${size}`,
      {
        method: "GET",
        headers: {
          ...this.headers,
          ...customHeader,
        },
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Get stored files request failed: ${error.error}`);
    }

    const result: GetStoredFilesResponse = await response.json();
    if (!result.success) {
      throw new Error("Failed to fetch stored files");
    }

    return result;
  }
}
