import { GTElement } from "../crypto";

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
  };
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

export interface GetStoredFilesResponse {
  payload: {
    data: Array<GetStoredFileResponse>;
    next_page: number;
    page: number;
    size: number;
  };
  success: boolean;
}
