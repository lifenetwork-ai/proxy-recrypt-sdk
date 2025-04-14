# Human Network PRE SDK

A TypeScript SDK for Proxy Re-Encryption (PRE) that enables secure data sharing directly in the browser. Built on the BN254 curve, this SDK implements client-side cryptographic operations for key generation, encryption, and secure data sharing through proxy re-encryption.

[![codecov](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib/graph/badge.svg?token=7JUVSD2ESJ)](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib)

## Overview

This SDK allows users to securely encrypt and share data via a proxy service, without exposing raw data to the proxy. It implements the PRE method as detailed in our [design specification](https://www.overleaf.com/read/fxqmmczvtxjn#cc8f9b).

### Key Features

- ✨ **Client-Side Security**: All cryptographic operations performed in-browser
- 🔐 **Shamir's Secret Sharing**: Split keys into secure shares with configurable thresholds
- 🔑 **Passphrase Protection**: Optional encryption for key shares
- 📁 **File Encryption**: Support for images and files up to 10MB
- 🔄 **Proxy Re-Encryption**: Share encrypted data without exposing content
- 📅 **Browser Storage**: Secure local storage integration

## Installation

```bash
npm install human-network-pre
# or
yarn add human-network-pre
```

## Quick Start

### Basic Encryption Example

```typescript
import { PreSdk, SecretKey } from "human-network-pre";

// Initialize SDK
const client = new PreSdk();

// Generate and split keys (returns 3 shares)
const shares = await client.generateShares();

// Combine shares to reconstruct secret
const secretBytes = await client.pre.combineSecret([shares[0], shares[1]]);
const secret = SecretKey.fromBytes(secretBytes);

// Encrypt data
const data = new Uint8Array(/* your data */);
const encrypted = await client.encryptData(secret, data);
```

### Complete Data Sharing Flow

```typescript
// 1. Initialize clients
const client = new PreSdk();
const damClient = new DAMClient(
  "http://localhost:8080",
  "organization-id",
  "auth-token"
);

// 2. Generate sender's keys
const senderShares = await client.generateShares();
const senderSecret = SecretKey.fromBytes(
  await client.pre.combineSecret([senderShares[0], senderShares[1]])
);

// 3. Encrypt data
const data = new Uint8Array(/* your data */);
const encrypted = await client.encryptData(senderSecret, data);

// 4. Upload encrypted data to DAM service
const uploadResponse = await damClient.storeFile(encrypted.encryptedMessage);

// 5. Share the key with recipient
await damClient.uploadKey(senderShares[0], recipientPublicKey);

// 6. Recipient retrieves and decrypts data
const keyShare = await damClient.getKeyShare();
const storedFile = await damClient.getStoredFile(uploadResponse.id);
// Decrypt using the retrieved key share and file
```

## API Reference

### PreSdk

Main client class for cryptographic operations.

#### Methods

- `generateShares(): Promise<Array<Uint8Array>>` - Generates key shares (3 shares, 2-share threshold)
- `encryptData(secret: SecretKey, data: Uint8Array): Promise<SecondLevelEncryptionResponse>` - Encrypts data
- `pre.combineSecret(shares: Uint8Array[]): Promise<Uint8Array>` - Reconstructs secret from shares

### DAMClient

Handles Data Access Management (DAM) service communication.

#### Methods

- `uploadKey(share: Uint8Array, pubkey: PublicKey): Promise<void>` - Uploads a key share
- `getKeyShare(): Promise<Uint8Array>` - Retrieves a shared key
- `storeFile(encryptedData: Uint8Array, filename?: string): Promise<StoreResponse>` - Stores encrypted file
- `getStoredFile(fileID: string): Promise<GetStoredFileResponse>` - Retrieves stored file information
- `getStoredFiles(page?: number, size?: number): Promise<GetStoredFilesResponse>` - Lists stored files

## File Support

### Supported File Types

- Images: PNG, JPEG, JPG, GIF, WebP, BMP, TIFF
- Maximum file size: 10MB

## Security Best Practices

- Use strong, unique passphrases for key share protection
- Store shares in separate secure locations
- Never transmit or store unencrypted secret keys
- Implement proper error handling for all operations
- Use secure channels for share distribution
- Validate file types and sizes before encryption

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
