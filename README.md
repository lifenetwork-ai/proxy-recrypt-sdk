# Crypto Library

A TypeScript SDK for Proxy Re-Encryption (PRE) and cryptographic primitives, enabling secure data sharing directly in the browser.

[![codecov](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib/graph/badge.svg?token=7JUVSD2ESJ)](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib)

## Overview

This SDK allows users to securely encrypt and share data via a proxy service, without exposing raw data to the proxy. It includes full client-side support for key generation, encryption, and Proxy Re-Encryption (PRE).

This SDK implements the PRE method as detailed in our design spec:
[Overleaf PRE Design Doc](https://www.overleaf.com/read/fxqmmczvtxjn#cc8f9b) (Work in progress)

## Key Features

- ✨ **Client-Side Only**: All crypto operations are performed in-browser
- 🔐 **Key Generation**: Generate secure encryption keys with share splitting
- 🔑 **Shamir's Secret Sharing**: Split keys into threshold shares for secure distribution
- 📁 **Data Encryption**: Encrypt arbitrary data (files, images, etc.) in the browser
- 🔄 **Proxy Re-Encryption**: Share encrypted data securely without giving direct access
- 📤 **File Upload**: Store encrypted files via the proxy server

## Installation

```bash
npm install pre-ts
# or
yarn add pre-ts
```

## Quick Start

```typescript
import { PreSdk, SecretKey } from "pre-ts";

// Initialize the SDK
const client = new PreSdk();

// Generate key shares (default: 3 shares with threshold of 2)
const shares = await client.generateShares();

// Combine shares to reconstruct the secret key
const secretBytes = await client.preClient.combineShares(shares.slice(0, 2));
const secretKey = SecretKey.fromBytes(secretBytes);

// Encrypt data
const data = new Uint8Array([/* your data */]);
const encrypted = await client.encryptData(secretKey, data);

// Decrypt data
const decrypted = await client.decryptData(
  encrypted.encryptedKey, 
  encrypted.encryptedMessage, 
  secretKey
);
```

## Usage Guide

### 1. Key Generation and Sharing

```typescript
const client = new PreSdk();

// Configure share count and threshold if needed
client.shareCount = 5;  // Generate 5 shares
client.threshold = 3;   // Need at least 3 shares to reconstruct

// Generate shares
const shares = await client.generateShares();

// Store shares securely
const proxyClient = new ProxyClient("https://your-proxy-server.com", "orgId", "authToken");
const keyPair = client.generateRandomKeyPair();
await proxyClient.uploadKey(shares[0], keyPair.publicKey);
```

### 2. Data Encryption

```typescript
// Create a secret key from shares
const secretBytes = await client.preClient.combineShares([share1, share2]);
const secretKey = SecretKey.fromBytes(secretBytes);

// Encrypt data
const dataBuffer = new Uint8Array([/* your data */]);
const encrypted = await client.encryptData(secretKey, dataBuffer);
```

### 3. File Storage

```typescript
// Upload encrypted file to proxy server
const proxyClient = new ProxyClient("https://your-proxy-server.com", "orgId", "authToken");
const response = await proxyClient.storeFile(
  encrypted.encryptedMessage,
  "encrypted-document.enc"
);

// Retrieve file information
const fileInfo = await proxyClient.getStoredFile(response.id);

// List all stored files
const files = await proxyClient.getStoredFiles(1, 10); // page 1, 10 items per page
```

### 4. Proxy Re-Encryption

```typescript
// Generate re-encryption key from sender to recipient
const reKey = client.preClient.generateReEncryptionKey(
  senderSecret,
  recipientPublic
);

// Store data with re-encryption key
const proxyClient = new ProxyClient();
await proxyClient.store(
  reKey,
  encrypted.encryptedKey,
  encrypted.encryptedMessage,
  "recipientUserId"
);

// Recipient decryption
const decrypted = await client.decryptData(
  firstLevelKey,
  encryptedData,
  recipientSecretKey
);
```

## API Reference

### `PreSdk`

Main class for cryptographic operations.

#### Properties:
- `shareCount`: Number of shares to generate (default: 3)
- `threshold`: Minimum shares needed for reconstruction (default: 2)
- `preClient`: Instance of the underlying PreClient

#### Methods:
- `generateRandomKeyPair()`: Generates a new random KeyPair
- `generateShares()`: Generates and splits a secret key into shares
- `encryptData(secret, data)`: Encrypts data with the given secret key
- `decryptData(encryptedKey, encryptedData, secret)`: Decrypts data using the given keys

### `ProxyClient`

Handles communication with the proxy server for key and file management.

#### Methods:
- `uploadKey(share, pubkey)`: Uploads a key share to the proxy server
- `getKeyShare()`: Retrieves a key share from the proxy server
- `store(reEncryptionKey, encryptedKey, encryptedData, userId)`: Stores encrypted data with re-encryption key
- `storeFile(encryptedData, filename, customHeaders)`: Uploads an encrypted file
- `getStoredFile(fileID, customHeaders)`: Gets information about a stored file
- `getStoredFiles(page, size, customHeaders)`: Lists stored files with pagination

## Security Best Practices

- Store shares separately across different storage systems or parties
- Ensure the threshold is set appropriately for your security requirements
- Never transmit unencrypted secret keys over the network
- Use HTTPS for all proxy server communications
- Implement additional application-level authentication for sensitive operations

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributions

PRs and issues welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more info.
