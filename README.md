# Human Network Crypto Library

A TypeScript SDK for Proxy Re-Encryption (PRE) and cryptographic primitives, enabling secure data sharing directly in the browser.

[![codecov](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib/graph/badge.svg?token=7JUVSD2ESJ)](https://codecov.io/gh/tuantran-genetica/human-network-pre-lib)

## Overview

This SDK allows users to securely encrypt and share data via a proxy service, without exposing raw data to the proxy. It includes full client-side support for key generation, encryption, and Proxy Re-Encryption (PRE).

This SDK implements the PRE method as detailed in our design spec:
[Overleaf PRE Design Doc]([https://www.overleaf.com/project/67b830bc1bfd7b6dab9affb5](https://www.overleaf.com/read/fxqmmczvtxjn#cc8f9b))

## Key Features

-   ✨ **Client-Side Only**: All crypto operations are performed in-browser
-   🔐 **Key Generation**: Generate secure encryption keys with share splitting
-   🔑 **Passphrase Protection**: Add passphrase security to key shares
-   📁 **Data Encryption**: Encrypt arbitrary data (files, images, etc.) in the browser
-   🔄 **Proxy Re-Encryption**: Share encrypted data securely without giving direct access
-   📅 **Local Storage Support**: Save key shares securely in browser storage

## Installation

```bash
npm install human-network-pre
# or
yarn add human-network-pre
```

## Quick Start

```ts
import { PreSdk, SecretKey } from "human-network-pre";

const client = new PreSdk();
const shares = await client.generateKeys();

const data = new Uint8Array([
    /* your data */
]);
const secretKey = SecretKey.fromBytes(await client.pre.combineSecret(shares));
const encrypted = await client.encryptData(secretKey, data);
```

## Usage Guide

### 1. Key Generation

```ts
const client = new PreSdk();
const shares = await client.generateKeys();
```

### 2. Share Protection (Optional)

```ts
const passphrase = "your-secure-passphrase";
const encryptedShare = await encryptShare(shares[0], passphrase);

localStorage.setItem(
    "share1",
    JSON.stringify({
        share: Array.from(new Uint8Array(encryptedShare)),
        hasPassphrase: true,
        passphraseHash: hashPassphrase(passphrase),
    })
);
```

### 3. Data Encryption

```ts
const secretBytes = await client.pre.combineSecret([share1Array, share2Array]);
const secret = SecretKey.fromBytes(secretBytes);
const encrypted = await client.encryptData(secret, new Uint8Array(dataBuffer));
```

### 4. Proxy Re-Encryption

```ts
const reKey = client.preClient.generateReEncryptionKey(
    senderSecret.first,
    recipientPublic.second
);

const proxyClient = new pre.ProxyClient();
await proxyClient.store(
    reKey,
    encrypted.encryptedKey,
    encrypted.encryptedMessage,
    "userId"
);
```

### 5. Decryption by Recipient

```ts
const { firstLevelKey, encryptedData } = await proxyClient.request(
    proxyStoreId
);

const decrypted = await client.preClient.decryptFirstLevel(
    {
        encryptedKey: firstLevelKey,
        encryptedMessage: encryptedData,
    },
    recipientSecretKey
);
```

## API Reference

### `PreSdk`

#### Methods:

-   `generateKeys(): Promise<Uint8Array[]>`
-   `encryptData(secret: SecretKey, data: Uint8Array): Promise<SecondLevelEncryptionResponse>`
-   `pre`: Contains utility methods like `combineSecret()`

### `ProxyClient`

Handles proxy server communication.

#### Methods:

-   `store(reEncryptionKey: G2Point, encryptedKey: Uint8Array, encryptedMessage: Uint8Array, userId: string): Promise<ProxyResponse>`
-   `request(id: string): Promise<{ firstLevelKey: Uint8Array, encryptedData: Uint8Array }>`

## Security Best Practices

-   Use strong, unique passphrases to protect key shares
-   Always store shares separately and securely
-   Never transmit or store unencrypted secret keys
-   Limit proxy access to re-encryption operations only

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributions

PRs and issues welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for more info.
