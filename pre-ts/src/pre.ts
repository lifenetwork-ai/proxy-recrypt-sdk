import {
  SecretKey,
  PublicKey,
  FirstLevelEncryptionResponse,
  SecondLevelEncryptionResponse,
  SecondLevelSymmetricKey,
  FirstLevelSymmetricKey,
  KeyPair,
} from "./types";
import * as utils from "./utils";
import {
  encryptAESGCM,
  decryptAESGCM,
  generateRandomSymmetricKeyFromGT,
  deriveKeyFromGT,
} from "./crypto";
import { BN254CurveWrapper, G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bn254 } from "@noble/curves/bn254";
import * as bigintModArith from "bigint-mod-arith";
import { generateRandomSecretKey } from "./utils/keypair";


/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-explicit-any */
function getCrypto() {
  if (typeof window !== "undefined" && window.crypto) {
    // Browser environment
    return window.crypto;
  } else if (typeof global !== "undefined") {
    // Node.js environment
    try {
      // Node.js v19+ has webcrypto as part of the global crypto
      const nodeCrypto = require("crypto");
      if (nodeCrypto.webcrypto) {
        return nodeCrypto.webcrypto;
      }
      // Fallback to @peculiar/webcrypto for older Node versions
      const { Crypto } = require("@peculiar/webcrypto");
      return new Crypto();
    } catch (error: any) {
      throw new Error(
        "Crypto support not available. Please install @peculiar/webcrypto package." + error.message
      );
    }
  }
  throw new Error("No crypto implementation available in this environment");
}

export class PreClient {
  G1: G1Point;
  G2: G2Point;
  Z: GTElement;

  constructor() {
    this.G1 = BN254CurveWrapper.G1Generator();
    this.G2 = BN254CurveWrapper.G2Generator();
    this.Z = BN254CurveWrapper.pairing(this.G1, this.G2);
  }

  generateReEncryptionKey(secretA: bigint, publicB: G2Point): G2Point {
    return BN254CurveWrapper.g2ScalarMul(publicB, secretA);
  }

  async secondLevelEncryption(
    secretA: SecretKey,
    message: Uint8Array,
    scalar: bigint,
    keyGT?: GTElement,
    key?: Uint8Array,
    nonce?: Uint8Array
  ): Promise<SecondLevelEncryptionResponse> {
    // Generate random symmetric key only if not provided
    if (!keyGT || !key) {
      const generatedKeys = await generateRandomSymmetricKeyFromGT();
      keyGT = keyGT || generatedKeys.keyGT;
      key = key || generatedKeys.key;
    }

    if (!nonce) {
      nonce = getCrypto().getRandomValues(new Uint8Array(12));
    }
    const encryptedMessage = await encryptAESGCM(message, key, nonce);
    const first = BN254CurveWrapper.g1ScalarMul(this.G1, scalar);
    const second = BN254CurveWrapper.gtMul(
      BN254CurveWrapper.gtPow(
        BN254CurveWrapper.gtPow(this.Z, secretA.first),
        scalar
      ),
      keyGT
    );

    const encryptedKey: SecondLevelSymmetricKey = { first, second };
    return { encryptedKey, encryptedMessage };
  }

  secretToPubkey(secret: SecretKey): PublicKey {
    return utils.secretToPubkey(secret, this.G2, this.Z);
  }

  async decryptFirstLevel(
    payload: FirstLevelEncryptionResponse,
    secretKey: SecretKey
  ): Promise<Uint8Array> {
    const symmetricKey = await this.decryptFirstLevelKey(
      payload.encryptedKey,
      secretKey
    );

    const decryptedMessage = await decryptAESGCM(
      payload.encryptedMessage,
      symmetricKey
    );

    return decryptedMessage;
  }

  async decryptFirstLevelKey(
    encryptedKey: FirstLevelSymmetricKey,
    secretKey: SecretKey
  ): Promise<Uint8Array> {
    const order = bn254.fields.Fr.ORDER;

    const temp = BN254CurveWrapper.gtPow(
      encryptedKey.first,
      bigintModArith.modInv(secretKey.second, order)
    );
    // console.log("temp", BN254CurveWrapper.GTToBytes(temp));
    const symmetricKeyGT = BN254CurveWrapper.gtDiv(encryptedKey.second, temp);
    const symmetricKey = await deriveKeyFromGT(symmetricKeyGT);

    return symmetricKey;
  }

  async decryptSecondLevel(
    encryptedKey: SecondLevelSymmetricKey,
    encryptedMessage: Uint8Array,
    secretKey: SecretKey
  ): Promise<Uint8Array> {
    const symmetricKey = await this.decryptSecondLevelKey(
      encryptedKey,
      secretKey
    );

    const decryptedMessage = await decryptAESGCM(encryptedMessage, symmetricKey);

    return decryptedMessage;
  }

  async decryptSecondLevelKey(
    encryptedKey: SecondLevelSymmetricKey,
    secretKey: SecretKey
  ): Promise<Uint8Array> {
    const temp = BN254CurveWrapper.pairing(encryptedKey.first, this.G2);
    const symmetricKeyGT = BN254CurveWrapper.gtDiv(
      encryptedKey.second,
      BN254CurveWrapper.gtPow(temp, secretKey.first)
    );
    const symmetricKey = await deriveKeyFromGT(symmetricKeyGT);

    return symmetricKey;
  }

  generateRandomKeyPair(): KeyPair {
    const secretKey = generateRandomSecretKey();
    const publicKey = this.secretToPubkey(secretKey);
    return { publicKey, secretKey };
  }
}
