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
  getCrypto,
} from "./crypto";
import { BN254CurveWrapper, G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bn254 } from "@noble/curves/bn254";
import * as bigintModArith from "bigint-mod-arith";
import { generateRandomSecretKey } from "./utils/keypair";

export class PreClient {
  G1: G1Point;
  G2: G2Point;
  Z: GTElement;
  allowedFileTypes: string[] = [
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
  ];

  magicNumbers = new Map<string, Uint8Array>([
    ["image/png", new Uint8Array([0x89, 0x50, 0x4e, 0x47])],
    ["image/jpeg", new Uint8Array([0xff, 0xd8, 0xff])],
    ["image/jpg", new Uint8Array([0xff, 0xd8, 0xff])],
    ["image/gif", new Uint8Array([0x47, 0x49, 0x46])],
    ["image/webp", new Uint8Array([0x52, 0x49, 0x46, 0x46])],
    ["image/bmp", new Uint8Array([0x42, 0x4d])],
    ["image/tiff", new Uint8Array([0x49, 0x49])],
  ]);

  /* Constructor
  // @param allowedFileTypes - Array of allowed file types for encryption - Default to most common image types: 
  // png, jpeg, jpg, gif, webp, bmp, tiff
  */
  // @returns {PreClient} - Instance of PreClient
  constructor(allowedFileTypes?: string[]) {
    this.G1 = BN254CurveWrapper.G1Generator();
    this.G2 = BN254CurveWrapper.G2Generator();
    this.Z = BN254CurveWrapper.pairing(this.G1, this.G2);

    if (allowedFileTypes) {
      this.allowedFileTypes = allowedFileTypes;
    }
  }

  generateReEncryptionKey(secretA: bigint, publicB: G2Point): G2Point {
    return BN254CurveWrapper.g2ScalarMul(publicB, secretA);
  }

  /* istanbul ignore next */
  async validate(message: Uint8Array) {
    // Validate magic number
    const fileType = message.slice(0, 4);
    const isValidType = this.allowedFileTypes.some((type) => {
      const magicNumber = this.magicNumbers.get(type);
      return (
        magicNumber &&
        fileType
          .slice(0, magicNumber.length)
          .every((byte, index) => byte === magicNumber[index])
      );
    });
    if (!isValidType) {
      throw new Error("Invalid file type");
    }

    // Validate size
    const maxSize = 10 * 1024 * 1024; // 10 MB
    if (message.length > maxSize) {
      throw new Error("File size exceeds 10 MB");
    }
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

    const encryptedKey: SecondLevelSymmetricKey = new SecondLevelSymmetricKey(
      first,
      second
    );
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

    const decryptedMessage = await decryptAESGCM(
      encryptedMessage,
      symmetricKey
    );

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
