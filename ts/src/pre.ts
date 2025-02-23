import {
  SecretKey,
  PublicKey,
  FirstLevelCipherText,
  SecondLevelCipherText,
  SecondLevelSymmetricKey,
  FirstLevelSymmetricKey,
} from "./types";
import * as utils from "./utils";
import {
  encryptAESGCM,
  decryptAESGCM,
  generateRandomSymmetricKeyFromGT,
  deriveKeyFromGT,
} from "./crypto";
import { CurveType } from "@noble/curves/abstract/bls";
import { BN254CurveWrapper, G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bn254 } from "@noble/curves/bn254";
import * as bigintModArith from "bigint-mod-arith";

const DEFAULT_KEY_SIZE = 32;

export class PreSchemeImpl {
  private G1: G1Point;
  private G2: G2Point;
  private Z: GTElement;

  constructor() {
    this.G1 = BN254CurveWrapper.G1Generator();
    this.G2 = BN254CurveWrapper.G2Generator();
    this.Z = BN254CurveWrapper.pairing(this.G1, this.G2);
  }

  generateReEncryptionKey(secretA: bigint, publicB: G2Point): G2Point {
    return BN254CurveWrapper.g2ScalarMul(publicB, secretA);
  }

  async secondLevelEncryption(
    pubkeyA: GTElement,
    secretB: bigint,
    message: string,
    scalar: bigint
  ): Promise<SecondLevelCipherText> {
    const { keyGT, key } = generateRandomSymmetricKeyFromGT(DEFAULT_KEY_SIZE);
    const encryptedMessage = await encryptAESGCM(message, key);

    const first = BN254CurveWrapper.g1ScalarMul(this.G1, scalar);
    const second = BN254CurveWrapper.gtMul(
      BN254CurveWrapper.gtPow(pubkeyA, scalar),
      keyGT
    );

    const encryptedKey: SecondLevelSymmetricKey = { first, second };
    return { encryptedKey, encryptedMessage };
  }

  secretToPubkey(secret: SecretKey): PublicKey {
    return utils.secretToPubkey(secret, this.G2, this.Z);
  }

  async decryptFirstLevel(
    ciphertext: FirstLevelCipherText,
    secretKey: SecretKey
  ): Promise<string> {
    let symmetricKey = this.decryptFirstLevelKey(
      ciphertext.encryptedKey,
      secretKey
    );

    let decryptedMessage = await decryptAESGCM(
      ciphertext.encryptedMessage,
      symmetricKey
    );

    return decryptedMessage;
  }

  decryptFirstLevelKey(
    encryptedKey: FirstLevelSymmetricKey,
    secretKey: SecretKey
  ): Uint8Array {
    const order = bn254.fields.Fp.ORDER;
    const temp = BN254CurveWrapper.gtPow(
      encryptedKey.first,
      bigintModArith.modInv(secretKey.second, order)
    );

    const symmetricKeyGT = BN254CurveWrapper.gtDiv(encryptedKey.second, temp);

    const symmetricKey = deriveKeyFromGT(symmetricKeyGT, DEFAULT_KEY_SIZE);

    return symmetricKey;
  }
}
