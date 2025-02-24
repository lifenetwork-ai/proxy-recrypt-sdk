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
import { BN254CurveWrapper, G1Point, G2Point, GTElement } from "./crypto/bn254";
import { bn254 } from "@noble/curves/bn254";
import * as bigintModArith from "bigint-mod-arith";
import { webcrypto } from "crypto";

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
    secretA: SecretKey,
    message: string,
    scalar: bigint,
    keyGT?: GTElement,
    key?: Uint8Array,
    nonce?: Uint8Array
  ): Promise<SecondLevelCipherText> {
    // Generate random symmetric key only if not provided
    if (!keyGT || !key) {
      const generatedKeys = generateRandomSymmetricKeyFromGT();
      keyGT = keyGT || generatedKeys.keyGT;
      key = key || generatedKeys.key;
    }

    nonce = new Uint8Array([
      223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123,
    ]);

    if (!nonce) {
      nonce = webcrypto.getRandomValues(new Uint8Array(12));
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

    const symmetricKey = deriveKeyFromGT(symmetricKeyGT);

    return symmetricKey;
  }
}
