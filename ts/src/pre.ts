import {
  SecretKey,
  PublicKey,
  FirstLevelEncryptionResponse,
  SecondLevelEncryptionResponse,
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
  ): Promise<SecondLevelEncryptionResponse> {
    // Generate random symmetric key only if not provided
    if (!keyGT || !key) {
      const generatedKeys = generateRandomSymmetricKeyFromGT();
      keyGT = keyGT || generatedKeys.keyGT;
      key = key || generatedKeys.key;
    }

    if (!nonce) {
      nonce = webcrypto.getRandomValues(new Uint8Array(12));
    }
    const encryptedMessage = await encryptAESGCM(
      Buffer.from(message),
      key,
      nonce
    );
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
    let symmetricKey = this.decryptFirstLevelKey(
      payload.encryptedKey,
      secretKey
    );

    let decryptedMessage = await decryptAESGCM(
      payload.encryptedMessage,
      symmetricKey
    );

    return decryptedMessage;
  }

  decryptFirstLevelKey(
    encryptedKey: FirstLevelSymmetricKey,
    secretKey: SecretKey
  ): Uint8Array {
    const order = bn254.fields.Fr.ORDER;

    // console.log("scalar", bigintModArith.modInv(secretKey.second, order));
    // console.log(
    //   "Encrypted key first",
    //   BN254CurveWrapper.GTToBytes(encryptedKey.first)
    // );
    // console.log("bob secret key", secretKey.second);
    // console.log("order", order);
    const temp = BN254CurveWrapper.gtPow(
      encryptedKey.first,
      bigintModArith.modInv(secretKey.second, order)
    );
    // console.log("temp", BN254CurveWrapper.GTToBytes(temp));
    const symmetricKeyGT = BN254CurveWrapper.gtDiv(encryptedKey.second, temp);
    const symmetricKey = deriveKeyFromGT(symmetricKeyGT);

    return symmetricKey;
  }

  async decryptSecondLevel(
    encryptedKey: SecondLevelSymmetricKey,
    encryptedMessage: Uint8Array,
    secretKey: SecretKey
  ): Promise<Uint8Array> {
    let symmetricKey = this.decryptSecondLevelKey(encryptedKey, secretKey);

    let decryptedMessage = await decryptAESGCM(encryptedMessage, symmetricKey);

    return decryptedMessage;
  }

  decryptSecondLevelKey(
    encryptedKey: SecondLevelSymmetricKey,
    secretKey: SecretKey
  ): Uint8Array {
    const temp = BN254CurveWrapper.pairing(encryptedKey.first, this.G2);
    const symmetricKeyGT = BN254CurveWrapper.gtDiv(
      encryptedKey.second,
      BN254CurveWrapper.gtPow(temp, secretKey.first)
    );
    const symmetricKey = deriveKeyFromGT(symmetricKeyGT);

    return symmetricKey;
  }
}
