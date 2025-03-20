import * as utils from "./utils";
import { encryptAESGCM, decryptAESGCM, generateRandomSymmetricKeyFromGT, deriveKeyFromGT, } from "./crypto";
import { BN254CurveWrapper } from "./crypto/bn254";
import { bn254 } from "@noble/curves/bn254";
import * as bigintModArith from "bigint-mod-arith";
import { Crypto } from "@peculiar/webcrypto";
import { generateRandomSecretKey } from "./utils/keypair";
export class PreClient {
    constructor() {
        this.G1 = BN254CurveWrapper.G1Generator();
        this.G2 = BN254CurveWrapper.G2Generator();
        this.Z = BN254CurveWrapper.pairing(this.G1, this.G2);
    }
    generateReEncryptionKey(secretA, publicB) {
        return BN254CurveWrapper.g2ScalarMul(publicB, secretA);
    }
    async secondLevelEncryption(secretA, message, scalar, keyGT, key, nonce) {
        // Generate random symmetric key only if not provided
        if (!keyGT || !key) {
            const generatedKeys = generateRandomSymmetricKeyFromGT();
            keyGT = keyGT || generatedKeys.keyGT;
            key = key || generatedKeys.key;
        }
        if (!nonce) {
            nonce = new Crypto().getRandomValues(new Uint8Array(12));
        }
        const encryptedMessage = await encryptAESGCM(Buffer.from(message), key, nonce);
        const first = BN254CurveWrapper.g1ScalarMul(this.G1, scalar);
        const second = BN254CurveWrapper.gtMul(BN254CurveWrapper.gtPow(BN254CurveWrapper.gtPow(this.Z, secretA.first), scalar), keyGT);
        const encryptedKey = { first, second };
        return { encryptedKey, encryptedMessage };
    }
    secretToPubkey(secret) {
        return utils.secretToPubkey(secret, this.G2, this.Z);
    }
    async decryptFirstLevel(payload, secretKey) {
        let symmetricKey = this.decryptFirstLevelKey(payload.encryptedKey, secretKey);
        let decryptedMessage = await decryptAESGCM(payload.encryptedMessage, symmetricKey);
        return decryptedMessage;
    }
    decryptFirstLevelKey(encryptedKey, secretKey) {
        const order = bn254.fields.Fr.ORDER;
        // console.log("scalar", bigintModArith.modInv(secretKey.second, order));
        // console.log(
        //   "Encrypted key first",
        //   BN254CurveWrapper.GTToBytes(encryptedKey.first)
        // );
        // console.log("bob secret key", secretKey.second);
        // console.log("order", order);
        const temp = BN254CurveWrapper.gtPow(encryptedKey.first, bigintModArith.modInv(secretKey.second, order));
        // console.log("temp", BN254CurveWrapper.GTToBytes(temp));
        const symmetricKeyGT = BN254CurveWrapper.gtDiv(encryptedKey.second, temp);
        const symmetricKey = deriveKeyFromGT(symmetricKeyGT);
        return symmetricKey;
    }
    async decryptSecondLevel(encryptedKey, encryptedMessage, secretKey) {
        let symmetricKey = this.decryptSecondLevelKey(encryptedKey, secretKey);
        let decryptedMessage = await decryptAESGCM(encryptedMessage, symmetricKey);
        return decryptedMessage;
    }
    decryptSecondLevelKey(encryptedKey, secretKey) {
        const temp = BN254CurveWrapper.pairing(encryptedKey.first, this.G2);
        const symmetricKeyGT = BN254CurveWrapper.gtDiv(encryptedKey.second, BN254CurveWrapper.gtPow(temp, secretKey.first));
        const symmetricKey = deriveKeyFromGT(symmetricKeyGT);
        return symmetricKey;
    }
    generateRandomKeyPair() {
        const secretKey = generateRandomSecretKey();
        const publicKey = this.secretToPubkey(secretKey);
        return { publicKey, secretKey };
    }
}
