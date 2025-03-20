import { PreClient } from "./pre";
import { splitSecret } from "./shamir";
import { generateRandomScalar } from "./utils/keypair";
export class PreSdk {
    constructor() {
        this.preClient = new PreClient();
    }
    generateRandomKeyPair() {
        console.log("Generating key pair in PreSdk...");
        const keyPair = this.preClient.generateRandomKeyPair();
        console.log("Key pair generated:", keyPair);
        return keyPair;
    }
    async generateKeys() {
        console.log("Generating keys in PreSdk...");
        const secretKey = this.preClient.generateRandomKeyPair().secretKey;
        const bytes = secretKey.toBytes();
        const shares = await splitSecret(bytes, 2, 3);
        return shares;
    }
    async encryptData(secret, data) {
        console.log("Encrypting data in PreSdk...");
        const randomScalar = generateRandomScalar();
        const encryptedData = await this.preClient.secondLevelEncryption(secret, data, randomScalar);
        return encryptedData;
    }
    async decryptData(encryptedKey, encryptedData, secret) {
        console.log("Decrypting data in PreSdk...");
        const decryptedData = await this.preClient.decryptFirstLevel({
            encryptedKey,
            encryptedMessage: encryptedData,
        }, secret);
        console.log("Data decrypted:", decryptedData);
        return decryptedData;
    }
    storeShare() {
        console.log("Storing share in PreSdk...");
        // super.storeShare();
        console.log("Share stored.");
    }
}
export * from "./crypto";
export * from "./shamir";
export * from "./utils";
