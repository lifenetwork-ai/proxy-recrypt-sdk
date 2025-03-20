import fs from "fs";
import { BN254CurveWrapper } from "../crypto/bn254";
import { base64BufferToBigInt, loadKeyPairFromFile } from "./index";
export async function loadMessage() {
    const messageBuffer = await fs.readFileSync("../testdata/data/message.txt", "utf-8");
    return Buffer.from(messageBuffer.toString(), "base64");
}
export async function loadEncryptedMessage() {
    const content = await fs.readFileSync("../testdata/encrypted_message.txt", "utf-8");
    return Buffer.from(content, "base64");
}
export async function loadRandomScalar() {
    const buffer = await fs.readFileSync("../testdata/random_scalar.txt");
    return base64BufferToBigInt(buffer);
}
export async function loadSymmetricKeyGT() {
    const buffer = await fs.readFileSync("../testdata/symmetric_key_gt.txt", "utf-8");
    return BN254CurveWrapper.GTFromBytes(Buffer.from(buffer.trim(), "base64"));
}
export async function loadSymmetricKey() {
    const content = await fs.readFileSync("../testdata/symmetric_key.txt");
    return Buffer.from(content.toString(), "base64");
}
export async function loadReKey() {
    const content = await fs.readFileSync("../testdata/rekey.txt", "utf-8");
    return BN254CurveWrapper.G2FromBytes(Buffer.from(content.trim(), "base64"));
}
export async function loadAliceKeyPair() {
    return await loadKeyPairFromFile("../testdata/alice_keypair.json");
}
export async function loadBobKeyPair() {
    return await loadKeyPairFromFile("../testdata/bob_keypair.json");
}
export const getMockNonce = () => {
    return new Uint8Array([
        223, 226, 69, 90, 252, 126, 59, 176, 98, 14, 194, 123,
    ]);
};
// get the first level payload(proxy -> Bob payload)
export const getFirstLevelEncryptedKeyFirst = async () => {
    const firstLevelEncryptedKeyFirst = await fs.readFileSync("../testdata/first_encrypted_key_first.txt", "utf-8");
    return BN254CurveWrapper.GTFromBytes(Buffer.from(firstLevelEncryptedKeyFirst.trim(), "base64"));
};
export const getFirstLevelEncryptedKeySecond = async () => {
    const firstLevelEncryptedKeySecond = await fs.readFileSync("../testdata/first_encrypted_key_second.txt", "utf-8");
    return BN254CurveWrapper.GTFromBytes(Buffer.from(firstLevelEncryptedKeySecond.trim(), "base64"));
};
// G1 from bytes not implemented, so we compare the string representation
export const getSecondLevelEncryptedKeyFirst = async () => {
    const secondLevelEncryptedKeyFirst = await fs.readFileSync("../testdata/second_encrypted_key_first.txt");
    return secondLevelEncryptedKeyFirst.toString();
};
export const getSecondLevelEncryptedKeySecond = async () => {
    const secondLevelEncryptedKeySecond = await fs.readFileSync("../testdata/second_encrypted_key_second.txt", "utf-8");
    return BN254CurveWrapper.GTFromBytes(Buffer.from(secondLevelEncryptedKeySecond.trim(), "base64"));
};
// Helper function to load all test data at once if needed
export async function loadAllTestData() {
    const [message, encryptedMessage, randomScalar, symmetricKeyGT, symmetricKey, reKey, aliceKeyPair, bobKeyPair,] = await Promise.all([
        loadMessage(),
        loadEncryptedMessage(),
        loadRandomScalar(),
        loadSymmetricKeyGT(),
        loadSymmetricKey(),
        loadReKey(),
        loadAliceKeyPair(),
        loadBobKeyPair(),
    ]);
    return {
        message,
        encryptedMessage,
        randomScalar,
        symmetricKeyGT,
        symmetricKey,
        mockNonce: getMockNonce(),
        reKey,
        aliceKeyPair,
        bobKeyPair,
    };
}
