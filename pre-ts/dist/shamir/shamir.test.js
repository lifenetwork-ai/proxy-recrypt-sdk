import { combineSecret, splitSecret } from ".";
import { generateRandomSymmetricKeyFromGT } from "../crypto";
describe("Test Shamir's Secret Sharing", () => {
    test("Split then combine simple secret", async () => {
        const secret = Buffer.from("Hello, World!");
        const threshold = 2;
        const shares = 3;
        const sharesArray = await splitSecret(secret, threshold, shares);
        const combinedSecret = await combineSecret(sharesArray);
        expect(Buffer.from(combinedSecret).toString()).toEqual(secret.toString());
    });
    test("Split then combine complex secret", async () => {
        const secret = Buffer.from(generateRandomSymmetricKeyFromGT().key);
        const threshold = 2;
        const shares = 3;
        const sharesArray = await splitSecret(secret, threshold, shares);
        const combinedSecret = await combineSecret(new Array(sharesArray[0], sharesArray[1]));
        expect(Buffer.from(combinedSecret).toString()).toEqual(secret.toString());
    });
    test("Split then combine complex secret", async () => {
        const secret = Buffer.from(generateRandomSymmetricKeyFromGT().key);
        const threshold = 3;
        const shares = 5;
        const sharesArray = await splitSecret(secret, threshold, shares);
        const combinedSecret = await combineSecret(new Array(sharesArray[0], sharesArray[1], sharesArray[2]));
        const combinedSecret2 = await combineSecret(new Array(sharesArray[1], sharesArray[2], sharesArray[3]));
        expect(Buffer.from(combinedSecret).toString()).toBeTruthy();
        expect(Buffer.from(combinedSecret).toString()).toEqual(secret.toString());
        expect(Buffer.from(combinedSecret).toString()).toEqual(combinedSecret2.toString());
    });
});
