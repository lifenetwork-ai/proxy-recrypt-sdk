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

    const combinedSecret = await combineSecret(sharesArray);
    expect(Buffer.from(combinedSecret).toString()).toEqual(secret.toString());
  });
});
