import { combineSecret, splitSecret } from ".";
import { generateRandomSymmetricKeyFromGT } from "../crypto";
import { describe, test, expect } from "@jest/globals";

describe("Test Shamir's Secret Sharing", () => {
  test("Split then combine simple secret", async () => {
    const secret = new Uint8Array(
      "Hello, world!".split("").map((c) => c.charCodeAt(0))
    );
    const threshold = 2;
    const shares = 3;
    const sharesArray = await splitSecret(secret, threshold, shares);
    const combinedSecret = await combineSecret(sharesArray);
    expect(combinedSecret.toString()).toEqual(secret.toString());
  });
  test("Split then combine complex secret", async () => {
    const secret = (await generateRandomSymmetricKeyFromGT()).key;

    const threshold = 2;
    const shares = 3;

    const sharesArray = await splitSecret(secret, threshold, shares);

    const combinedSecret = await combineSecret([
      sharesArray[0],
      sharesArray[1],
    ]);
    expect(combinedSecret.toString()).toEqual(secret.toString());
  });

  test("Split then combine complex secret", async () => {
    const secret = (await generateRandomSymmetricKeyFromGT()).key;

    const threshold = 3;
    const shares = 5;

    const sharesArray = await splitSecret(secret, threshold, shares);

    const combinedSecret = await combineSecret([
      sharesArray[0],
      sharesArray[1],
      sharesArray[2],
    ]);

    const combinedSecret2 = await combineSecret([
      sharesArray[1],
      sharesArray[2],
      sharesArray[3],
    ]);

    expect(Buffer.from(combinedSecret).toString()).toBeTruthy();
    expect(combinedSecret.toString()).toEqual(secret.toString());
    expect(combinedSecret.toString()).toEqual(combinedSecret2.toString());
  });
});
