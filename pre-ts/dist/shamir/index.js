import { split, combine } from "shamir-secret-sharing";
export const splitSecret = async (secret, threshold, shares) => {
    const sharesUint8Array = await split(secret, shares, threshold);
    return sharesUint8Array;
};
export const combineSecret = async (shares) => {
    const secret = await combine(shares);
    return secret;
};
