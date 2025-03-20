import { split, combine } from "shamir-secret-sharing";

export const splitSecret = async (
  secret: Uint8Array,
  threshold: number,
  shares: number
): Promise<Array<Uint8Array>> => {
  const sharesUint8Array = await split(secret, shares, threshold);
  return sharesUint8Array;
};

export const combineSecret = async (
  shares: Array<Uint8Array>
): Promise<Uint8Array> => {
  const secret = await combine(shares);
  return secret;
};
