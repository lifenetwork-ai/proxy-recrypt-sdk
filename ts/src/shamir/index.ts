import { split, combine } from "shamir-secret-sharing";

export const splitSecret = async (
  secret: Buffer,
  threshold: number,
  shares: number
): Promise<Array<Buffer>> => {
  const secretUint8Array = new Uint8Array(secret);
  const sharesUint8Array = await split(secretUint8Array, shares, threshold);
  return sharesUint8Array.map((share) => Buffer.from(share));
};

export const combineSecret = async (shares: Array<Buffer>): Promise<Buffer> => {
  const sharesUint8Array = shares.map((share) => new Uint8Array(share));
  const secretUint8Array = await combine(sharesUint8Array);
  return Buffer.from(secretUint8Array);
};
