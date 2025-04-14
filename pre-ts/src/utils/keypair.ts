import { BN254CurveWrapper, G2Point, GTElement } from "../crypto";
import { PublicKey, SecretKey } from "../types/keypair";
import { bn254 } from "@noble/curves/bn254";

export function generateRandomSecretKey(): SecretKey {
  const secret = new SecretKey(generateRandomScalar(), generateRandomScalar());
  return secret;
}

// Generate a random scalar in [0, order-1] of the BN254 curve
export function generateRandomScalar(): bigint {
  // Get the order of BN254 curve
  const order = bn254.fields.Fr.ORDER;

  // Generate a random scalar in [0, order-1]
  const scalar = BigInt(Math.floor(Math.random() * Number(order)));
  return scalar;
}

export function secretToPubkey(
  secret: SecretKey,
  g: G2Point,
  Z: GTElement
): PublicKey {
  return new PublicKey(
    BN254CurveWrapper.gtPow(Z, secret.first),
    BN254CurveWrapper.g2ScalarMul(g, secret.second)
  );
}
