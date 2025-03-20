import { SecretKey } from "../types";
import { bn254 } from "@noble/curves/bn254";
export function generateRandomSecretKey() {
    const secret = new SecretKey(generateRandomScalar(), generateRandomScalar());
    return secret;
}
// Generate a random scalar in [0, order-1] of the BN254 curve
export function generateRandomScalar() {
    // Get the order of BN254 curve
    const order = bn254.fields.Fr.ORDER;
    // Generate a random scalar in [0, order-1]
    const scalar = BigInt(Math.floor(Math.random() * Number(order)));
    return scalar;
}
