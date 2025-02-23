import { BN254CurveWrapper } from "./bn254";

describe("Bn254 wrapper", () => {
  test("Bilinearity", () => {
    let g1Base = BN254CurveWrapper.G1Generator();
    let g2Base = BN254CurveWrapper.G2Generator();

    let randomScalar1 = BigInt(123456789);
    let randomScalar2 = BigInt(987654321);

    let g1ScalarMul1 = BN254CurveWrapper.g1ScalarMul(g1Base, randomScalar1);
    let g2ScalarMul2 = BN254CurveWrapper.g2ScalarMul(g2Base, randomScalar2);

    let pairing1 = BN254CurveWrapper.pairing(g1Base, g2Base);

    let pairing2 = BN254CurveWrapper.pairing(g1ScalarMul1, g2ScalarMul2);

    let pairingMul = BN254CurveWrapper.gtPow(
      pairing1,
      randomScalar1 * randomScalar2
    );
    expect(pairingMul).toEqual(pairing2);
  });
});
