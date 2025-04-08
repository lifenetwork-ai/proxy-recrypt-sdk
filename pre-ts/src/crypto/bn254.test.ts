import { PreClient } from "../pre";
import { loadRandomScalar } from "../utils/testUtils";
import { BN254CurveWrapper } from "./bn254";
import { describe, test, expect } from "@jest/globals";

describe("Bn254 wrapper", () => {
  test("pow", async () => {
    const Z = BN254CurveWrapper.pairing(
      BN254CurveWrapper.G1Generator(),
      BN254CurveWrapper.G2Generator()
    );

    const randomScalar = await loadRandomScalar();
    const result = BN254CurveWrapper.gtPow(Z, randomScalar);
    const actualBytes = BN254CurveWrapper.GTToBytes(result);
    const scheme = new PreClient();

    const expectedBytes = BN254CurveWrapper.GTToBytes(
      BN254CurveWrapper.gtPow(scheme.Z, randomScalar)
    );
    expect(actualBytes).toEqual(expectedBytes);
  });

  test("g1 to bytes and from bytes", async () => {
    const g1 = BN254CurveWrapper.G1Generator();
    const bytes = BN254CurveWrapper.G1ToBytes(g1);
    const g1FromBytes = BN254CurveWrapper.G1FromBytes(bytes);
    expect(g1FromBytes).toEqual(g1);
  });
});
