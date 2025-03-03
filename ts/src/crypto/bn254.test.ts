import { PreSchemeImpl } from "../pre";
import { loadRandomScalar } from "../utils/testUtils";
import { BN254CurveWrapper } from "./bn254";

describe("Bn254 wrapper", () => {
  test("pow", async () => {
    let Z = BN254CurveWrapper.pairing(
      BN254CurveWrapper.G1Generator(),
      BN254CurveWrapper.G2Generator()
    );

    const randomScalar = await loadRandomScalar();
    const result = BN254CurveWrapper.gtPow(Z, randomScalar);
    const actualBytes = BN254CurveWrapper.GTToBytes(result);
    const scheme = new PreSchemeImpl();

    const expectedBytes = BN254CurveWrapper.GTToBytes(
      BN254CurveWrapper.gtPow(scheme.Z, randomScalar)
    );
    expect(actualBytes).toEqual(expectedBytes);
  });
});
