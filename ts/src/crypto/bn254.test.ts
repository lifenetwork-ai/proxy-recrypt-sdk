import { base64BufferToBigInt } from "../utils";
import { BN254CurveWrapper } from "./bn254";
import fs from "fs/promises";
describe("Bn254 wrapper", () => {
  test("pow", async () => {
    let Z = BN254CurveWrapper.pairing(
      BN254CurveWrapper.G1Generator(),
      BN254CurveWrapper.G2Generator()
    );

    console.log(
      "g1",
      BN254CurveWrapper.G1ToBytes(BN254CurveWrapper.G1Generator())
    );

    console.log(
      "g2",
      BN254CurveWrapper.G2ToBytes(BN254CurveWrapper.G2Generator())
    );

    const randomScalarBuffer = await fs.readFile(
      "../testdata/random_scalar.txt"
    );
    const randomScalar = base64BufferToBigInt(randomScalarBuffer);

    console.log("randomScalar", randomScalar);
    console.log("Z", BN254CurveWrapper.GTToBytes(Z));
    const result = BN254CurveWrapper.gtPow(Z, randomScalar);

    console.log("result", BN254CurveWrapper.GTToBytes(result));
  });
});
