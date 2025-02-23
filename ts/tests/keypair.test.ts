import { loadKeyPairFromFile } from "../src/utils";
import { BN254CurveWrapper } from "../src/crypto";
import { PreSchemeImpl } from "../src/pre";
describe("KeyPair Loading", () => {
  test("should correctly load and parse a keypair file", async () => {
    // Load the keypair
    const keyPair = await loadKeyPairFromFile("tests/alice_keypair.json");

    // Test secret key values
    expect(keyPair.secretKey.first.toString(16)).toBe(
      "1b3c4f2629e642f076a6f9da84d8dba47176d88659e2027193d1a9710d790a45"
    );
    expect(keyPair.secretKey.second.toString(16)).toBe(
      "12b4bd11710ac1a327c74386d0229500352339a20bb33c685723791c700fb253"
    );
    // Test public key serialization
    const firstBytes = Buffer.from(
      BN254CurveWrapper.GTToBytes(keyPair.publicKey.first)
    );
    const secondBytes = Buffer.from(
      BN254CurveWrapper.G2ToBytes(keyPair.publicKey.second)
    );

    expect(firstBytes.toString("base64")).toBe(
      "AF/OsI1el6csnTJZ07epOCOL+nRKDJjo/p5B814seI0qQkTggOLxzjNs0iCBxA/ATvmYVoy2OKvT+xUfLgawrh//NXJ9JFMMBZtsCdGOMMDda/mW3gVqcgudYCvUW21YBR+sAy+vTabYWOF15zpge5eYekwMx/m9aE/RG2fkX2oP2KL5a1NsVml7OpFiDssib/C9bdnWYIQrIRzi3fiAOClBMioocAmaWrblAqpAiOBfN44ej01V8WPAh7hlYEWKJlZBUe0+6TmJW+K2dEEgI0HCJIzQ4K6VBAzWy2Ae9b0KQrOpypd/rwrH5DCwEggrJZHzcskav84gww34m5tztx0SEoHvap1/NFUpII+qoyp6t277+lUzCYpIsUOA4lYTCPK9mrziRzdSeU/milhxsaFSB5pBvGJKgv+b/PgECTgRJRqEuF1lRCZdwgWHQ2sPuln+UMik9SY+Ilyarb8EOCK0P9u2QCA3uLokZ8Fq2hiLlJt5jWI3SOPtqAneMFYJ"
    );
    expect(secondBytes.toString("base64")).toBe(
      "EtvW8XMRpM9xgPs7mEvtjyHSoeZf049i6UIQAdKOT3cu1HPlSRApPrfYImE6IX6jZxrUisoFM6MpdAn6Hb/rIhQ1daopaZRN0MsG3hHZ1BCiBplhVitcfcbWQZKBVMjFLgxvEEupAY8oq5ymxdEowzA7AnX4EPl+FOtDqzILTpA="
    );
  });

  test("should calculate correct rekey", async () => {
    const aliceKeyPair = await loadKeyPairFromFile("tests/alice_keypair.json");
    const bobKeyPair = await loadKeyPairFromFile("tests/bob_keypair.json");

    const preScheme = new PreSchemeImpl();

    const reKey = preScheme.generateReEncryptionKey(
      aliceKeyPair.secretKey.first,
      bobKeyPair.publicKey.second
    );

    const expectedReKey =
      "ESgWlUTPCI2RLGsOwSeXw5EEXClLWbCqbovNZptkkFEsXM1TgbJoTYJUV/JVX4RHzj+isEh0ydZxtAQ2gYUK5AvdgYs3Jrw91MVE0bpd1ppbYSeozE1vNHIw23KepLo5G30UfYysV4LKwCbWb7Gt+z7UGs1N7/9qdK6vpj0GX0w=";

    const actualReKey = Buffer.from(
      BN254CurveWrapper.G2ToBytes(reKey)
    ).toString("base64");

    expect(actualReKey).toBe(expectedReKey);
  });
});
