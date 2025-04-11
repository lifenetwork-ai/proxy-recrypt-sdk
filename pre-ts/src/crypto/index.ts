export * from "./bn254";
export * from "./hdkf";
export * from "./aes-gcm";

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* istanbul ignore next */
export function getCrypto() {
  if (typeof window !== "undefined" && window.crypto) {
    // Browser environment
    return window.crypto;
  } else if (typeof global !== "undefined") {
    // Node.js environment
    try {
      const nodeCrypto = require("crypto");
      if (nodeCrypto.webcrypto) {
        return nodeCrypto.webcrypto;
      }
      const { Crypto } = require("@peculiar/webcrypto");
      return new Crypto();
    } catch (error: any) {
      throw new Error(
        "Crypto support not available. Please install @peculiar/webcrypto package." +
          error.message
      );
    }
  }
  throw new Error("No crypto implementation available in this environment");
}
