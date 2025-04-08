// Helper function to convert hex string to Uint8Array
export function hexToBytes(hex: string) {
  // Make sure the hex string has an even length
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }

  const result = new Uint8Array(hex.length / 2);
  const chunkSize = 10000; // Process 5000 bytes (10000 hex chars) at a time

  for (let i = 0; i < hex.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, hex.length);
    const chunk = hex.substring(i, end);

    for (let j = 0; j < chunk.length; j += 2) {
      const byteIndex = (i + j) / 2;
      result[byteIndex] = parseInt(chunk.substring(j, j + 2), 16);
    }
  }

  return result;
}

// Convert byte array to hex string with chunking
export function bytesToHex(bytes: Uint8Array) {
  let result = "";
  const chunkSize = 5000; // Process 5000 bytes at a time

  for (let i = 0; i < bytes.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, bytes.length);
    let chunkResult = "";

    for (let j = i; j < end; j++) {
      const hex = bytes[j].toString(16).padStart(2, "0");
      chunkResult += hex;
    }

    result += chunkResult;
  }

  return result;
}

// Helper function to convert a utf-8 string to Uint8Array
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Helper function to convert Uint8Array to a utf-8 string
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Helper function to convert Uint8Array to base64 string
export function bytesToBase64(bytes: Uint8Array): string {
  // Modern browsers
  if (typeof btoa === "function") {
    const binary = Array.from(bytes)
      .map((b) => String.fromCharCode(b))
      .join("");
    return btoa(binary);
  }
  // Node.js
  return Buffer.from(bytes).toString("base64");
}

// Helper function to convert base64 string to Uint8Array
export function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
