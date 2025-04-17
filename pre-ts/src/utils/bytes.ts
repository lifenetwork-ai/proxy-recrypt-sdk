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

// UTF-8 encode a string to a Uint8Array
export function stringToBytes(str: string) {
  const result = [];

  for (let i = 0; i < str.length; i++) {
    const codePoint = str.codePointAt(i)!;

    // Handle Unicode code points
    // For characters that take up two JavaScript "characters", skip the next loop iteration
    if (codePoint > 0xffff) {
      i++;
    }

    // 1-byte sequence (0 to 127)
    if (codePoint <= 0x7f) {
      result.push(codePoint);
    }
    // 2-byte sequence (128 to 2047)
    else if (codePoint <= 0x7ff) {
      result.push(0xc0 | (codePoint >> 6));
      result.push(0x80 | (codePoint & 0x3f));
    }
    // 3-byte sequence (2048 to 65535)
    else if (codePoint <= 0xffff) {
      result.push(0xe0 | (codePoint >> 12));
      result.push(0x80 | ((codePoint >> 6) & 0x3f));
      result.push(0x80 | (codePoint & 0x3f));
    }
    // 4-byte sequence (65536 to 1114111)
    else {
      result.push(0xf0 | (codePoint >> 18));
      result.push(0x80 | ((codePoint >> 12) & 0x3f));
      result.push(0x80 | ((codePoint >> 6) & 0x3f));
      result.push(0x80 | (codePoint & 0x3f));
    }
  }

  return new Uint8Array(result);
}

// Decode a UTF-8 Uint8Array to a string
export function bytesToString(bytes: Uint8Array) {
  let result = "";
  let i = 0;

  while (i < bytes.length) {
    // 1-byte sequence (0 to 127)
    if (bytes[i] <= 0x7f) {
      result += String.fromCodePoint(bytes[i]);
      i++;
    }
    // 2-byte sequence
    else if ((bytes[i] & 0xe0) === 0xc0) {
      const codePoint = ((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f);
      result += String.fromCodePoint(codePoint);
      i += 2;
    }
    // 3-byte sequence
    else if ((bytes[i] & 0xf0) === 0xe0) {
      const codePoint =
        ((bytes[i] & 0x0f) << 12) |
        ((bytes[i + 1] & 0x3f) << 6) |
        (bytes[i + 2] & 0x3f);
      result += String.fromCodePoint(codePoint);
      i += 3;
    }
    // 4-byte sequence
    else if ((bytes[i] & 0xf8) === 0xf0) {
      const codePoint =
        ((bytes[i] & 0x07) << 18) |
        ((bytes[i + 1] & 0x3f) << 12) |
        ((bytes[i + 2] & 0x3f) << 6) |
        (bytes[i + 3] & 0x3f);
      result += String.fromCodePoint(codePoint);
      i += 4;
    }
    // Invalid byte - skip it
    else {
      i++;
    }
  }

  return result;
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
  // Modern browsers
  if (typeof atob === "function") {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js
  return new Uint8Array(Buffer.from(base64, "base64"));
}
