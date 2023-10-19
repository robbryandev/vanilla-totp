"use strict";

import cryptoNativeModule from "./reactNative/index.js"
export const cryptoNative = cryptoNativeModule;

// Convert the base32 string to a binary string
function base32Decode(encoded) {
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let binaryString = "";

    for (let i = 0; i < encoded.length; i++) {
        const char = encoded.charAt(i).toUpperCase();
        const charIndex = base32Chars.indexOf(char);
        if (charIndex !== -1) {
            binaryString += charIndex.toString(2).padStart(5, "0");
        }
    }

    // Convert the binary string to a buffer
    const bytes = [];
    for (let i = 0; i < binaryString.length; i += 8) {
        bytes.push(parseInt(binaryString.slice(i, i + 8), 2));
    }

    // Return the buffer
    return Buffer.from(bytes);
}

function getHmac(secretKey, value, algorithm, crypto) {
    // Create HMAC-SHA1 signature from secret key and the counter value.
    // Get list of supported algorithms with openssl
    // openssl list -digest-algorithm
    return crypto.createHmac(algorithm, secretKey).update(value).digest();
}

function dynamicTruncation(hmac) {
    // Code adapted from the HOTP specification https://www.ietf.org/rfc/rfc4226.txt
    // Section 5.4
    const offset = hmac[hmac.length - 1] & 0xf;
    const binCode =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return binCode;
}

export function getTotp(secretKey, timestamp = Date.now(), algorithm = "sha1", digits = 6, interval = 30, crypto) {
    // Get the interval counter from the timestamp
    const counter = Math.floor(timestamp / 1000 / interval);

    // Convert the counter to an 8-byte buffer with a 4-byte offset
    const paddedCounter = Buffer.alloc(8);
    paddedCounter.writeUInt32BE(counter, 4);

    // Generate the HMAC from the padded counter
    const hmac = getHmac(base32Decode(secretKey), paddedCounter, algorithm, crypto);

    // Truncate the HMAC to a 6-digit code
    const trunc = dynamicTruncation(hmac) % 10 ** digits;
    const code = trunc.toString().padStart(digits, "0");

    return code;
}
