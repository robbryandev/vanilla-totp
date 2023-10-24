"use strict";

import cryptoNativeModule from "./reactNative/index.js"
export const cryptoNative = cryptoNativeModule;

/**
 * Convert base32 encoded string to a buffer
 * @param {String} encoded - a base32 encoded string
 * @returns {Buffer} resulting buffer
 */
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

/**
 * Get an Hmac to use with cyphers
 * @param {Buffer} secretKey - Decoded base32 secret key
 * @param {Buffer} counter - Encoded counter for Hmac digest
 * @param {"sha1" | "sha256" | "sha512" | "md5"} algorithm - Supported openssl compatible algorithms
 * @param {*} crypto - Dependency injection for crypto module
 * @returns {Hmac}
 */
function getHmac(secretKey, counter, algorithm, crypto) {
    // Create HMAC signature from secret key and the counter value.
    // Get list of supported algorithms with openssl
    // openssl list -digest-algorithm
    return crypto.createHmac(algorithm, secretKey).update(counter).digest();
}

/**
 * Get dynamic truncation offset from hmac
 * @param {Hmac} hmac - Hmac value
 * @returns {Number}
 */
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

/**
 * Get an Hmac to use with cyphers
 * @param {String} secretKey - base32 encoded key
 * @param {Number} timestamp - Number of milliseconds since UNIX Epoch.
 * @param {"sha1" | "sha256" | "sha512" | "md5"} algorithm - Supported openssl compatible algorithms
 * @param {6 | 8} digits - Length of generated TOTP code
 * @param {15 | 30 | 60} interval - Time interval in seconds to base code generation
 * @param {*} crypto - Dependency injection for crypto module
 */
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
