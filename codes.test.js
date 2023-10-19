"use strict";

import crypto from "crypto";
import { getTotp } from "./totp.js";
import "colors";

const secret = "JBSWY3DPEHPK3PXP";
let passed = 0;
let failed = 0;

// Test values referenced from the npm totp-generator
// https://github.com/bellstrand/totp-generator/blob/master/test/index.spec.js
const tests = [
    { time: 0, digits: 6, interval: 30, expected: "282760", algorithm: "sha1" },
    { time: 1465324707000, digits: 6, interval: 30, expected: "341128", algorithm: "sha1" },
    { time: 1665644340100, digits: 6, interval: 30, expected: "886842", algorithm: "sha1" },
    { time: 1665644339900, digits: 6, interval: 30, expected: "134996", algorithm: "sha1" },
    { time: 1465324707000, digits: 8, interval: 30, expected: "43341128", algorithm: "sha1" },
    { time: 1465324707000, digits: 6, interval: 30, expected: "093730", algorithm: "sha512" },
    { time: 1465324707000, digits: 6, interval: 60, expected: "313995", algorithm: "sha1" }
];

tests.forEach((test) => {
    const code = getTotp(secret, test.time, test.algorithm, test.digits, test.interval, crypto);
    console.log(`Code: ${code}`.blue);
    console.log(`expected: ${test.expected}`.cyan);
    const pass = code === test.expected;
    if (pass) {
        console.log("Test: Passed".green);
        passed++;
    } else {
        console.log("Test: Failed".red);
    }
    console.log("\n");
});

console.log(`Pass Count: ${passed}`.green.bold);
console.log(`Fail Count: ${failed}`.red.bold);
