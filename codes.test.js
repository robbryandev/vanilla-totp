"use strict";

import { getTotp } from "./totp.js";
import "colors";

const secret = "JBSWY3DPEHPK3PXP";
let passed = 0;
let failed = 0;

// Test values referenced from the npm totp-generator
// https://github.com/bellstrand/totp-generator/blob/master/test/index.spec.js
const tests = [
    { time: 0, expected: "282760" },
    { time: 1465324707000, expected: "341128" },
    { time: 1665644340100, expected: "886842" },
    { time: 1665644339900, expected: "134996" }
];

tests.forEach((test) => {
    const code = getTotp(secret, test.time);
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
