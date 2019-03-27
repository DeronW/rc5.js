const assert = require("assert").strict;

const RC5 = require("./rc5.js");
let rc5, plain, cipher;

function parseBuf(s) {
    // "<Buffer d9 62 60 3f 8d b9 09 9f>"
    let arr = s
        .slice(8, s.length - 1)
        .split(" ")
        .map(i => "0x" + i);
    return Buffer.from(arr);
}

function equal(bufferArrayA, bufferArrayB) {
    for (let i = 0; i < bufferArrayA.length && i < bufferArrayB.length; i++) {
        if (!bufferArrayA[i] || !bufferArrayB[i]) return false;
        for (let j = 0; j < bufferArrayA[i].length && j < bufferArrayB[i].length; j++) {
            if (bufferArrayA[i][j] != bufferArrayB[i][j]) return false;
        }
    }
    return true;
}

// no key, zero rounds
rc5 = new RC5("", 16, 0);
assert.ok(equal(rc5.S, [parseBuf("<Buffer 78 65>"), parseBuf("<Buffer 33 f4>")]));

rc5 = new RC5("", 32, 0);
assert.ok(equal(rc5.S, [parseBuf("<Buffer 4d ba 7b 7a>"), parseBuf("<Buffer 1e 1d 11 79>")]));

rc5 = new RC5("", 64, 0);
assert.ok(
    equal(rc5.S, [
        parseBuf("<Buffer d9 62 60 3f 8d b9 09 9f>"),
        parseBuf("<Buffer 63 0e 0e d0 73 99 d5 d4>")
    ])
);

// normal params
rc5 = new RC5([1, 2, 3]);
let sakula = "桜";
cipher = rc5.encrypt(sakula);
plain = rc5.decrypt(cipher);
assert.ok(sakula == plain.toString());
