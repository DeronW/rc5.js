"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Pw, Qw are magic constants
const Pw = {
    16: Buffer.from([0xb7, 0xe1]),
    32: Buffer.from([0xb7, 0xe1, 0x51, 0x63]),
    64: Buffer.from([0xb7, 0xe1, 0x51, 0x62, 0x8a, 0xed, 0x2a, 0x6b]),
};
const Qw = {
    16: Buffer.from([0x9e, 0x37]),
    32: Buffer.from([0x9e, 0x37, 0x79, 0xb9]),
    64: Buffer.from([0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15]),
};
// Why don't I use BigInt
// https://github.com/tc39/proposal-bigint/issues/40
function add(A, B) {
    let buf = Buffer.alloc(A.length), carry = 0;
    for (let i = A.length - 1; i >= 0; i--) {
        let t = A[i] + B[i] + carry;
        carry = t > 255 ? 1 : 0;
        buf[i] = t;
    }
    return buf;
}
function minus(A, B) {
    let buf = Buffer.alloc(A.length), borrow = 0;
    for (let i = A.length - 1; i >= 0; i--) {
        let t = A[i] - B[i] - borrow;
        borrow = t < 0 ? 1 : 0;
        buf[i] = t;
    }
    return buf;
}
function assign(A, B) {
    for (let i = 0; i < A.length; i++)
        A[i] = B[i];
}
/*
 * exclusive OR funciton used for merge two buffer
 * the reason why does't use Integer same as funciton `add` or `minus`
 */
function merge(A, B, fn) {
    let buf = Buffer.alloc(A.length);
    for (let i = 0; i < A.length; i++)
        buf[i] = fn(A[i], B[i]);
    return buf;
}
let xor = (A, B) => merge(A, B, (a, b) => a ^ b);
function mod(B, n) {
    if (B.length == 8) {
        return ((B.readUInt32BE(0) % n) * Math.pow(2, 32) + B.readUInt32BE(4)) % n;
    }
    else if (B.length == 4) {
        return B.readUInt32BE(0) % n;
    }
    else {
        //  B.length == 2
        return B.readUInt16BE(0) % n;
    }
}
function rotl(B, n) {
    let buf = Buffer.alloc(B.length), templ = Buffer.concat([B, B]), index = Math.floor(n / 8), pos = n % 8;
    for (let i = 0; i < buf.length; i++) {
        let head = (Math.pow(2, (8 - pos)) - 1) & templ[index + i], tail = ((Math.pow(2, pos) - 1) << (8 - pos)) & templ[index + i + 1];
        buf[i] = (head << pos) + (tail >> (8 - pos));
    }
    return buf;
}
function rotr(B, n) {
    return rotl(B, B.length * 8 - n);
}
function expandL({ K, u, c }) {
    let L = new Array(c).fill(null), filledK = Buffer.concat([K], c * u);
    for (let i = 0; i < c; i++)
        L[i] = filledK.slice(i * u, (i + 1) * u).reverse();
    return L;
}
function expandS({ w, t }) {
    let P = Pw[w], Q = Qw[w], S = [P];
    for (let i = 1; i < t; i++)
        S.push(add(S[i - 1], Q));
    return S;
}
function mixin({ w, t, c, u }, S, L) {
    let count = Math.max(c, t) * 3, A = Buffer.alloc(u), B = Buffer.alloc(u);
    for (let k = 0, i = 0, j = 0; k < count; k++) {
        A = S[i] = rotl(add(S[i], add(A, B)), 3);
        B = L[j] = rotl(add(L[j], add(A, B)), mod(add(A, B), w));
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
    return S;
}
function encryption({ args: { r, w }, S, A, B }) {
    A = add(A, S[0]);
    B = add(B, S[1]);
    for (let i = 1; i <= r; i++) {
        A = add(rotl(xor(A, B), mod(B, w)), S[2 * i]);
        B = add(rotl(xor(B, A), mod(A, w)), S[2 * i + 1]);
    }
    return [A.reverse(), B.reverse()];
}
function decryption({ args: { r, w }, S, A, B }) {
    for (let i = r; i > 0; i--) {
        B = xor(rotr(minus(B, S[2 * i + 1]), mod(A, w)), A);
        A = xor(rotr(minus(A, S[2 * i]), mod(B, w)), B);
    }
    B = minus(B, S[1]);
    A = minus(A, S[0]);
    return [A.reverse(), B.reverse()];
}
class RC5 {
    constructor(key = "", w = 32, r = 12) {
        let K = Buffer.from(key), b = K.length; // number of bytes in key
        this.cb = { w, r, b, K };
        if (r > 255)
            throw new Error(`Parameter r must be less than 256, got ${r}`);
        if (b > 255)
            throw new Error(`Secret key is too long. must less than 255 bytes, got ${b}`);
        this.S = [];
        this.fullParams = this.initParams();
        this.expand();
    }
    initParams() {
        let { w, r, b, K } = this.cb, t = 2 * (r + 1), u = w / 8, c = Math.ceil(b / u) || 1;
        return { w, r, b, K, t, u, c };
    }
    expand() {
        let L = expandL(this.fullParams);
        let S = expandS(this.fullParams);
        mixin(this.fullParams, S, L);
        this.S = S;
    }
    parseBuffer(s) {
        let buf = Buffer.from(s), { u } = this.fullParams, u2 = u * 2, gap = (u2 - (buf.length % u2)) % u2;
        if (gap)
            buf = Buffer.concat([buf], buf.length + gap);
        return buf;
    }
    process(source, handle) {
        let buf = this.parseBuffer(source), { u, r, w } = this.fullParams;
        for (let i = 0; i < buf.length; i += 2 * u) {
            let A = buf.slice(i, i + u).reverse(), B = buf.slice(i + u, i + u * 2).reverse();
            let [newA, newB] = handle({ args: { r, w }, S: this.S, A, B });
            assign(A, newA);
            assign(B, newB);
        }
        return buf;
    }
    encrypt(plain) {
        return this.process(plain, encryption);
    }
    decrypt(cipher) {
        let filled = this.process(cipher, decryption), pos = filled.length - 1;
        while (filled[pos] == 0)
            pos--;
        return filled.slice(0, pos + 1);
    }
}
exports.default = RC5;
//# sourceMappingURL=index.js.map