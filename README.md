# RC5 &middot; [![Travis Status](https://travis-ci.org/DeronW/rc5.js.svg?branch=master)]

What is RC5: https://en.wikipedia.org/wiki/RC5

This implementation keep to paper: http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf

## Usage

#### installation

```shell
npm install rc5
```

#### example

```javascript
import RC5 from "rc5";

let key = "whisper";

let rc5 = new RC5(key);

// Encryption
let enBuf = rc5.encrypt("plain");
// => <Buffer 47 f1 b4 5c 8d e5 6d e3>

// Decryption
let deBuf = rc5.decrypt(enBuf);
// => <Buffer 70 6c 61 69 6e>
deBuf.toString();
// => plain
```

## Documentation

The `rc5` module provides RC-5 protocol encryption algorithm. use `require('rc5')` to access this module. to use rc5 we must create a instance of RC5 first, and provide 3 initial parameters:

- key // secret key which user selected
- w // bits size of each block
- r // round of encryption

after that, we can use instance of RC5 to encrypt or decrypt data. _NOTE_ that, encryption inputs and outputs are both should be [Buffer](https://nodejs.org/dist/latest-v11.x/docs/api/buffer.html), for convinent, _encrypt_ method accept string type parameter, and will automatically convert to Buffer, by _Buffer.from_ method.

#### new RC5(key, w, r)

- key: Buffer | String, secret key that used in encryption/decryption. length of key should less than 255 bytes. Default: ""
- w: Integer, which block size selected, w ∈ [16, 32, 64]. Default: 32
- r: Integer, how many rounds during encryption/decryption, r ∈ [0, 255] . Default: 12

Example: create `RC5` instance

```javascript
const RC5 = require("rc5");
let rc5; // instance of RC5

// create a normal instance
rc5 = new RC5("secret key", 32, 12);

// use default block size , rounds without key
rc5 = new RC5();

// use most complex secure level
rct = new RC5(Buffer.from("... a 255 bytes length key..."), 64, 255);
```

#### rc5.encrypt(plaintext)

- plaintext: Buffer | String, plain resource to be encrypted.

Example: encryption

```javascript
const RC5 = require("rc5");
const rc5 = new RC5("key");
rc5.encrypt(Buffer.from([1, 2, 3, 4, 5, 6]));
// => <Buffer fe 14 e1 42 64 2b db de>
rc5.encrypt("桜の花");
// => <Buffer d8 66 d5 3b b5 d4 91 7e c5 06 98 10 8a 63 d7 d3>
```

#### rc5.decrypt(ciphertext)

- ciphertext: Buffer| String, cipher text to be decrypted.
- options
  - trim: weather trim the tailing zero or not, default is **true**, [see issue](https://github.com/DeronW/rc5.js/issues/12).

Example: decryption

```javascript
const RC5 = require("rc5");
const rc5 = new RC5("key");
rc5.decrypt(Buffer.from([0xfe, 0x14, 0xe1, 0x42, 0x64, 0x2b, 0xdb, 0xde]));
// => <Buffer 01 02 03 04 05 06>
let buf = rc5.decrypt(
  Buffer.from([
    0xd8, 0x66, 0xd5, 0x3b, 0xb5, 0xd4, 0x91, 0x7e, 0xc5, 0x06, 0x98, 0x10,
    0x8a, 0x63, 0xd7, 0xd3,
  ])
);
// => <Buffer e6 a1 9c e3 81 ae e8 8a b1>
buf.toString();
// => '桜の花'
```

**note** rc5 is block cipher algorithm, every block has the same length, if the last block is not long enough, it will completing with `0x00`, and rc5.js will trim the tailing `0x00` by default, but maybe it's wrong because the source data is the `0x00`. In such case, you should pass set option `trim` to `false`, not finished yet! then you should calculate the correct bytes by yourself, see the example:

```javascript
// https://github.com/DeronW/rc5.js/issues/12
import RC5 from "rc5";

const rc5 = new RC5("a key", 64, 255);
const ptBinary = Uint8Array.from([1, 2, 3, 4, 5, 0, 0]);
const encrypted = rc5.encrypt(Buffer.from(ptBinary));

console.log(rc5.decrypt(encrypted));
// => <Buffer 01 02 03 04 05>

console.log(rc5.decrypt(encrypted, { trim: false }));
// => <Buffer 01 02 03 04 05 00 00 00>

// none of them is right, pick up the bytes properly
```

## Specification

of disadvantages in RC5 scenario with JavaScript.

RC5 need even size of blocks in encryption algorithm, and `For simplicity it is proposed here that only the values 16, 32 and 64 be "allowable"`, which means RC5 need a 64 bits data type, that natively support add, subtract and shift(left or right) operations.

- Number, BigInt

JavaScript has two foundamental numeral type `Number` and `BigInt`. But none of them could be used in RC5 cryption. `Number` has the biggest safe number: _2^53-1_. why this number ? Because JavaScript followed [IEEE754](https://en.wikipedia.org/wiki/IEEE_754) where specified double precision float number, in easy way, `Number` can't represent Int64 type number accurate. `BigInt` is designed for represent big nubmer, really big nubmer without any inaccuracy, but, it does't support shift operation natively.

- [U]Int8Array, [U]Int16Array, [U]Int32Array, Float64Array

None of such type could be used in RC5 cryption either. none of these type could represent UInt64 data.

all of them has same problem

#### TODO

- [x] Unit testing & 100% test coverage
- [x] Travis integrate
- [ ] Browser support
- [x] TypeScript support
