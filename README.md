# RC5

RC5: https://en.wikipedia.org/wiki/RC5

implementation keep to paper: http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf


`For simplicity it is proposed here(block size) that only the values 16, 32 and 64 be "allowable"`

### Usage

```javascript

import RC5 from "rc5"

let key = "some key"

let rc5 = new RC5(key, 32, 12)
rc5.encrypt("plaintext")

```

### Disadvantages

* Number, BigInt

JavaScript has two foundamental numeral type `Number`  and `BigInt`. But none of them could used in RC5 cryption. `Number` has a biggest safe number: *2^53-1* , why this number ? Because JavaScript followed [IEEE754](https://en.wikipedia.org/wiki/IEEE_754) where specified double precision float number, in easy way, `Number` can't represent Int64 type number accurate. `BigInt` is designed for represent big nubmer, really big nubmer without any inaccuracy, but, it does't support shift operation natively.

* [U]Int8Array, [U]Int16Array, [U]Int32Array, Float64Array

all of them has same problem 

### Browser support

Recently browser does't support `Buffer` yet.
if you want use this in browser.
I recommend combined a polyfill, such as [buffer](https://www.npmjs.com/package/buffer)
