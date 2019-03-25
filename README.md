# RC5

Designed by http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf

For simplicity it is proposed here that only the values 16, 32 and 64 be "allowable"

### Usage

```javascript

import RC5 from "rc5"

let key = "some key"

let rc5 = new RC5(key, 32, 12)
rc5.encrypt("plaintext")


```

### Browser support

Recently browser does't support `Buffer` yet.
if you want use this in browser.
I recommend combined a polyfill, such as [buffer](https://www.npmjs.com/package/buffer)
