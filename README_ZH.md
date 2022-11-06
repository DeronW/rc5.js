# RC5

什么是 RC5: https://baike.baidu.com/item/RC5

本软件代码实现完全遵循作者论文: http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf

## 软件用法

#### 安装

```shell
npm install rc5
```

#### 使用举例

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

## 文档

`rc5` 软件模块, 提供了基于 RC5 加密协议的算法功能. 通过 `require('rc5')` 引入该模块后, 即可使用相关方法. 使用 rc5 软件, 需要提供 3 个初始化参数

- key // 用于加密的密钥
- w // 每个加密块的大小, 单位 bit (可选大小只有 16, 32, 64 三种)
- r // 加密算法对每个数据块进行加密的轮数

使用参数创建出 RC5 加密对象的实例后, 我们就可以使用该实例进行加密或者解密.
_注意_ 被加密或被解密的数据类型应该 [Buffer](https://nodejs.org/dist/latest-v11.x/docs/api/buffer.html) 类型. 为了方便使用, _encrypt_ 方法在接收到字符串类型的参数时, 会使用 _Buffer.from_ 方法转换成字节类型, 再进行加密或者解密.

#### new RC5(key, w, r)

- key: Buffer 或 String, 用于加密或解密的密钥, 可以是字符串或字节数组类型数据, 参数的字节长度应小于 255, 默认为空.
- w: Integer, 选择一个加密数据块的大小, 只能在 [16, 32, 64] 中选择一个. 默认: 32 个比特位
- r: Integer, 对一个数据库进行加密的轮数, 加密轮数越高安全级别越高. 最大轮数为 255, 默认轮数: 12.

例子: 创建一个 `RC5` 的实例

```javascript
const RC5 = require("rc5");
let rc5; // 声明变量

// 常用参数创建的实例
rc5 = new RC5("secret key", 32, 12);

// 默认参数创建的实例, 此时密码为 ''
rc5 = new RC5();

// 高安全级别实例
rct = new RC5(Buffer.from("... a 255 bytes length key..."), 64, 255);
```

#### rc5.encrypt(plaintext)

- plaintext: Buffer | String, 需要被加密的原文
- options:
  - trim: 是否去掉结尾的 0x00，默认 **true** [原因](https://github.com/DeronW/rc5.js/issues/12)。

例子: 加密

```javascript
const RC5 = require("rc5");
const rc5 = new RC5("key");
rc5.encrypt(Buffer.from([1, 2, 3, 4, 5, 6]));
// => <Buffer fe 14 e1 42 64 2b db de>
rc5.encrypt("似水年华");
// => <Buffer d8 66 d5 3b b5 d4 91 7e c5 06 98 10 8a 63 d7 d3>
// => <Buffer 44 26 54 88 0b fa 77 f3 ff fa 69 9b d5 2a 04 2c>
```

#### rc5.decrypt(ciphertext)

- ciphertext: Buffer| String, 需要被解密的密文
- options:
  - trim: 是否自动移动结尾的空格，默认为 **true**，[查看 issue](https://github.com/DeronW/rc5.js/issues/12)。

例子: 解密

```javascript
const RC5 = require("rc5");
const rc5 = new RC5("key");
rc5.decrypt(Buffer.from([0xfe, 0x14, 0xe1, 0x42, 0x64, 0x2b, 0xdb, 0xde]));
// => <Buffer 01 02 03 04 05 06>
let buf = rc5.decrypt(
  Buffer.from([
    0x44, 0x26, 0x54, 0x88, 0x0b, 0xfa, 0x77, 0xf3, 0xff, 0xfa, 0x69, 0x9b,
    0xd5, 0x2a, 0x04, 0x2c,
  ])
);
// => <Buffer e4 bc bc e6 b0 b4 e5 b9 b4 e5 8d 8e>
buf.toString();
// => '似水年华'
```

## 文档说明

用 JavaScript 语言实现 RC5 算法的劣势

RC5 算法需要一个对称大小的基本数据块来支撑所有计算. 并且为了便于计算机运算, 一般只允许使用 16, 32 或 64 个比特位来作为一个基本数据块的大小. 这一般对应了 3 中大小的整数, 这也意味着实现 RC5 算法的预言最好能够原生支持 16, 32 和 64 位的数据类型的 加/减/位移 操作.

- Number, BigInt

JavaScript 语言中有 2 种表达整数的数据类型: `Number` 和 `BigInt`. 可惜的是, 这 2 种类型都不能够直接使用在 RC5 算法中. `Number` 类型有一个最大安全数的限制, JavaScript 的最大安全数是 _2^53-1_. 为什么 JavaScript 存在一个最大安全数? 因为 JavaScript 的整数表达方式采用了[IEEE754](https://en.wikipedia.org/wiki/IEEE_754) 协议, 一种双精度浮点数的规范. 简单来说, `Number` 不能准确表达一个大于最大安全数的整数. `BigInt` 类型是专门设计用来表示大整数的, 但可惜的是它不支持位移操作.

- [U]Int8Array, [U]Int16Array, [U]Int32Array, Float64Array

JavaScript 中其它表示整数的数据类型也都不能被应用到 RC5 算法中. 包括以上列出的数据类型, 都不能飙到 64 位无符号整型数字.
