import RC5 from "./index";

test("adds 1 + 2 to equal 3", () => {
  expect(1 + 2).toBe(3);
});

function parseBuf(s: string): Buffer {
  // "<Buffer d9 62 60 3f 8d b9 09 9f>"
  const arr = s
    .slice(8, s.length - 1)
    .split(" ")
    .map((i) => parseInt(i, 16));
  return Buffer.from(arr);
}

test("wrong w/r/b", () => {
  expect(() => {
    new RC5(Buffer.alloc(256).toString(), 16, 0);
  }).toThrow();

  expect(() => {
    new RC5("", 16, 256);
  }).toThrow();
});

test("w/r/b 16/0/0", () => {
  const rc5 = new RC5("", 16, 0);
  expect(rc5.S).toEqual([
    parseBuf("<Buffer 78 65>"),
    parseBuf("<Buffer 33 f4>"),
  ]);
});

test("w/r/b 32/0/0", () => {
  const rc5 = new RC5("", 32, 0);
  expect(rc5.S).toEqual([
    parseBuf("<Buffer 4d ba 7b 7a>"),
    parseBuf("<Buffer 1e 1d 11 79>"),
  ]);
});

test("w/r/b 64/0/0", () => {
  const rc5 = new RC5("", 64, 0);
  expect(rc5.S).toEqual([
    parseBuf("<Buffer d9 62 60 3f 8d b9 09 9f>"),
    parseBuf("<Buffer 63 0e 0e d0 73 99 d5 d4>"),
  ]);
});

test("fast encryption", () => {
  const rc5 = new RC5("key", 16, 12),
    source = "桜",
    cipher = rc5.encrypt(source),
    plain = rc5.decrypt(cipher);
  expect(plain.toString()).toBe(source);
});

test("standard(default) encryption, w/r/b 32/12/0", () => {
  const rc5 = new RC5(),
    source = "桜",
    cipher = rc5.encrypt(source),
    plain = rc5.decrypt(cipher);
  expect(plain.toString()).toBe(source);
});

test("complex encryption, w/r/b 64/255/x", () => {
  const rc5 = new RC5("shakespeare", 64, 255),
    source = `Two loves I have of comfort and despair,
Which like two spirits do suggest me still:
The better angel is a man right fair,
The worser spirit a woman color’d ill.`,
    cipher = rc5.encrypt(source),
    plain = rc5.decrypt(cipher);
  expect(plain.toString()).toBe(source);
});

test("standard with UTF8 coding", () => {
  const rc5 = new RC5("😂😂😂"),
    source = "🐁🐂🐅🐇🐉🐍🐎🐐🐒🐓🐕🐖",
    cipher = rc5.encrypt(source),
    plain = rc5.decrypt(cipher);
  expect(plain.toString()).toBe(source);
});

test("issue: https://github.com/DeronW/rc5.js/issues/12", () => {
  const rc5 = new RC5("a key", 64, 255);
  const ptBinary = Uint8Array.from([1, 2, 3, 4, 5, 0, 0]);
  const encrypted = rc5.encrypt(Buffer.from(ptBinary));
  const decrypted = rc5.decrypt(encrypted, { trim: false });
  const decryptedBinary = new Uint8Array(decrypted);
  expect(decryptedBinary).toStrictEqual(
    Uint8Array.from([1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  );
});
