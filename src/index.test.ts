import RC5 from "./index";

test("adds 1 + 2 to equal 3", () => {
    expect(1 + 2).toBe(3);
});

function parseBuf(s: string): Buffer {
    // "<Buffer d9 62 60 3f 8d b9 09 9f>"
    let arr = s
        .slice(8, s.length - 1)
        .split(" ")
        .map((i) => "0x" + i);
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
    let rc5 = new RC5("", 16, 0);
    expect(rc5.S).toEqual([
        parseBuf("<Buffer 78 65>"),
        parseBuf("<Buffer 33 f4>"),
    ]);
});

test("w/r/b 32/0/0", () => {
    let rc5 = new RC5("", 32, 0);
    expect(rc5.S).toEqual([
        parseBuf("<Buffer 4d ba 7b 7a>"),
        parseBuf("<Buffer 1e 1d 11 79>"),
    ]);
});

test("w/r/b 64/0/0", () => {
    let rc5 = new RC5("", 64, 0);
    expect(rc5.S).toEqual([
        parseBuf("<Buffer d9 62 60 3f 8d b9 09 9f>"),
        parseBuf("<Buffer 63 0e 0e d0 73 99 d5 d4>"),
    ]);
});

test("fast encryption", () => {
    let rc5 = new RC5("key", 16, 12),
        source = "桜",
        cipher = rc5.encrypt(source),
        plain = rc5.decrypt(cipher);
    expect(source).toBe(plain.toString());
});

test("standard(default) encryption, w/r/b 32/12/0", () => {
    let rc5 = new RC5(),
        source = "桜",
        cipher = rc5.encrypt(source),
        plain = rc5.decrypt(cipher);
    expect(source).toBe(plain.toString());
});

test("complex encryption, w/r/b 64/255/x", () => {
    let rc5 = new RC5("shakespeare", 64, 255),
        source = `
    Two loves I have of comfort and despair,
    Which like two spirits do suggest me still:
    The better angel is a man right fair,
    The worser spirit a woman color’d ill.
    `,
        cipher = rc5.encrypt(source),
        plain = rc5.decrypt(cipher);
    expect(source).toBe(plain.toString());
});

test("standard with UTF8 coding", () => {
    let rc5 = new RC5("😂😂😂"),
        source = "🐁🐂🐅🐇🐉🐍🐎🐐🐒🐓🐕🐖",
        cipher = rc5.encrypt(source),
        plain = rc5.decrypt(cipher);
    expect(source).toBe(plain.toString());
});
