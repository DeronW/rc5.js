/// <reference types="node" />
declare type TypedW = 16 | 32 | 64;
declare class RC5 {
    private cb;
    private fullParams;
    S: Array<Buffer>;
    constructor(key?: string, w?: TypedW, r?: number);
    private initParams;
    private expand;
    private parseBuffer;
    private process;
    encrypt(plain: string | Buffer): Buffer;
    decrypt(cipher: string | Buffer): Buffer;
}
export default RC5;
//# sourceMappingURL=index.d.ts.map