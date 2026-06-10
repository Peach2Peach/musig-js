import type { Crypto } from '../index.js';
export interface PointEcc {
    pointMultiply(p: Uint8Array, a: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointAdd(a: Uint8Array, b: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointAddScalar(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
    pointFromScalar(seckey: Uint8Array, compressed?: boolean): Uint8Array | null;
}
export interface AdapterOptions {
    sha256?: (...messages: Uint8Array[]) => Uint8Array;
}
export declare function createCrypto(ecc: PointEcc, opts?: AdapterOptions): Crypto;
