// Ready-made `Crypto` adapter for any tiny-secp256k1-compatible implementation
// (tiny-secp256k1, @bitcoinerlab/secp256k1, ...). Scalar/structural math comes
// from the bundled base_crypto; point math from the injected `ecc`; hashing from
// @noble/hashes by default (override via opts.sha256 for platform-native hashes).
//
// This keeps the core library bring-your-own-crypto: importing it is opt-in, and
// the secp256k1 implementation is injected by the caller (so the same adapter
// works with whichever lib a project already depends on).
import * as baseCrypto from '../base_crypto.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import type { Crypto } from '../index.js';

// The subset of the tiny-secp256k1 API the adapter needs. Both `tiny-secp256k1`
// and `@bitcoinerlab/secp256k1` implement this identically.
export interface PointEcc {
  pointMultiply(p: Uint8Array, a: Uint8Array, compressed?: boolean): Uint8Array | null;
  pointAdd(a: Uint8Array, b: Uint8Array, compressed?: boolean): Uint8Array | null;
  pointAddScalar(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
  pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
  pointFromScalar(seckey: Uint8Array, compressed?: boolean): Uint8Array | null;
}

export interface AdapterOptions {
  // Override the hash function (e.g. a platform-native sha256). Must be a real
  // SHA-256. Defaults to @noble/hashes (pure JS; works in Node, browser, RN).
  sha256?: (...messages: Uint8Array[]) => Uint8Array;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * Build a musig-js `Crypto` from a tiny-secp256k1-compatible `ecc`.
 *
 *   import * as ecc from 'tiny-secp256k1';           // or @bitcoinerlab/secp256k1
 *   const musig = MuSigFactory(createCrypto(ecc));
 */
export function createCrypto(ecc: PointEcc, opts: AdapterOptions = {}): Crypto {
  const sha256 =
    opts.sha256 ??
    ((...messages: Uint8Array[]): Uint8Array => {
      const h = nobleSha256.create();
      for (const m of messages) h.update(m);
      return h.digest();
    });

  const taggedHash = (tag: string, ...messages: Uint8Array[]): Uint8Array => {
    const tagHash = sha256(utf8(tag));
    return sha256(tagHash, tagHash, ...messages);
  };

  return {
    ...baseCrypto,
    pointMultiplyUnsafe: (p, a, compress) => ecc.pointMultiply(p, a, compress),
    pointMultiplyAndAddUnsafe: (p1, a, p2, compress) => {
      const p1a = ecc.pointMultiply(p1, a, false);
      return p1a === null ? null : ecc.pointAdd(p1a, p2, compress);
    },
    pointAdd: (a, b, compress) => ecc.pointAdd(a, b, compress),
    pointAddTweak: (p, tweak, compress) => ecc.pointAddScalar(p, tweak, compress),
    pointCompress: (p, compress = true) => ecc.pointCompress(p, compress),
    liftX: (p) => {
      try {
        return ecc.pointCompress(concatBytes(Uint8Array.of(2), p), false);
      } catch {
        return null;
      }
    },
    getPublicKey: (s, compress) => {
      try {
        return ecc.pointFromScalar(s, compress);
      } catch {
        return null;
      }
    },
    taggedHash,
    sha256,
  };
}
