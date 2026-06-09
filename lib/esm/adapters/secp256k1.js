import * as baseCrypto from '../base_crypto.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
function concatBytes(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}
const utf8 = (s) => new TextEncoder().encode(s);
export function createCrypto(ecc, opts = {}) {
  const sha256 =
    opts.sha256 ??
    ((...messages) => {
      const h = nobleSha256.create();
      for (const m of messages) h.update(m);
      return h.digest();
    });
  const taggedHash = (tag, ...messages) => {
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
