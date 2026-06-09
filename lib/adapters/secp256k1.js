'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (!desc || ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.createCrypto = void 0;
const baseCrypto = __importStar(require('../base_crypto.js'));
const sha256_1 = require('@noble/hashes/sha256');
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
function createCrypto(ecc, opts = {}) {
  const sha256 =
    opts.sha256 ??
    ((...messages) => {
      const h = sha256_1.sha256.create();
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
exports.createCrypto = createCrypto;
