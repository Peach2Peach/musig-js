import * as nc from 'node:crypto';
import * as tiny from 'tiny-secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { createCrypto } from '../adapters/secp256k1';

// Direct unit tests for the bundled adapter's standalone surface — the parts the
// MuSig2 protocol itself never exercises (liftX, the error branches, the sha256
// override). The protocol-level behaviour is covered by the parametrised suite
// in index.ts, which runs every test against createCrypto(tiny).

function validSecret(): Uint8Array {
  let k: Uint8Array;
  do {
    k = new Uint8Array(nc.randomBytes(32));
  } while (!tiny.isPrivate(k));
  return k;
}

describe('adapters/secp256k1 createCrypto', function () {
  const c = createCrypto(tiny);

  it('getPublicKey: pubkey for a valid scalar, null for an invalid one', function () {
    const k = validSecret();
    expect(Buffer.from(c.getPublicKey(k, true)!).toString('hex')).toBe(
      Buffer.from(tiny.pointFromScalar(k, true)!).toString('hex')
    );
    expect(c.getPublicKey(new Uint8Array(32), true)).toBeNull(); // zero scalar -> catch -> null
  });

  it('liftX: lifts a valid x-only point, returns null for a non-curve x', function () {
    const xonly = tiny.pointFromScalar(validSecret(), true)!.slice(1); // 32-byte x
    const lifted = c.liftX(xonly);
    expect(lifted).not.toBeNull();
    expect(lifted!.length).toBe(65); // uncompressed
    expect(Buffer.from(lifted!.subarray(1, 33)).toString('hex')).toBe(
      Buffer.from(xonly).toString('hex')
    );
    expect(c.liftX(new Uint8Array(32))).toBeNull(); // x = 0 is not on the curve
  });

  it('sha256: default matches @noble/hashes; an injected override is used', function () {
    const msg = Uint8Array.from([1, 2, 3]);
    expect(Buffer.from(c.sha256(msg)).toString('hex')).toBe(
      Buffer.from(sha256(msg)).toString('hex')
    );

    const sentinel = new Uint8Array(32).fill(7);
    const overridden = createCrypto(tiny, { sha256: () => sentinel });
    expect(Buffer.from(overridden.sha256(msg))).toEqual(Buffer.from(sentinel));
    // taggedHash must route through the injected sha256
    expect(Buffer.from(overridden.taggedHash('TapLeaf', msg))).toEqual(Buffer.from(sentinel));
  });
});
