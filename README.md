# MuSig2 in TypeScript

An implementation of [BIP-327: MuSig2 for BIP340-compatible multi-signatures](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki):
key aggregation, tweaking, nonce generation and aggregation, partial signing
and verification, signature aggregation, and deterministic (stateless)
signing.

It passes every official BIP-327 test vector, including all the error cases:
invalid inputs raise the error the reference implementation raises, blaming the
same participant for the same contribution.

Like [bitcoinjs/bip32](https://github.com/bitcoinjs/bip32), it does not bundle a
secp256k1 implementation: you inject one. The only runtime dependency is
`@noble/hashes`. Scalar and structural math (`base_crypto`) uses `BigInt`, so it
needs ECMAScript 2020.

## Setup

Build a `Crypto` from any tiny-secp256k1-compatible library with the bundled
adapter:

```typescript
import { MuSigFactory } from '@brandonblack/musig';
import { createCrypto } from '@brandonblack/musig/adapters/secp256k1';
import * as ecc from 'tiny-secp256k1'; // or '@bitcoinerlab/secp256k1' (pure JS)

const musig = MuSigFactory(createCrypto(ecc));
```

Or implement the `Crypto` interface yourself; `test/utils.ts` has two examples.

## Signing with two rounds

Public keys are 33-byte compressed points. Any `Uint8Array` works; `Buffer` is
not required.

```typescript
import { randomBytes } from 'node:crypto';

// The order of the keys is part of the aggregate key. keySort gives a canonical one.
const publicKeys = musig.keySort([alice.publicKey, bob.publicKey]);
const aggregateKey = musig.getXOnlyPubkey(musig.keyAgg(publicKeys));
const msg = transactionHash; // any length; most commonly 32 bytes

// Round 1: every signer makes a nonce and shares only the public nonce.
const aliceNonce = musig.nonceGen({
  sessionId: randomBytes(32), // must never repeat
  secretKey: alice.secretKey,
  publicKey: alice.publicKey,
  xOnlyPublicKey: aggregateKey,
  msg,
});
const bobNonce = musig.nonceGen({ sessionId: randomBytes(32), secretKey: bob.secretKey, publicKey: bob.publicKey });
const aggNonce = musig.nonceAgg([aliceNonce, bobNonce]);

// Round 2: every signer starts the same session and signs exactly once.
const session = musig.startSigningSession(aggNonce, msg, publicKeys);
const aliceSig = musig.partialSign({ secretKey: alice.secretKey, publicNonce: aliceNonce, sessionKey: session });
const bobSig = musig.partialSign({ secretKey: bob.secretKey, publicNonce: bobNonce, sessionKey: session });

// Check each partial signature before aggregating: a bad one would otherwise
// only show up as an invalid final signature, with no way to tell who sent it.
musig.partialVerify({ sig: bobSig, publicKey: bob.publicKey, publicNonce: bobNonce, sessionKey: session }); // true

const signature = musig.signAgg([aliceSig, bobSig], session);
ecc.verifySchnorr(msg, aggregateKey, signature); // true
```

### Tweaks (e.g. taproot)

Pass tweaks to `keyAgg` and `startSigningSession`. For a taproot key-path spend
of an output with a script tree, the tweak is BIP-341's
`tagged_hash("TapTweak", internalKey || merkleRoot)`, applied x-only:

```typescript
const tweak = { tweak: tapTweak, xOnly: true };
const outputKey = musig.getXOnlyPubkey(musig.keyAgg(publicKeys, tweak));
const session = musig.startSigningSession(aggNonce, msg, publicKeys, tweak);
```

## Signing in one round: deterministic signing

A signer that contributes its nonce **last**, after every other nonce is fixed,
can sign in a single step without keeping any nonce state:

```typescript
const aggOtherNonce = musig.nonceAgg([aliceNonce]); // every other signer's public nonce
const { publicNonce, sig } = musig.deterministicSign({
  secretKey: bob.secretKey,
  aggOtherNonce,
  publicKeys,
  tweaks: [tweak],
  msg,
  rand: randomBytes(32), // strongly recommended, see below
});
// Send publicNonce and sig back. Alice then signs with her stored nonce and aggregates.
```

This is only safe when the deterministic signer really is last. `rand` mixes
fresh randomness into the nonce; without it the nonce depends only on the
inputs, which leaves the signer more exposed to fault attacks.

`deterministicNonceGen` returns just the public nonce, for a signer that wants to
publish its nonce first and sign later with the same arguments.

## Nonces

Reusing a secret nonce for two different messages reveals the secret key.

- `nonceGen` keeps the secret nonce in an in-memory cache keyed by the public
  nonce object, and `partialSign` deletes it before anything else can fail, so
  a nonce cannot be used twice within a process.
- `nonceGenExtractable` also returns the 97-byte secret nonce, for signers that
  must persist it between rounds. Store it like a private key, and erase it
  before or as you sign.
- `addExternalNonce` puts a stored secret nonce back into the cache. It refuses
  a secret nonce with out-of-range values, or one that does not produce the
  given public nonce.

## Errors

Invalid input from another participant throws an `InvalidContributionError`,
BIP-327's way of saying who to hold accountable:

```typescript
import { InvalidContributionError } from '@brandonblack/musig';

try {
  musig.nonceAgg(publicNonces);
} catch (e) {
  if (e instanceof InvalidContributionError) {
    e.signer; // index of the signer at fault, or null for the aggregator
    e.contrib; // 'pubkey' | 'pubnonce' | 'aggnonce' | 'aggothernonce' | 'psig'
  }
}
```

| Thrown by | When | Error |
| --- | --- | --- |
| `keyAgg`, `startSigningSession`, `deterministicSign` | public key `i` is not a valid compressed point | `InvalidContributionError(i, 'pubkey')` |
| `nonceAgg` | public nonce `i` is invalid | `InvalidContributionError(i, 'pubnonce')` |
| `partialVerify` | the signer's public nonce is invalid | `InvalidContributionError(signer, 'pubnonce')` |
| `startSigningSession` | the aggregate nonce is invalid | `InvalidContributionError(null, 'aggnonce')` |
| `deterministicSign` | `aggOtherNonce` is invalid | `InvalidContributionError(null, 'aggothernonce')` |
| `signAgg` | partial signature `i` is not less than n | `InvalidContributionError(i, 'psig')` |

Invalid values of your own throw an `Error` with the reference implementation's
message, for example `The tweak must be less than n.`, `first secnonce value is
out of range.`, or `The signer's pubkey must be included in the list of pubkeys.`
Wrong lengths throw a `TypeError`.

`partialVerify` returns `false`, rather than throwing, for a signature that does
not verify, including one that is not less than n.

## Security notes

- This is alpha software. Review it before trusting it with funds.
- JavaScript cannot guarantee constant-time arithmetic. `BigInt` scalar
  operations on secrets may leak timing information to a local attacker.
- Validation is explicit: public keys and nonces are checked against the curve
  equation in `base_crypto`, not left to the injected point-math backend.
- Always verify other signers' partial signatures before aggregating.

## Development

```shell
npm ci
npm test       # format check, lint, build, and the full test suite with coverage
npm run bench
```

The test suite runs every test, including the BIP-327 vectors in
`test/bip-vectors/`, against three backends: noble, tiny-secp256k1, and the
bundled adapter. Update the vectors from
[bitcoin/bips](https://github.com/bitcoin/bips/tree/master/bip-0327/vectors).

`lib/` is committed so the package can be installed straight from git; rebuild
it with `npm run build` before committing source changes.
