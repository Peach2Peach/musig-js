import * as nc from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { hashToPrivateScalar } from '@noble/curves/abstract/modular';
import { numberToBytesBE } from '@noble/curves/abstract/utils';
import { InvalidContributionError, KeyGenContext, MuSigFactory, SessionKey } from '../index';
import { nobleCrypto, tinyCrypto } from './utils';
import * as tinyEcc from 'tiny-secp256k1';
import { createCrypto } from '../adapters/secp256k1';
import * as det_sign_vectors from './bip-vectors/det_sign_vectors.json';
import * as key_sort_vectors from './bip-vectors/key_sort_vectors.json';
import * as nonce_gen_vectors from './bip-vectors/nonce_gen_vectors.json';
import * as sign_verify_vectors from './bip-vectors/sign_verify_vectors.json';
import * as key_agg_vectors from './bip-vectors/key_agg_vectors.json';
import * as nonce_agg_vectors from './bip-vectors/nonce_agg_vectors.json';
import * as sig_agg_vectors from './bip-vectors/sig_agg_vectors.json';
import * as tweak_vectors from './bip-vectors/tweak_vectors.json';

interface Signer {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicNonce?: Uint8Array;
  sig?: Uint8Array;
}
function randomBytes(n = 32): Uint8Array {
  const ret = new Uint8Array(n);
  nc.randomFillSync(ret);
  return ret;
}
function randomPrivateKey(): Uint8Array {
  const rand = randomBytes(secp256k1.CURVE.Fp.BYTES + 8);
  const d = hashToPrivateScalar(rand, secp256k1.CURVE.n);
  return numberToBytesBE(d, secp256k1.CURVE.Fp.BYTES);
}

const validPub = secp256k1.getPublicKey(randomPrivateKey(), true);
const invalidPub = Buffer.from(
  '02a02b2026e3b9c3842684d892cd8cf3a30530c21ec6d75d1d03ed9f4f536af692',
  'hex'
);
const invalidPoint = Buffer.from(
  '0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);
const notSecret = Buffer.from(
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'hex'
);
const validTweak = randomPrivateKey();

interface BipError {
  type: string;
  signer?: number | null;
  contrib?: string;
  message?: string;
}

/**
 * Asserts that `attempt` throws exactly what a BIP327 vector expects: an
 * InvalidContributionError blaming the same signer for the same contribution,
 * or an error with the reference implementation's message.
 */
function expectBipError(attempt: () => unknown, expected: BipError): void {
  let thrown: unknown;
  try {
    attempt();
  } catch (e) {
    thrown = e;
  }
  if (thrown === undefined) throw new Error('Expected an error, but none was thrown');
  if (expected.type === 'invalid_contribution') {
    expect(thrown).toBeInstanceOf(InvalidContributionError);
    const { signer, contrib } = thrown as InvalidContributionError;
    expect({ signer, contrib }).toEqual({ signer: expected.signer, contrib: expected.contrib });
  } else {
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe(expected.message);
  }
}

const nonceArgs = {
  sessionId: Buffer.from(nonce_gen_vectors.test_cases[0].rand_, 'hex'),
  secretKey: Buffer.from(nonce_gen_vectors.test_cases[0].sk || '', 'hex'),
  publicKey: Buffer.from(nonce_gen_vectors.test_cases[0].pk || '', 'hex'),
  msg: Buffer.from(nonce_gen_vectors.test_cases[0].msg || '', 'hex'),
  aggregatePublicKey: Buffer.from(nonce_gen_vectors.test_cases[0].aggpk || '', 'hex'),
  extraInput: Buffer.from(nonce_gen_vectors.test_cases[0].extra_in || '', 'hex'),
};

const tweaks = new Array(5).fill(0).map((_, i) => {
  const tweak = randomPrivateKey();
  return { tweak, xOnly: (tweak[i] & 1) === 1 };
});
const cryptos = [
  { cryptoName: 'noble', crypto: nobleCrypto },
  { cryptoName: 'tiny', crypto: tinyCrypto },
  // The shipped adapter (adapters/secp256k1) fed the same tiny-secp256k1 ecc —
  // validates it against every test incl. the BIP327 vectors.
  { cryptoName: 'adapter', crypto: createCrypto(tinyEcc) },
];

for (const { cryptoName, crypto } of cryptos) {
  describe(cryptoName, function () {
    const musig = MuSigFactory(crypto);

    for (let nSigners = 1; nSigners < 5; nSigners++)
      describe(`random musig(${nSigners})`, function () {
        let keyGenContext: KeyGenContext;
        let signers: Signer[] = [];
        let msg = randomBytes();
        let aggNonce: Uint8Array;
        let sessionKey: SessionKey;
        let sig: Uint8Array;

        beforeAll(function () {
          for (let i = 0; i < nSigners; i++) {
            const secretKey = randomPrivateKey();
            const publicKey = secp256k1.getPublicKey(secretKey, true);
            signers.push({ secretKey, publicKey });
          }
        });

        it('aggregates keys', function () {
          keyGenContext = musig.keyAgg(signers.map(({ publicKey }) => publicKey));
        });

        for (let i = -1; i < tweaks.length; i++) {
          describe(`tweak(${i})`, function () {
            if (i >= 0) {
              it('tweaks a key', function () {
                keyGenContext = musig.addTweaks(keyGenContext, ...tweaks.slice(i, i + 1));
              });
            }

            it('makes nonces', function () {
              const publicKey = musig.getXOnlyPubkey(keyGenContext);
              for (let j = 0; j < signers.length; j++) {
                const signer = signers[j];
                switch (j) {
                  case 1:
                    const sessionId = new Uint8Array(32);
                    sessionId[31] = nSigners;
                    signer.publicNonce = musig.nonceGen({
                      sessionId,
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                    });
                    break;
                  case 2:
                    signer.publicNonce = musig.nonceGen({
                      sessionId: randomBytes(),
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                    });
                    break;
                  case 3:
                    signer.publicNonce = musig.nonceGen({
                      sessionId: randomBytes(),
                      secretKey: signer.secretKey,
                      publicKey: signer.publicKey,
                      msg,
                      xOnlyPublicKey: publicKey,
                      extraInput: randomBytes(),
                    });
                    break;
                  default:
                    signer.publicNonce = musig.nonceGen({
                      publicKey: signer.publicKey,
                    });
                    break;
                }
              }
            });

            it('aggregates nonces', function () {
              aggNonce = musig.nonceAgg(signers.map(({ publicNonce }) => publicNonce!));
            });

            it('starts a signing sesion', function () {
              sessionKey = musig.startSigningSession(
                aggNonce,
                msg,
                signers.map(({ publicKey }) => publicKey),
                ...tweaks.slice(0, i + 1)
              );
            });

            it(`makes partial sigs ${signers.length % 2 === 1 ? 'w/verify' : ''}`, function () {
              for (const signer of signers) {
                const sig = musig.partialSign({
                  secretKey: signer.secretKey,
                  publicNonce: signer.publicNonce!,
                  sessionKey,
                  verify: signers.length % 2 === 1,
                });
                signer.sig = sig;
              }
            });

            it(`verifies partial sigs`, function () {
              for (const signer of signers) {
                const result = musig.partialVerify({
                  sig: signer.sig!,
                  publicKey: signer.publicKey,
                  publicNonce: signer.publicNonce!,
                  sessionKey,
                });
                if (!result) throw new Error('Expected result to be truthy');
              }
            });

            it('aggregates sigs', function () {
              sig = musig.signAgg(
                signers.map(({ sig }) => sig!),
                sessionKey
              );
            });

            it('verifies sig', function () {
              const publicKey = musig.getXOnlyPubkey(keyGenContext);
              expect(schnorr.verify(sig, msg, publicKey)).toBe(true);
            });
          });
        }
      });

    describe('keySort vectors', function () {
      it('sorts keys', function () {
        const sorted = musig.keySort(key_sort_vectors.pubkeys.map((k) => Buffer.from(k, 'hex')));
        expect(sorted.map((k) => Buffer.from(k).toString('hex'))).toEqual(
          key_sort_vectors.sorted_pubkeys.map((k) => k.toLowerCase())
        );
      });
    });

    describe('keyAgg vectors', function () {
      const { pubkeys, tweaks, valid_test_cases, error_test_cases } = key_agg_vectors;
      valid_test_cases.forEach(({ key_indices, expected }, index) => {
        it(`aggregates keys ${index}`, function () {
          const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
          const keyGenContext = musig.keyAgg(publicKeys);
          const actual = musig.getXOnlyPubkey(keyGenContext);
          expect(Buffer.from(actual).toString('hex')).toBe(expected.toLowerCase());
        });
      });

      // (These used to call jasmine's `fail()`, which jest-circus does not
      // define: the ReferenceError it threw was caught by the test itself, so
      // the cases could never fail.)
      error_test_cases.forEach(
        ({ key_indices, tweak_indices, is_xonly, error, comment }, index) => {
          it(`fails to aggregate keys ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            // is_xonly lines up with tweak_indices by position.
            const tweaksI = tweak_indices.map((i, k) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[k],
            }));
            expectBipError(() => musig.keyAgg(publicKeys, ...tweaksI), error);
          });
        }
      );
    });

    describe('tweak vectors', function () {
      const {
        sk,
        pubkeys,
        secnonce,
        pnonces,
        aggnonce,
        tweaks,
        msg,
        valid_test_cases,
        error_test_cases,
      } = tweak_vectors;

      valid_test_cases.forEach(
        (
          { key_indices, nonce_indices, tweak_indices, is_xonly, signer_index, comment, expected },
          index
        ) => {
          it(`tweaks and signs ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i, k) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[k],
            }));

            const message = Buffer.from(msg, 'hex');
            const nonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
            const aggNonce = musig.nonceAgg(nonces);
            expect(Buffer.from(aggNonce).toString('hex')).toBe(aggnonce.toLowerCase());
            const secNonce = Buffer.from(secnonce, 'hex');
            const sessionKey = musig.startSigningSession(aggNonce, message, publicKeys, ...tweaksI);
            musig.addExternalNonce(nonces[signer_index], Buffer.from(secnonce, 'hex'));
            const sig = musig.partialSign({
              secretKey: Buffer.from(sk, 'hex'),
              publicNonce: nonces[signer_index],
              sessionKey,
              verify: false,
            });
            expect(Buffer.from(sig).toString('hex')).toBe(expected.toLowerCase());

            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce: nonces[signer_index],
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );

      error_test_cases.forEach(
        ({ key_indices, tweak_indices, is_xonly, error, comment }, index) => {
          it(`fails to tweak key ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i, k) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[k],
            }));
            expectBipError(() => musig.keyAgg(publicKeys, ...tweaksI), error);
          });
        }
      );
    });

    describe('nonceGen vectors', function () {
      nonce_gen_vectors.test_cases.forEach(
        ({ rand_, sk, pk, aggpk, msg, extra_in, expected_pubnonce }, index) => {
          it(`generates nonces ${index}`, function () {
            const args = {
              sessionId: Buffer.from(rand_, 'hex'),
              secretKey: sk === null ? undefined : Buffer.from(sk, 'hex'),
              publicKey: Buffer.from(pk, 'hex'),
              xOnlyPublicKey: aggpk === null ? undefined : Buffer.from(aggpk, 'hex'),
              msg: msg === null ? undefined : Buffer.from(msg, 'hex'),
              extraInput: extra_in === null ? undefined : Buffer.from(extra_in, 'hex'),
            };
            const publicNonce = musig.nonceGen(args);
            expect(Buffer.from(publicNonce).toString('hex')).toBe(expected_pubnonce.toLowerCase());
          });
        }
      );
    });

    describe('nonceGenExtractable', function () {
      nonce_gen_vectors.test_cases.forEach(
        ({ rand_, sk, pk, aggpk, msg, extra_in, expected_secnonce, expected_pubnonce }, index) => {
          it(`returns the secret nonce matching BIP327 vector ${index}`, function () {
            const args = {
              sessionId: Buffer.from(rand_, 'hex'),
              secretKey: sk === null ? undefined : Buffer.from(sk, 'hex'),
              publicKey: Buffer.from(pk, 'hex'),
              xOnlyPublicKey: aggpk === null ? undefined : Buffer.from(aggpk, 'hex'),
              msg: msg === null ? undefined : Buffer.from(msg, 'hex'),
              extraInput: extra_in === null ? undefined : Buffer.from(extra_in, 'hex'),
            };
            const { publicNonce, secretNonce } = musig.nonceGenExtractable(args);
            // secret nonce layout, as in BIP327: k1(32) || k2(32) || publicKey(33)
            expect(Buffer.from(secretNonce).toString('hex')).toBe(expected_secnonce.toLowerCase());
            expect(Buffer.from(publicNonce).toString('hex')).toBe(expected_pubnonce.toLowerCase());
            // publicNonce must equal what nonceGen produces for identical args
            expect(Buffer.from(publicNonce).toString('hex')).toBe(
              Buffer.from(musig.nonceGen(args)).toString('hex')
            );
            // public nonce halves must be k1*G and k2*G
            const r1 = secp256k1.getPublicKey(secretNonce.subarray(0, 32), true);
            const r2 = secp256k1.getPublicKey(secretNonce.subarray(32, 64), true);
            expect(Buffer.from(publicNonce.subarray(0, 33)).toString('hex')).toBe(
              Buffer.from(r1).toString('hex')
            );
            expect(Buffer.from(publicNonce.subarray(33)).toString('hex')).toBe(
              Buffer.from(r2).toString('hex')
            );
          });
        }
      );
    });

    describe('nonceAgg vectors', function () {
      const { pnonces, valid_test_cases, error_test_cases } = nonce_agg_vectors;
      valid_test_cases.forEach(({ pnonce_indices, expected, comment }, index) => {
        it(`aggregatesNonces ${index} "${comment || ''}"`, function () {
          const nonces = pnonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
          const aggNonce = musig.nonceAgg(nonces);
          expect(Buffer.from(aggNonce).toString('hex')).toBe(expected.toLowerCase());
        });
      });

      error_test_cases.forEach(({ pnonce_indices, error, comment }, index) => {
        it(`fails to aggregate nonces ${index} "${comment || ''}"`, function () {
          const nonces = pnonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
          expectBipError(() => musig.nonceAgg(nonces), error);
        });
      });
    });

    describe('sign vectors', function () {
      const {
        sk,
        pubkeys,
        secnonces,
        pnonces,
        aggnonces,
        msgs,
        valid_test_cases,
        sign_error_test_cases,
        verify_fail_test_cases,
        verify_error_test_cases,
      } = sign_verify_vectors;

      it('checks public key', function () {
        const publicKey = secp256k1.getPublicKey(sk, true);
        expect(Buffer.from(publicKey).toString('hex')).toEqual(pubkeys[0].toLowerCase());
      });

      valid_test_cases.forEach(
        (
          {
            key_indices,
            nonce_indices,
            aggnonce_index,
            msg_index,
            signer_index,
            expected,
            comment,
          },
          index
        ) => {
          it(`partial signs ${index} "${comment || ''}"`, function () {
            const publicKeys: Uint8Array[] = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const pubNonces: Uint8Array[] = nonce_indices.map((i) =>
              Buffer.from(pnonces[i], 'hex')
            );

            const aggNonce = musig.nonceAgg(pubNonces);
            expect(Buffer.from(aggNonce).toString('hex')).toEqual(
              aggnonces[aggnonce_index].toLowerCase()
            );

            const msg = Buffer.from(msgs[msg_index], 'hex');

            const sessionKey = musig.startSigningSession(aggNonce, msg, publicKeys);
            musig.addExternalNonce(pubNonces[signer_index], Buffer.from(secnonces[0], 'hex'));
            const sig = musig.partialSign({
              secretKey: Buffer.from(sk, 'hex'),
              publicNonce: pubNonces[signer_index],
              sessionKey,
              verify: false,
            });

            expect(Buffer.from(sig).toString('hex')).toBe(expected.toLowerCase());

            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce: pubNonces[signer_index],
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );

      sign_error_test_cases.forEach(
        ({ key_indices, aggnonce_index, msg_index, secnonce_index, error, comment }, index) => {
          it(`fails to partial sign ${index} "${comment || ''}"`, function () {
            const attempt = () => {
              const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
              const sessionKey = musig.startSigningSession(
                Buffer.from(aggnonces[aggnonce_index], 'hex'),
                Buffer.from(msgs[msg_index], 'hex'),
                publicKeys
              );
              // pnonces[0] is the signer's public nonce, matching secnonces[0].
              const publicNonce = Buffer.from(pnonces[0], 'hex');
              musig.addExternalNonce(publicNonce, Buffer.from(secnonces[secnonce_index], 'hex'));
              return musig.partialSign({
                secretKey: Buffer.from(sk, 'hex'),
                publicNonce,
                sessionKey,
                verify: false,
              });
            };
            expectBipError(attempt, error);
          });
        }
      );

      verify_fail_test_cases.forEach(
        ({ sig, key_indices, nonce_indices, msg_index, signer_index, comment }, index) => {
          it(`rejects partial signature ${index} "${comment || ''}"`, function () {
            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const pubNonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
            const sessionKey = musig.startSigningSession(
              musig.nonceAgg(pubNonces),
              Buffer.from(msgs[msg_index], 'hex'),
              publicKeys
            );
            const result = musig.partialVerify({
              sig: Buffer.from(sig, 'hex'),
              publicKey: publicKeys[signer_index],
              publicNonce: pubNonces[signer_index],
              sessionKey,
            });
            expect(result).toBe(false);
          });
        }
      );

      verify_error_test_cases.forEach(
        ({ sig, key_indices, nonce_indices, msg_index, signer_index, error, comment }, index) => {
          it(`fails to verify partial signature ${index} "${comment || ''}"`, function () {
            expectBipError(() => {
              const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
              const pubNonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
              const sessionKey = musig.startSigningSession(
                Buffer.from(aggnonces[0], 'hex'),
                Buffer.from(msgs[msg_index], 'hex'),
                publicKeys
              );
              return musig.partialVerify({
                sig: Buffer.from(sig, 'hex'),
                publicKey: publicKeys[signer_index],
                publicNonce: pubNonces[signer_index],
                sessionKey,
              });
            }, error);
          });
        }
      );
    });

    describe('deterministic sign vectors', function () {
      const { sk, pubkeys, msgs, valid_test_cases, error_test_cases } = det_sign_vectors;

      const secretKey = Buffer.from(sk, 'hex');
      let publicKey: Uint8Array;

      it('checks public key', function () {
        publicKey = secp256k1.getPublicKey(secretKey, true);
        expect(Buffer.from(publicKey).toString('hex')).toEqual(pubkeys[0].toLowerCase());
      });

      valid_test_cases.forEach(
        (
          {
            rand,
            aggothernonce,
            key_indices,
            tweaks,
            is_xonly,
            msg_index,
            signer_index,
            expected,
            comment,
          },
          index
        ) => {
          const message = Buffer.from(msgs[msg_index], 'hex');
          const aggOtherNonce = Buffer.from(aggothernonce, 'hex');
          const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
          const tweaksI = tweaks.map((t, i) => ({
            tweak: Buffer.from(t, 'hex'),
            xOnly: is_xonly[i],
          }));

          let nonce: { publicNonce: Uint8Array };

          it(`generates nonce only ${index} "${comment || ''}"`, function () {
            nonce = musig.deterministicNonceGen({
              secretKey,
              aggOtherNonce,
              publicKeys,
              tweaks: tweaksI,
              msg: message,
              rand: rand === null ? undefined : Buffer.from(rand, 'hex'),
            });

            expect(Buffer.from(nonce.publicNonce).toString('hex')).toBe(expected[0].toLowerCase());
          });

          it(`signs ${index} "${comment || ''}"`, function () {
            const { sig, publicNonce, sessionKey } = musig.deterministicSign({
              secretKey,
              aggOtherNonce,
              publicKeys,
              tweaks: tweaksI,
              msg: message,
              rand: rand === null ? undefined : Buffer.from(rand, 'hex'),
              verify: false,
            });

            expect(Buffer.from(publicNonce).toString('hex')).toBe(expected[0].toLowerCase());

            if (sig === undefined) throw new Error('Expected sig');
            expect(Buffer.from(sig).toString('hex')).toBe(expected[1].toLowerCase());

            if (sessionKey === undefined) throw new Error('Expected sessionKey');
            const result = musig.partialVerify({
              sig,
              publicKey: publicKeys[signer_index],
              publicNonce,
              sessionKey,
            });
            expect(result).toBeTruthy();
          });
        }
      );

      error_test_cases.forEach(
        (
          { rand, aggothernonce, key_indices, tweaks, is_xonly, msg_index, error, comment },
          index
        ) => {
          const args = () => ({
            secretKey,
            aggOtherNonce: Buffer.from(aggothernonce, 'hex'),
            publicKeys: key_indices.map((i) => Buffer.from(pubkeys[i], 'hex')),
            tweaks: tweaks.map((t, i) => ({ tweak: Buffer.from(t, 'hex'), xOnly: is_xonly[i] })),
            msg: Buffer.from(msgs[msg_index], 'hex'),
            rand: rand === null ? undefined : Buffer.from(rand, 'hex'),
          });
          it(`fails to sign deterministically ${index} "${comment || ''}"`, function () {
            expectBipError(() => musig.deterministicSign({ ...args(), verify: false }), error);
          });

          it(`fails to generate a deterministic nonce ${index} "${comment || ''}"`, function () {
            expectBipError(() => musig.deterministicNonceGen(args()), error);
          });
        }
      );
    });

    describe('sig agg vectors', function () {
      const { pubkeys, pnonces, tweaks, psigs, msg, valid_test_cases, error_test_cases } =
        sig_agg_vectors;
      const message = Buffer.from(msg, 'hex');
      valid_test_cases.forEach(
        (
          { aggnonce, nonce_indices, key_indices, tweak_indices, is_xonly, psig_indices, expected },
          index
        ) => {
          it(`aggregates signatures ${index}`, function () {
            const pubNonces = nonce_indices.map((i) => Buffer.from(pnonces[i], 'hex'));
            const aggNonce = musig.nonceAgg(pubNonces);
            expect(Buffer.from(aggNonce).toString('hex')).toEqual(aggnonce.toLowerCase());

            const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
            const tweaksI = tweak_indices.map((i, k) => ({
              tweak: Buffer.from(tweaks[i], 'hex'),
              xOnly: is_xonly[k],
            }));
            const partialSigs = psig_indices.map((i) => Buffer.from(psigs[i], 'hex'));

            const sessionKey = musig.startSigningSession(aggNonce, message, publicKeys, ...tweaksI);
            const sig = musig.signAgg(partialSigs, sessionKey);

            expect(Buffer.from(sig).toString('hex')).toEqual(expected.toLowerCase());

            const aggPk = musig.getXOnlyPubkey(sessionKey);
            // Something in signAgg, nonce processing, or maybe key aggregation broken
            expect(schnorr.verify(sig, message, aggPk)).toBe(true);
          });
        }
      );

      error_test_cases.forEach(
        (
          { aggnonce, key_indices, tweak_indices, is_xonly, psig_indices, error, comment },
          index
        ) => {
          it(`fails to aggregate signatures ${index} "${comment || ''}"`, function () {
            expectBipError(() => {
              const publicKeys = key_indices.map((i) => Buffer.from(pubkeys[i], 'hex'));
              const tweaksI = tweak_indices.map((i, k) => ({
                tweak: Buffer.from(tweaks[i], 'hex'),
                xOnly: is_xonly[k],
              }));
              const sessionKey = musig.startSigningSession(
                Buffer.from(aggnonce, 'hex'),
                message,
                publicKeys,
                ...tweaksI
              );
              return musig.signAgg(
                psig_indices.map((i) => Buffer.from(psigs[i], 'hex')),
                sessionKey
              );
            }, error);
          });
        }
      );
    });

    //    describe('keyGenContext', function () {
    //      const keyGenContext = musig.keyAgg([
    //        secp256k1.getPublicKey(randomPrivateKey(), true),
    //      ]);
    //      const tweaks = [validTweak];
    //
    //      it('rejects wrong base length', function () {
    //        const ctx = { ...keyGenContext, base: new Uint8Array(31) };
    //        expect(() => musig.addTweaks(ctx, tweaks)).toThrow();
    //      });
    //
    //      it('rejects wrong rest length', function () {
    //        const ctx = { ...keyGenContext, base: new Uint8Array(31) };
    //        expect(() => musig.addTweaks(ctx, tweaks)).toThrow();
    //      });
    //
    //      it('rejects non-point public key', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(invalidPoint, 0);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //
    //      it('rejects invalid second public key', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(invalidPub, 65);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //
    //      it('rejects invalid tweak', function () {
    //        const rest = Uint8Array.from(keyGenContext.rest);
    //        rest.set(notSecret, 99);
    //        expect(() => musig.addTweaks({ ...keyGenContext, rest }, tweaks)).toThrow();
    //      });
    //    });

    //    describe('signingSession', function () {
    //      const keyGenContext = musig.keyAgg([validPub]);
    //      const aggNonce = new Uint8Array(66);
    //      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 0);
    //      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 33);
    //      const msg = randomBytes();
    //      const sigs = [randomBytes()];
    //      const signingSession = musig.createSigningSession(aggNonce, msg, keyGenContext);
    //
    //      it('rejects wrong length', function () {
    //        expect(() => musig.createSigningSession(new Uint8Array(65), msg, keyGenContext)).toThrow(
    //          /Invalid aggNonce length/
    //        );
    //        expect(() => musig.signAgg(sigs, keyGenContext, new Uint8Array(160))).toThrow(
    //          /Invalid signingSession length/
    //        );
    //      });
    //
    //      it('rejects non-point final nonce', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(invalidPoint, 0);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //
    //      it('rejects invalid coefficient', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(notSecret, 65);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //
    //      it('rejects invalid challenge', function () {
    //        const invalidSession = Uint8Array.from(signingSession);
    //        invalidSession.set(notSecret, 97);
    //        expect(() => musig.signAgg(sigs, keyGenContext, invalidSession)).toThrow();
    //      });
    //    });

    describe('keyAgg errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.keyAgg([new Uint8Array(31)])).toThrow();
      });

      it('rejects one wrong length', function () {
        expect(() => musig.keyAgg([validPub, new Uint8Array(31)])).toThrow();
      });

      it('rejects one invalid key', function () {
        expect(() => musig.keyAgg([validPub, invalidPub])).toThrow();
      });

      it('rejects no keys', function () {
        expect(() => musig.keyAgg([])).toThrow();
      });
    });

    describe('addTweaks', function () {
      const keyGenContext = musig.keyAgg([validPub]);

      it('performs ordinary tweaking if xOnly omitted', function () {
        const k1 = musig.addTweaks(keyGenContext, validTweak);
        const k2 = musig.addTweaks(keyGenContext, { tweak: validTweak, xOnly: false });
        expect(Buffer.from(k1.aggPublicKey)).toEqual(Buffer.from(k2.aggPublicKey));
      });
    });

    describe('nonceGen errors', function () {
      it('rejects wrong length', function () {
        expect(() => musig.nonceGen({ ...nonceArgs, sessionId: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, secretKey: new Uint8Array(31) })).toThrow();
        expect(() => musig.nonceGen({ ...nonceArgs, publicKey: new Uint8Array(31) })).toThrow();
        expect(() =>
          musig.nonceGen({ ...nonceArgs, xOnlyPublicKey: new Uint8Array(31) })
        ).toThrow();
        expect(() =>
          musig.nonceGen({ ...nonceArgs, extraInput: new Uint8Array(Math.pow(2, 32)) })
        ).toThrow();
      });
    });

    describe('partialSign errors', function () {
      const signerKey = randomPrivateKey();
      const signerPub = secp256k1.getPublicKey(signerKey, true);
      const aggNonce = new Uint8Array(66);
      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 0);
      aggNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 33);
      const sessionKey = musig.startSigningSession(aggNonce, randomBytes(), [signerPub]);
      const secretNonce = new Uint8Array(97);
      secretNonce.set(randomPrivateKey(), 0);
      secretNonce.set(randomPrivateKey(), 32);
      secretNonce.set(signerPub, 64);

      // The public nonce a secret nonce produces: k1*G || k2*G.
      const publicNonceFor = (secret: Uint8Array): Uint8Array => {
        const publicNonce = new Uint8Array(66);
        publicNonce.set(secp256k1.getPublicKey(secret.subarray(0, 32), true), 0);
        publicNonce.set(secp256k1.getPublicKey(secret.subarray(32, 64), true), 33);
        return publicNonce;
      };

      for (const [badNonceI, which] of [
        [0, 'first'],
        [1, 'second'],
      ] as const) {
        it(`rejects an out-of-range ${which} secret nonce value`, function () {
          const invalidSecretNonce = Uint8Array.from(secretNonce);
          invalidSecretNonce.set(notSecret, badNonceI * 32);
          expect(() => musig.addExternalNonce(new Uint8Array(66), invalidSecretNonce)).toThrow(
            `${which} secnonce value is out of range.`
          );
        });
      }

      it('rejects a public nonce the secret nonce does not produce', function () {
        const otherSecretNonce = Uint8Array.from(secretNonce);
        otherSecretNonce.set(randomPrivateKey(), 0);
        expect(() => musig.addExternalNonce(publicNonceFor(otherSecretNonce), secretNonce)).toThrow(
          'Public nonce does not match secret nonce'
        );
      });

      it('rejects an out-of-range secret key', function () {
        const publicNonce = publicNonceFor(secretNonce);
        musig.addExternalNonce(publicNonce, secretNonce);
        expect(() => musig.partialSign({ secretKey: notSecret, publicNonce, sessionKey })).toThrow(
          'secret key value is out of range.'
        );
      });

      it('rejects a secret key the nonce was not generated for', function () {
        const publicNonce = publicNonceFor(secretNonce);
        musig.addExternalNonce(publicNonce, secretNonce);
        expect(() =>
          musig.partialSign({ secretKey: randomPrivateKey(), publicNonce, sessionKey })
        ).toThrow('Public key does not match nonce_gen argument');
      });

      it('signs with the right secret key', function () {
        const publicNonce = publicNonceFor(secretNonce);
        musig.addExternalNonce(publicNonce, secretNonce);
        expect(() =>
          musig.partialSign({ secretKey: signerKey, publicNonce, sessionKey, verify: true })
        ).not.toThrow();
      });
    });

    describe('input validation', function () {
      const keys = [randomPrivateKey(), randomPrivateKey()].map((sk) =>
        secp256k1.getPublicKey(sk, true)
      );
      const randomPubNonce = (): Uint8Array => {
        const publicNonce = new Uint8Array(66);
        publicNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 0);
        publicNonce.set(secp256k1.getPublicKey(randomPrivateKey(), true), 33);
        return publicNonce;
      };
      // Flipping the parity byte of both points negates the nonce.
      const negate = (publicNonce: Uint8Array): Uint8Array => {
        const negated = Uint8Array.from(publicNonce);
        negated[0] ^= 1;
        negated[33] ^= 1;
        return negated;
      };
      const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
      const newSession = (): SessionKey =>
        musig.startSigningSession(
          musig.nonceAgg([randomPubNonce(), randomPubNonce()]),
          randomBytes(),
          keys
        );

      it('blames the signer whose public key is invalid', function () {
        expectBipError(() => musig.keyAgg([validPub, invalidPub]), {
          type: 'invalid_contribution',
          signer: 1,
          contrib: 'pubkey',
        });
      });

      it('keeps adding nonces after a running sum reaches infinity', function () {
        const a = randomPubNonce();
        const b = randomPubNonce();
        expect(hex(musig.nonceAgg([a, negate(a), b]))).toBe(hex(musig.nonceAgg([b])));
        expect(hex(musig.nonceAgg([a, negate(a)]))).toBe('00'.repeat(66));
      });

      it('treats a zero tweak as no tweak', function () {
        const zero = new Uint8Array(32);
        const untweaked = hex(musig.getXOnlyPubkey(musig.keyAgg(keys)));
        expect(hex(musig.getXOnlyPubkey(musig.keyAgg(keys, zero)))).toBe(untweaked);
        expect(hex(musig.getXOnlyPubkey(musig.keyAgg(keys, { tweak: zero, xOnly: true })))).toBe(
          untweaked
        );
      });

      it('rejects a tweak of the wrong length', function () {
        expectBipError(() => musig.keyAgg(keys, new Uint8Array(31)), {
          type: 'value',
          message: 'The tweak must be a 32-byte array.',
        });
      });

      it('blames the aggregator for an aggregate nonce of the wrong length', function () {
        expectBipError(() => musig.startSigningSession(new Uint8Array(65), randomBytes(), keys), {
          type: 'invalid_contribution',
          signer: null,
          contrib: 'aggnonce',
        });
      });

      it('accepts an aggregate nonce whose points are at infinity', function () {
        expect(() =>
          musig.startSigningSession(new Uint8Array(66), randomBytes(), keys)
        ).not.toThrow();
      });

      it('blames the signer whose partial signature is out of range', function () {
        expectBipError(() => musig.signAgg([randomBytes(), notSecret], newSession()), {
          type: 'invalid_contribution',
          signer: 1,
          contrib: 'psig',
        });
      });

      it('blames the verified signer for an invalid public nonce', function () {
        const badNonce = randomPubNonce();
        badNonce[33] = 4;
        expectBipError(
          () =>
            musig.partialVerify({
              sig: randomBytes(),
              publicKey: keys[1],
              publicNonce: badNonce,
              sessionKey: newSession(),
            }),
          { type: 'invalid_contribution', signer: 1, contrib: 'pubnonce' }
        );
      });

      it('refuses to verify for a public key outside the session', function () {
        expectBipError(
          () =>
            musig.partialVerify({
              sig: randomBytes(),
              publicKey: validPub,
              publicNonce: randomPubNonce(),
              sessionKey: newSession(),
            }),
          { type: 'value', message: "The signer's pubkey must be included in the list of pubkeys." }
        );
      });

      it('rejects nonce generation for an invalid public key', function () {
        expect(() => musig.nonceGen({ ...nonceArgs, publicKey: invalidPub })).toThrow(
          'Invalid publicKey'
        );
      });

      it('gives InvalidContributionError a useful name and message', function () {
        const error = new InvalidContributionError(2, 'psig');
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe('InvalidContributionError');
        expect(error.message).toBe('Invalid psig from signer 2');
        expect(new InvalidContributionError(null, 'aggnonce').message).toBe('Invalid aggnonce');
      });
    });
  });
}

for (const { cryptoName, crypto } of cryptos) {
  describe(`${cryptoName}: edge cases`, function () {
    const musig = MuSigFactory(crypto);
    const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
    const newSigner = () => {
      const secretKey = randomPrivateKey();
      return { secretKey, publicKey: secp256k1.getPublicKey(secretKey, true) };
    };
    const negateScalar = (k: Uint8Array): Uint8Array =>
      numberToBytesBE(secp256k1.CURVE.n - BigInt(`0x${hex(k)}`), 32);

    // An aggregate nonce half at infinity is valid, and takes a different path
    // when the final nonce R is computed. Build one on purpose: b's nonce
    // cancels a's in that half, and b still knows its own secret nonce.
    for (const half of [0, 1]) {
      it(`signs and verifies when half ${half} of the aggregate nonce is at infinity`, function () {
        const [a, b] = [newSigner(), newSigner()];
        const publicKeys = [a.publicKey, b.publicKey];
        const msg = randomBytes();
        const na = musig.nonceGenExtractable({
          sessionId: randomBytes(),
          secretKey: a.secretKey,
          publicKey: a.publicKey,
          msg,
        });

        const bSecrets = [randomPrivateKey(), randomPrivateKey()];
        bSecrets[half] = negateScalar(na.secretNonce.subarray(half * 32, (half + 1) * 32));
        const bSecretNonce = new Uint8Array(97);
        bSecretNonce.set(bSecrets[0], 0);
        bSecretNonce.set(bSecrets[1], 32);
        bSecretNonce.set(b.publicKey, 64);
        const bPublicNonce = new Uint8Array(66);
        bPublicNonce.set(secp256k1.getPublicKey(bSecrets[0], true), 0);
        bPublicNonce.set(secp256k1.getPublicKey(bSecrets[1], true), 33);
        musig.addExternalNonce(bPublicNonce, bSecretNonce);

        const aggNonce = musig.nonceAgg([na.publicNonce, bPublicNonce]);
        expect(hex(aggNonce.subarray(half * 33, (half + 1) * 33))).toBe('00'.repeat(33));

        const sessionKey = musig.startSigningSession(aggNonce, msg, publicKeys);
        const sigs = [
          musig.partialSign({ secretKey: a.secretKey, publicNonce: na.publicNonce, sessionKey }),
          musig.partialSign({ secretKey: b.secretKey, publicNonce: bPublicNonce, sessionKey }),
        ];
        const signature = musig.signAgg(sigs, sessionKey);
        expect(schnorr.verify(signature, msg, musig.getXOnlyPubkey(sessionKey))).toBe(true);
      });
    }

    it('rejects wrong-length inputs with a TypeError', function () {
      const { secretKey, publicKey } = newSigner();
      const { publicNonce, secretNonce } = musig.nonceGenExtractable({
        sessionId: randomBytes(),
        secretKey,
        publicKey,
      });
      const sessionKey = musig.startSigningSession(musig.nonceAgg([publicNonce]), randomBytes(), [
        publicKey,
      ]);

      expect(() => musig.addExternalNonce(new Uint8Array(65), secretNonce)).toThrow(TypeError);
      expect(() => musig.addExternalNonce(publicNonce, new Uint8Array(96))).toThrow(TypeError);
      expect(() =>
        musig.partialSign({ secretKey, publicNonce: new Uint8Array(65), sessionKey })
      ).toThrow(TypeError);
      expect(() =>
        musig.partialVerify({ sig: new Uint8Array(31), publicKey, publicNonce, sessionKey })
      ).toThrow(TypeError);
      expect(() => musig.nonceAgg([])).toThrow(TypeError);
      expect(() => musig.signAgg([], sessionKey)).toThrow(TypeError);
      // Last, because it consumes the cached secret nonce.
      expect(() =>
        musig.partialSign({ secretKey: new Uint8Array(31), publicNonce, sessionKey })
      ).toThrow(TypeError);
    });

    it('returns the same plain public key from a session as from its key gen context', function () {
      const { publicKey } = newSigner();
      const other = newSigner().publicKey;
      const keys = [publicKey, other];
      const sessionKey = musig.startSigningSession(new Uint8Array(66), randomBytes(), keys);
      expect(hex(musig.getPlainPubkey(sessionKey))).toBe(
        hex(musig.getPlainPubkey(musig.keyAgg(keys)))
      );
    });
  });
}

describe('adversarial / safety properties', function () {
  const musig = MuSigFactory(tinyCrypto);
  const newKey = () => {
    const sk = secp256k1.utils.randomPrivateKey();
    return { sk, pk: Buffer.from(secp256k1.getPublicKey(sk, true)) };
  };
  function setup() {
    const a = newKey();
    const b = newKey();
    const publicKeys = musig.keySort([a.pk, b.pk]);
    const msg = nc.randomBytes(32);
    const na = musig.nonceGenExtractable({
      sessionId: nc.randomBytes(32),
      secretKey: a.sk,
      publicKey: a.pk,
      msg,
    });
    const nb = musig.nonceGenExtractable({
      sessionId: nc.randomBytes(32),
      secretKey: b.sk,
      publicKey: b.pk,
      msg,
    });
    const aggNonce = musig.nonceAgg([na.publicNonce, nb.publicNonce]);
    const session = musig.startSigningSession(aggNonce, msg, publicKeys);
    return { a, b, na, nb, session };
  }

  it('enforces single-use nonces: signing twice with the same nonce throws', function () {
    const { a, na, session } = setup();
    musig.partialSign({ secretKey: a.sk, publicNonce: na.publicNonce, sessionKey: session });
    expect(() =>
      musig.partialSign({ secretKey: a.sk, publicNonce: na.publicNonce, sessionKey: session })
    ).toThrow(/No secret nonce/);
  });

  it('rejects a tampered partial signature', function () {
    const { a, na, session } = setup();
    const sig = musig.partialSign({
      secretKey: a.sk,
      publicNonce: na.publicNonce,
      sessionKey: session,
      verify: false,
    });
    const tampered = Uint8Array.from(sig);
    tampered[0] ^= 0x01;
    expect(
      musig.partialVerify({
        sig: tampered,
        publicKey: a.pk,
        publicNonce: na.publicNonce,
        sessionKey: session,
      })
    ).toBe(false);
  });

  it('rejects a partial signature checked against the wrong signer', function () {
    const { a, b, na, nb, session } = setup();
    const sigA = musig.partialSign({
      secretKey: a.sk,
      publicNonce: na.publicNonce,
      sessionKey: session,
      verify: false,
    });
    expect(
      musig.partialVerify({
        sig: sigA,
        publicKey: a.pk,
        publicNonce: na.publicNonce,
        sessionKey: session,
      })
    ).toBe(true);
    expect(
      musig.partialVerify({
        sig: sigA,
        publicKey: b.pk,
        publicNonce: nb.publicNonce,
        sessionKey: session,
      })
    ).toBe(false);
  });

  it('refuses to partially sign for a key set the signer is not part of', function () {
    const { a, na } = setup();
    const outsiders = musig.keySort([newKey().pk, newKey().pk]);
    const aggNonce = musig.nonceAgg([na.publicNonce, na.publicNonce]);
    const session = musig.startSigningSession(aggNonce, nc.randomBytes(32), outsiders);
    expect(() =>
      musig.partialSign({ secretKey: a.sk, publicNonce: na.publicNonce, sessionKey: session })
    ).toThrow(/must be included/);
  });

  it('refuses to sign deterministically for a key set the signer is not part of', function () {
    const { a, nb } = setup();
    const args = {
      secretKey: a.sk,
      aggOtherNonce: nb.publicNonce,
      publicKeys: musig.keySort([newKey().pk, newKey().pk]),
      msg: nc.randomBytes(32),
      rand: nc.randomBytes(32),
    };
    expect(() => musig.deterministicSign({ ...args, verify: true })).toThrow(/must be included/);
    expect(() => musig.deterministicNonceGen(args)).toThrow(/must be included/);
  });

  it('is rogue-key resistant: aggregate key applies coefficients (≠ naive point sum)', function () {
    const a = newKey();
    const b = newKey();
    const ctx = musig.keyAgg(musig.keySort([a.pk, b.pk]));
    const agg = musig.getPlainPubkey(ctx);
    const naiveSum = tinyCrypto.pointAdd(a.pk, b.pk, true);
    expect(Buffer.from(agg).toString('hex')).not.toBe(Buffer.from(naiveSum!).toString('hex'));
  });
});
