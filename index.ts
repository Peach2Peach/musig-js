/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
// Roughly based on the secp256k1-zkp implementation

export interface MuSig {
  /**
   * Gets the X-only public key associated with this context.
   *
   * @param ctx the key gen context or a signing session key
   * @returns the X-only public key associated with this context
   */
  getXOnlyPubkey(ctx: KeyGenContext | SessionKey): Uint8Array;

  /**
   * Gets the plain public key associated with this context.
   *
   * @param ctx the key gen context or a signing session key
   * @returns plain public key associated with this context in compressed DER format
   */
  getPlainPubkey(ctx: KeyGenContext | SessionKey): Uint8Array;

  /**
   * Sorts compressed DER format public keys lexicographically.
   *
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @returns sorted public keys (in a new array)
   */
  keySort(publicKeys: Uint8Array[]): Uint8Array[];

  /**
   * Performs MuSig key aggregation on 1+ x-only public keys.
   *
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 <= tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @returns an opaque key gen context for use with other MuSig operations
   * @throws InvalidContributionError (signer i, 'pubkey') if public key i is
   * not a valid compressed point
   * @throws Error if a tweak is not 32 bytes, is not less than n, or tweaking
   * results in the point at infinity
   */
  keyAgg(publicKeys: Uint8Array[], ...tweaks: Tweak[]): KeyGenContext;

  /**
   * Apply one or more x-only or ordinary tweaks to an aggregate public key.
   *
   * @param ctx the key generation context, as returned from `keyAgg`.
   * @param tweaks tweaks (0 <= tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @returns an opaque key gen context for use with other MuSig operations
   * @throws Error if a tweak is not 32 bytes, is not less than n, or tweaking
   * results in the point at infinity
   */
  addTweaks(ctx: KeyGenContext, ...tweaks: Tweak[]): KeyGenContext;

  /**
   * Generate a MuSig nonce pair based on the provided values.
   *
   * The caller must not use the same sessionId for multiple calls to nonceGen
   * with other parameters held constant.
   *
   * The secret nonce (97 bytes) is cached internally, and will be deleted
   * from the cache prior to use in a signature. The secret nonce will also be
   * deleted if the returned public nonce is deleted.
   *
   * @param sessionId if no secret key is provided, uniformly 32-bytes of
   * random data, otherwise a value guaranteed not to repeat for the secret
   * key. If no sessionId is provided a reasonably high quality random one will
   * be generated.
   * @param secretKey the secret key which will eventually sign with this nonce
   * @param publicKey the public key for which this nonce will be signed (required)
   * @param xOnlyPublicKey the x-coordinate of the aggregate public key that this
   * nonce will be signing a part of
   * @param msg the message which will eventually be signed with this nonce
   * (any possible Uint8Array length)
   * @param extraInput additional input which will contribute to the generated
   * nonce (0 <= extraInput.length <= 2^32-1)
   * @return the generated public nonce (66 bytes)
   */
  nonceGen(args: {
    sessionId?: Uint8Array;
    secretKey?: Uint8Array;
    publicKey: Uint8Array;
    xOnlyPublicKey?: Uint8Array;
    msg?: Uint8Array;
    extraInput?: Uint8Array;
  }): Uint8Array;

  /**
   * Like nonceGen, but also returns the 97-byte secret nonce so the caller can
   * persist it (e.g. a server storing it between signing rounds) instead of
   * relying on the internal cache. Treat the secret nonce like a private key.
   */
  nonceGenExtractable(args: {
    sessionId?: Uint8Array;
    secretKey?: Uint8Array;
    publicKey: Uint8Array;
    xOnlyPublicKey?: Uint8Array;
    msg?: Uint8Array;
    extraInput?: Uint8Array;
  }): { publicNonce: Uint8Array; secretNonce: Uint8Array };

  /**
   * Add an externally generated nonce to the cache.
   *
   * NOT RECOMMENDED, but useful in testing at least.
   * Throws if either secret nonce value is out of range, or if the secret
   * nonce does not produce `publicNonce`.
   * @param publicNonce 66-byte public nonce (2 points in compressed DER)
   * @param secretNonce 97-byte secret nonce (2 32-byte scalars, and the public
   * key which will sign for this nonce in compressed DER)
   */
  addExternalNonce(publicNonce: Uint8Array, secretNonce: Uint8Array): void;

  /**
   * Combine public nonces from all signers into a single aggregate public nonce.
   *
   * Per the spec, this function prefers to succeed with an invalid nonce at
   * infinity than to fail, to enable a dishonest signer to be detected later.
   *
   * This can be run by an untrusted node without breaking the security of the
   * protocol. An untrusted aggregator can cause the protocol to fail, but not
   * forge a signature.
   *
   * @param nonces n-signers public nonces (66-bytes each)
   * @return the aggregate public nonce (66-bytes)
   * @throws InvalidContributionError (signer i, 'pubnonce') if nonce i is not
   * two valid compressed points
   */
  nonceAgg(nonces: Uint8Array[]): Uint8Array;

  /**
   * Creates an opaque signing session for used in partial signing, partial
   * verification, or signature aggregation. This may be saved by a
   * participant, but may not be provided by an untrusted party.
   *
   * @param aggNonce this signing session's aggregate nonce
   * @param msg the message to sign, of any length (most commonly a 32-byte
   * transaction hash)
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 <= tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @return session key for `partialSign`, `partialVerify` and `signAgg`
   * @throws as `keyAgg`, then InvalidContributionError (null, 'aggnonce') if
   * the aggregate nonce is invalid
   */
  startSigningSession(
    aggNonce: Uint8Array,
    msg: Uint8Array,
    publicKeys: Uint8Array[],
    ...tweaks: Tweak[]
  ): SessionKey;

  /**
   * Creates a MuSig partial signature for the given values.
   *
   * Verifies the resulting partial signature by default, as recommended in the
   * specification.
   *
   * Note: Calling `partialSign` with the same `publicNonce` more than once
   * will not work, as the corresponding secret nonce is deleted. Generate a
   * new public nonce and try again.
   *
   * @param secretKey signer's secret key
   * @param publicNonce signer's public nonce
   * @param sessionKey signing session key (from startSigningSession)
   * @param verify if false, don't verify partial signature
   * @return resulting signature
   * @throws Error, with the BIP327 message, if a secret nonce value or the
   * secret key is out of range, the secret key does not match the nonce, or
   * the signer's public key is not one of the session's public keys
   */
  partialSign(args: {
    secretKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
    verify?: boolean;
  }): Uint8Array;

  /**
   * Verifies a MuSig partial signature for the given values.
   *
   * @param sig the 32-byte MuSig partial signature to verify
   * @param publicKey signer's public key
   * @param publicNonce signer's public nonce
   * @param sessionKey signing session key (from startSigningSession)
   * @return true if the partial signature is valid, otherwise false (including
   * when the signature is not less than n)
   * @throws Error if `publicKey` is not one of the session's public keys
   * @throws InvalidContributionError (the signer's index, 'pubnonce') if the
   * public nonce is invalid
   */
  partialVerify(args: {
    sig: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
  }): boolean;

  /**
   * Aggregates MuSig partial signatures. May be run by an untrusted party.
   *
   * @param sigs array of 32-bytes MuSig partial signatures.
   * @param sessionKey signing session key (from startSigningSession)
   * @return the resulting aggregate signature.
   * @throws InvalidContributionError (signer i, 'psig') if partial signature i
   * is not a 32-byte value less than n
   */
  signAgg(sigs: Uint8Array[], sessionKey: SessionKey): Uint8Array;

  /**
   * Deterministically generate nonces and partially sign for a MuSig key.
   * The security of this method depends on its being run after all other
   * parties have provided their nonces.
   *
   * @param secretKey signer's secret key
   * @param aggOtherNonce the result of calling `nonceAgg` on all other signing
   * parties' nonces
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param rand optional additional randomness for nonce generation
   * @param verify if false, don't verify partial signature
   * @return resulting signature, session key (for signature aggregation), and
   * public nonce (for partial verification)
   * @throws as `keyAgg`; Error if the secret key is out of range or its public
   * key is not in `publicKeys`; InvalidContributionError (null,
   * 'aggothernonce') if `aggOtherNonce` is invalid. All of these are checked
   * before any nonce is derived.
   */
  deterministicSign(args: {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
    verify?: boolean;
  }): {
    sig: Uint8Array;
    sessionKey: SessionKey;
    publicNonce: Uint8Array;
  };

  /**
   * Deterministically generate nonces. This is identical to deterministicSign,
   * except that it aborts after nonce generation and before signing, and
   * returns only the public nonce. This security of this method of nonce
   * generation depends on its being run after all other parties have provided
   * their nonces.
   *
   * A public nonce generated in this way cannot be directly used for signing
   * (no secret nonce is saved), but a matching partial signature can be
   * generated by subsequently calling deterministicSign with the same
   * arguments as the call to deterministicNonceGen.
   *
   * This can be useful in a case where a stateless signer only wants to
   * provide its partial signature after seeing valid partial signatures from
   * other parties.
   *
   * @param secretKey signer's secret key
   * @param aggOtherNonce the result of calling `nonceAgg` on all other signing
   * parties' nonces
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param rand optional additional randomness for nonce generation
   * @param verify if false, don't verify partial signature
   * @return public nonce
   */
  deterministicNonceGen(args: {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
  }): { publicNonce: Uint8Array };
  // TODO: Discuss with HSM team the generation of all the nonces and any
  // potential scaling concerns (3x the total cost of schnorr signing)
}

export interface Crypto {
  /**
   * Adds a tweak to a point.
   *
   * @param p A point, compressed or uncompressed
   * @param t A tweak, 0 < t < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The tweaked point, compressed or uncompressed, null if the result
   * is the point at infinity.
   */
  pointAddTweak(p: Uint8Array, t: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Adds two points.
   *
   * @param a An addend point, compressed or uncompressed
   * @param b An addend point, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The sum point, compressed or uncompressed, null if the result is
   * the point at infinity.
   */
  pointAdd(a: Uint8Array, b: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Multiplies a point by a scalar.
   * This function may use non-constant time operations, as no secret
   * information is processed.
   *
   * @param p A point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product point, compressed or uncompressed, null if the result
   * is the point at infinity.
   */
  pointMultiplyUnsafe(p: Uint8Array, a: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Multiplies point 1 by a scalar and adds it to point 2.
   * This function may use non-constant time operations, as no secret
   * information is processed.
   *
   * @param p1 point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param p2 point addend, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product/sum point, compressed or uncompressed, null if the
   * result is the point at infinity.
   */
  pointMultiplyAndAddUnsafe(
    p1: Uint8Array,
    a: Uint8Array,
    p2: Uint8Array,
    compressed: boolean
  ): Uint8Array | null;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point to negate, compressed or uncompressed
   * @returns The negated point, with same compression as input.
   */
  pointNegate(p: Uint8Array): Uint8Array;

  /**
   * Compresses a point.
   *
   * @param p A point, compressed or uncompressed
   * @param compress [default=true] if false, uncompress the point
   * @returns The point, compressed if compress is true, or uncompressed if false.
   */
  pointCompress(p: Uint8Array, compress?: boolean): Uint8Array;

  /**
   * Adds one value to another, mod n.
   *
   * @param a An addend, 0 <= a < n
   * @param b An addend, 0 <= b < n
   * @returns The sum, 0 <= sum < n
   */
  scalarAdd(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Multiply one value by another, mod n.
   *
   * @param a The multiplicand, 0 <= a < n
   * @param b The multiplier, 0 <= b < n
   * @returns The product, 0 <= product < n
   */
  scalarMultiply(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Negates a value, mod n.
   *
   * @param a The value to negate, 0 <= a < n
   * @returns The negated value, 0 <= negated < n
   */
  scalarNegate(a: Uint8Array): Uint8Array;

  /**
   * @param a The value to reduce
   * @returns a mod n
   */
  scalarMod(a: Uint8Array): Uint8Array;

  /**
   * @param s A buffer to check against the curve order
   * @returns true if s is a 32-byte array 0 <= s < n
   */
  isScalar(s: Uint8Array): boolean;

  /**
   * @param s A buffer to check against the curve order
   * @returns true if s is a 32-byte array 0 < s < n
   */
  isSecret(s: Uint8Array): boolean;

  /**
   * @param p A buffer to check against the curve equation, compressed or
   * uncompressed.
   * @returns true if p is a valid point on secp256k1, false otherwise
   */
  isPoint(p: Uint8Array): boolean;

  /**
   * @param p A buffer to check against the curve equation.
   * @returns true if p is the x coordinate of a valid point on secp256k1,
   * false otherwise
   */
  isXOnlyPoint(p: Uint8Array): boolean;

  /**
   * @param p an x coordinate
   * @returns the xy, uncompressed point if p is on the curve, otherwise null.
   */
  liftX(p: Uint8Array): Uint8Array | null;

  /**
   * @param p x-only, compressed or uncompressed
   * @returns the x coordinate of p
   */
  pointX(p: Uint8Array): Uint8Array;

  /**
   * @param p a point, compressed or uncompressed
   * @returns true if p has an even y coordinate, false otherwise
   */
  hasEvenY(p: Uint8Array): boolean;

  /**
   * Gets a public key for secret key.
   *
   * @param s Secret key
   * @param compressed Whether the resulting point should be compressed.
   * @returns The public key, compressed or uncompressed
   */
  getPublicKey(s: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Performs a BIP340-style tagged hash.
   *
   * @param tag
   * @param messages Array of data to hash.
   * @return The 32-byte BIP340-style tagged hash.
   */
  taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array;

  /**
   * SHA256 hash.
   *
   * @param messages Array of data to hash.
   * @return The 32-byte SHA256 digest.
   */
  sha256(...messages: Uint8Array[]): Uint8Array;
}

export type Tweak = TypedTweak | Uint8Array;
export interface TypedTweak {
  tweak: Uint8Array;
  xOnly?: boolean;
}

export interface KeyGenContext {
  aggPublicKey: Uint8Array; // a point on the curve
  gacc: Uint8Array; // accumulated negation factor from X-only tweaking
  tacc: Uint8Array; // 32-byte accumulated tweak (mod n)
}

interface SessionValues extends KeyGenContext {
  coefficient: Uint8Array; // 32-byte nonce coefficient (mod n)
  finalNonce: Uint8Array; // a point on the curve
  challenge: Uint8Array; // 32-byte challenge (mod n)
  publicKeys: Uint8Array[]; // individual public keys in compressed DER format
}

export interface SessionKey {
  publicKey: Uint8Array;
  aggNonce: Uint8Array;
  msg: Uint8Array;
}

/** Which value a participant contributed that was invalid. */
export type Contribution = 'pubkey' | 'pubnonce' | 'aggnonce' | 'aggothernonce' | 'psig';

/**
 * A participant contributed an invalid value: BIP327's InvalidContributionError.
 * Callers should hold the offending party accountable rather than crash.
 *
 * `signer` is the index of the offending signer in the list of public keys,
 * nonces or partial signatures, or null when the value came from the nonce
 * aggregator (`aggnonce`) or combines several signers (`aggothernonce`).
 */
export class InvalidContributionError extends Error {
  readonly signer: number | null;
  readonly contrib: Contribution;

  constructor(signer: number | null, contrib: Contribution) {
    super(signer === null ? `Invalid ${contrib}` : `Invalid ${contrib} from signer ${signer}`);
    this.name = 'InvalidContributionError';
    this.signer = signer;
    this.contrib = contrib;
    // Keeps `instanceof` working when compiled to ES5.
    Object.setPrototypeOf(this, InvalidContributionError.prototype);
  }
}

const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_aux: 'MuSig/aux',
  musig_nonce: 'MuSig/nonce',
  musig_deterministic_nonce: 'MuSig/deterministic/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
} as const;

/**
 * Compares two 32-byte Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare32b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 32 || b.length !== 32) throw new Error('Invalid array');
  const aD = new DataView(a.buffer, a.byteOffset, a.length);
  const bD = new DataView(b.buffer, b.byteOffset, b.length);
  for (let i = 0; i < 8; i++) {
    const cmp = aD.getUint32(i * 4) - bD.getUint32(i * 4);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

/**
 * Compares two 33-byte Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare33b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 33 || b.length !== 33) throw new Error('Invalid array');
  const cmp = a[0] - b[0];
  if (cmp !== 0) return cmp;
  return compare32b(a.subarray(1), b.subarray(1));
}

declare const self: Record<string, any> | undefined;
const makeSessionId =
  typeof self === 'object' && (self.crypto || self.msCrypto)
    ? () => (self.crypto || self.msCrypto).getRandomValues(new Uint8Array(32)) // Browsers
    : () => require('crypto').randomBytes(32); // Node

// Caches values needed to compute key agg coefficients for an array of public keys
interface KeyAggCache {
  publicKeyHash: Uint8Array;
  secondPublicKey?: Uint8Array;
}
const _keyAggCache = new WeakMap<Uint8Array[], KeyAggCache>();

// Caches coefficients associated with an array of public keys
const _coefCache = new WeakMap<Uint8Array[], Map<Uint8Array, Uint8Array>>();

// Caches secret nonces. We do this internally to help users ensure that they
// do not reuse a secret nonce.
const _nonceCache = new WeakMap<Uint8Array, Uint8Array>();

// Caches signing sessions. We do this internally to help users ensure that
// these session values were generated on the signer, and are not accepted from
// an untrusted third party.
const _sessionCache = new WeakMap<SessionKey, SessionValues>();

export function MuSigFactory(ecc: Crypto): MuSig {
  const CPOINT_INF = new Uint8Array(33);
  const SCALAR_0 = new Uint8Array(32);
  const SCALAR_1 = new Uint8Array(32);
  SCALAR_1[31] = 1;
  const SCALAR_MINUS_1 = ecc.scalarNegate(SCALAR_1);

  function keyAggCoeff(publicKeys: Uint8Array[], publicKey: Uint8Array): Uint8Array {
    let coefCache = _coefCache.get(publicKeys);
    if (coefCache === undefined) {
      coefCache = new Map<Uint8Array, Uint8Array>();
      _coefCache.set(publicKeys, coefCache);
    }
    let coefficient = coefCache.get(publicKey);
    if (coefficient) return coefficient;

    coefficient = SCALAR_1;
    let secondPublicKey;
    let publicKeyHash;
    let keyAggCache = _keyAggCache.get(publicKeys);
    if (keyAggCache === undefined) {
      // Index of the first occurrence of the second unique public key.
      const pkIdx2 = publicKeys.findIndex((pk) => compare33b(pk, publicKeys[0]) !== 0);
      secondPublicKey = publicKeys[pkIdx2]; // undefined if pkIdx2 === -1
      publicKeyHash = ecc.taggedHash(TAGS.keyagg_list, ...publicKeys);
      keyAggCache = { publicKeyHash, secondPublicKey };
      _keyAggCache.set(publicKeys, keyAggCache);
    } else {
      ({ publicKeyHash, secondPublicKey } = keyAggCache);
    }
    if (secondPublicKey === undefined || compare33b(publicKey, secondPublicKey) !== 0)
      coefficient = ecc.taggedHash(TAGS.keyagg_coef, publicKeyHash, publicKey);
    coefCache.set(publicKey, coefficient);
    return coefficient;
  }

  function addTweak(ctx: KeyGenContext, t: Tweak): KeyGenContext {
    const tweak = 'tweak' in t ? t : { tweak: t };
    // Messages as in BIP327 ApplyTweak.
    if (tweak.tweak.length !== 32) throw new Error('The tweak must be a 32-byte array.');
    if (!ecc.isScalar(tweak.tweak)) throw new Error('The tweak must be less than n.');
    let { gacc, tacc } = ctx;
    let aggPublicKey: Uint8Array | null = ctx.aggPublicKey;

    if (!ecc.hasEvenY(aggPublicKey) && tweak.xOnly) {
      // g = -1
      gacc = ecc.scalarNegate(gacc); // g * gacc mod n
      tacc = ecc.scalarNegate(tacc); // g * tacc mod n
      aggPublicKey = ecc.pointNegate(aggPublicKey); // g * Q
    }
    // A zero tweak leaves g * Q as it is, and not every backend accepts a zero scalar.
    if (compare32b(tweak.tweak, SCALAR_0) !== 0) {
      aggPublicKey = ecc.pointAddTweak(aggPublicKey, tweak.tweak, false); // g * Q + t * G
      if (aggPublicKey === null) throw new Error('The result of tweaking cannot be infinity.');
    }
    tacc = ecc.scalarAdd(tweak.tweak, tacc); // t + g * tacc mod n

    return { aggPublicKey, gacc, tacc };
  }

  function keyAgg(publicKeys: Uint8Array[], ...tweaks: Tweak[]): KeyGenContext {
    checkPublicKeys(publicKeys);
    const multipliedPublicKeys = publicKeys.map((publicKey) => {
      const coefficient = keyAggCoeff(publicKeys, publicKey);
      let multipliedPublicKey: Uint8Array | null;
      if (compare32b(coefficient, SCALAR_1) === 0) {
        multipliedPublicKey = publicKey;
      } else {
        multipliedPublicKey = ecc.pointMultiplyUnsafe(publicKey, coefficient, false);
      }
      if (multipliedPublicKey === null) throw new Error('Point at infinity during aggregation');
      return multipliedPublicKey;
    });

    const aggPublicKey = multipliedPublicKeys.reduce((a, b) => {
      const next = ecc.pointAdd(a, b, false);
      if (next === null) throw new Error('Point at infinity during aggregation');
      return next;
    });

    return tweaks.reduce((ctx, tweak) => addTweak(ctx, tweak), {
      aggPublicKey,
      gacc: SCALAR_1,
      tacc: SCALAR_0,
    });
  }

  function getSessionValues(sessionKey: SessionKey): SessionValues {
    const sessionValues = _sessionCache.get(sessionKey);
    if (!sessionValues) throw new Error('Invalid session key, please call `startSigningSession`');
    return sessionValues;
  }

  // Validity is checked explicitly with the bundled curve equation (`isPoint`),
  // rather than left to whichever point-math backend is injected.
  function isCompressedPoint(p: Uint8Array): boolean {
    return p.length === 33 && (p[0] === 2 || p[0] === 3) && ecc.isPoint(p);
  }

  // BIP327 KeyAgg: a key that is not a valid compressed point is the fault of
  // the signer who supplied it.
  function checkPublicKeys(publicKeys: Uint8Array[]): void {
    if (publicKeys.length === 0) throw new TypeError('0-length publicKeys not supported');
    publicKeys.forEach((publicKey, i) => {
      if (!isCompressedPoint(publicKey)) throw new InvalidContributionError(i, 'pubkey');
    });
  }

  // BIP327 Sign / DeterministicSign / PartialSigVerify: the signer's key must be
  // one of the keys being aggregated. Without this check a signer can be induced
  // to produce a partial signature for a key set it is not part of. Returns the
  // signer's index.
  function assertSignerIncluded(publicKey: Uint8Array, publicKeys: Uint8Array[]): number {
    const index = publicKeys.findIndex((key) => compare33b(key, publicKey) === 0);
    if (index === -1)
      throw new Error("The signer's pubkey must be included in the list of pubkeys.");
    return index;
  }

  // A public nonce is two valid compressed points. Neither may be infinity.
  function isValidPubNonce(publicNonce: Uint8Array): boolean {
    return (
      publicNonce.length === 66 &&
      isCompressedPoint(publicNonce.subarray(0, 33)) &&
      isCompressedPoint(publicNonce.subarray(33))
    );
  }

  // An aggregate nonce may encode either point as infinity: 33 zero bytes.
  function isValidAggNonce(aggNonce: Uint8Array): boolean {
    if (aggNonce.length !== 66) return false;
    return [aggNonce.subarray(0, 33), aggNonce.subarray(33)].every(
      (half) => compare33b(half, CPOINT_INF) === 0 || isCompressedPoint(half)
    );
  }

  function checkSecretKey(secretKey: Uint8Array, rangeMessage: string): void {
    if (secretKey.length !== 32)
      throw new TypeError(`Invalid secretKey length (${secretKey.length})`);
    if (!ecc.isSecret(secretKey)) throw new Error(rangeMessage);
  }

  // Messages as in BIP327 Sign.
  function checkSecretNonce(secretNonce: Uint8Array): void {
    if (secretNonce.length !== 97)
      throw new TypeError(`Invalid secretNonce length (${secretNonce.length})`);
    if (!ecc.isSecret(secretNonce.subarray(0, 32)))
      throw new Error('first secnonce value is out of range.');
    if (!ecc.isSecret(secretNonce.subarray(32, 64)))
      throw new Error('second secnonce value is out of range.');
  }

  function nonceAgg(publicNonces: Uint8Array[]): Uint8Array {
    if (publicNonces.length === 0) throw new TypeError('0-length publicNonces not supported');
    publicNonces.forEach((publicNonce, i) => {
      if (!isValidPubNonce(publicNonce)) throw new InvalidContributionError(i, 'pubnonce');
    });

    // Each half is summed separately. `null` is the point at infinity, which a
    // running sum can pass through (R, then -R) before later nonces are added.
    const aggNonce = new Uint8Array(66);
    for (let half = 0; half < 2; half++) {
      let sum: Uint8Array | null = null;
      for (const publicNonce of publicNonces) {
        const point = publicNonce.subarray(half * 33, (half + 1) * 33);
        sum = sum === null ? point : ecc.pointAdd(sum, point, false);
      }
      // A total at infinity stays encoded as 33 zero bytes.
      if (sum !== null) aggNonce.set(ecc.pointCompress(sum, true), half * 33);
    }
    return aggNonce;
  }

  function startSigningSessionInner(
    aggNonce: Uint8Array,
    msg: Uint8Array,
    publicKeys: Uint8Array[],
    ctx: KeyGenContext
  ): SessionKey {
    const pubKeyX = ecc.pointX(ctx.aggPublicKey);

    const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, msg);

    const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];

    // This is kinda ugly, but crypto.pointAdd doesn't work on 0-coded infinity
    let r: Uint8Array | null = null;
    if (compare33b(aggNonces[1], CPOINT_INF) !== 0 && compare33b(aggNonces[0], CPOINT_INF) !== 0) {
      r = ecc.pointMultiplyAndAddUnsafe(aggNonces[1], coefficient, aggNonces[0], false);
    } else if (compare33b(aggNonces[0], CPOINT_INF) !== 0) {
      r = ecc.pointCompress(aggNonces[0], false);
    } else if (compare33b(aggNonces[1], CPOINT_INF) !== 0) {
      r = ecc.pointMultiplyUnsafe(aggNonces[1], coefficient, false);
    }
    if (r === null) r = ecc.getPublicKey(SCALAR_1, false);
    if (r === null) throw new Error('Failed to get G');

    const challenge = ecc.scalarMod(ecc.taggedHash(TAGS.challenge, ecc.pointX(r), pubKeyX, msg));

    const key = { publicKey: ctx.aggPublicKey, aggNonce, msg };
    _sessionCache.set(key, { ...ctx, coefficient, challenge, finalNonce: r, publicKeys });
    return key;
  }

  function partialVerifyInner({
    sig,
    publicKey,
    publicNonces,
    sessionKey,
  }: {
    sig: Uint8Array;
    publicKey: Uint8Array;
    publicNonces: [Uint8Array, Uint8Array];
    sessionKey: SessionKey;
  }): boolean {
    const { msg } = sessionKey;
    const { aggPublicKey, gacc, challenge, coefficient, finalNonce, publicKeys } =
      getSessionValues(sessionKey);

    const rePrime = ecc.pointMultiplyAndAddUnsafe(
      publicNonces[1],
      coefficient,
      publicNonces[0],
      false
    );
    if (rePrime === null) throw new Error('Unexpected public nonce at infinity');
    const re = ecc.hasEvenY(finalNonce) ? rePrime : ecc.pointNegate(rePrime);

    const a = keyAggCoeff(publicKeys, publicKey);

    const g = ecc.hasEvenY(aggPublicKey) ? gacc : ecc.scalarNegate(gacc);

    const ea = ecc.scalarMultiply(challenge, a);
    const eag = ecc.scalarMultiply(ea, g);
    const ver = ecc.pointMultiplyAndAddUnsafe(publicKey, eag, re, true);
    if (ver === null) throw new Error('Unexpected verification point at infinity');

    const sG = ecc.getPublicKey(sig, true);
    if (sG === null) throw new Error('Unexpected signature point at infinity');

    return compare33b(ver, sG) === 0;
  }

  function partialSignInner({
    secretKey,
    publicKey,
    secretNonces,
    sessionKey,
  }: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    secretNonces: [Uint8Array, Uint8Array];
    sessionKey: SessionKey;
  }): Uint8Array {
    const { msg } = sessionKey;
    const { aggPublicKey, gacc, challenge, coefficient, finalNonce, publicKeys } =
      getSessionValues(sessionKey);

    const [k1, k2] = secretNonces.map((k) => (ecc.hasEvenY(finalNonce) ? k : ecc.scalarNegate(k)));

    const a = keyAggCoeff(publicKeys, publicKey);

    const g = ecc.hasEvenY(aggPublicKey) ? gacc : ecc.scalarNegate(gacc);
    const d = ecc.scalarMultiply(g, secretKey);

    const bk2 = ecc.scalarMultiply(coefficient, k2);
    const k1bk2 = ecc.scalarAdd(k1, bk2);

    const ea = ecc.scalarMultiply(challenge, a);
    const ead = ecc.scalarMultiply(ea, d);

    const sig = ecc.scalarAdd(k1bk2, ead);

    return sig;
  }

  function partialSign({
    secretKey,
    publicNonce,
    sessionKey,
    verify = true,
  }: {
    secretKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
    verify: boolean;
  }): Uint8Array {
    if (publicNonce.length !== 66)
      throw new TypeError(`Invalid publicNonce length (${publicNonce.length})`);
    const { publicKeys } = getSessionValues(sessionKey);

    // Removed before anything else can fail, so a failed attempt can never be
    // retried with the same nonce.
    const secretNonce = _nonceCache.get(publicNonce);
    if (secretNonce === undefined)
      throw new Error('No secret nonce found for specified public nonce');
    _nonceCache.delete(publicNonce);

    // Checked in the order of BIP327 Sign, with its messages.
    checkSecretNonce(secretNonce);
    checkSecretKey(secretKey, 'secret key value is out of range.');
    const publicKey = ecc.getPublicKey(secretKey, true);
    if (publicKey === null) throw new Error('secret key value is out of range.');
    if (compare33b(publicKey, secretNonce.subarray(64)) !== 0)
      throw new Error('Public key does not match nonce_gen argument');
    assertSignerIncluded(publicKey, publicKeys);
    const secretNonces: [Uint8Array, Uint8Array] = [
      secretNonce.subarray(0, 32),
      secretNonce.subarray(32, 64),
    ];
    const sig = partialSignInner({
      secretKey,
      publicKey,
      secretNonces,
      sessionKey,
    });

    if (verify) {
      const publicNonces: [Uint8Array, Uint8Array] = [
        publicNonce.subarray(0, 33),
        publicNonce.subarray(33),
      ];
      const valid = partialVerifyInner({
        sig,
        publicKey,
        publicNonces,
        sessionKey,
      });
      if (!valid) throw new Error('Partial signature failed verification');
    }
    return sig;
  }

  interface DeterministicSignArgsBase {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
  }
  interface DeterministicSignArgs extends DeterministicSignArgsBase {
    verify?: boolean;
    nonceOnly?: boolean;
  }
  interface DeterministicSignArgsSign extends DeterministicSignArgsBase {
    verify: boolean;
  }
  interface DeterministicSignArgsNonceOnly extends DeterministicSignArgsBase {
    nonceOnly: true;
  }
  function deterministicSign(args: DeterministicSignArgsSign): {
    sig: Uint8Array;
    sessionKey: SessionKey;
    publicNonce: Uint8Array;
  };
  function deterministicSign(args: DeterministicSignArgsNonceOnly): { publicNonce: Uint8Array };
  function deterministicSign({
    secretKey,
    aggOtherNonce,
    publicKeys,
    tweaks = [],
    msg,
    rand,
    verify = true,
    nonceOnly = false,
  }: DeterministicSignArgs): {
    sig?: Uint8Array;
    sessionKey?: SessionKey;
    publicNonce: Uint8Array;
  } {
    // No need to check msg, its max size is larger than JS typed array limit
    checkArgs({ rand });
    const secretKeyRange = 'The secret key must be an integer in the range 1..n-1.';
    checkSecretKey(secretKey, secretKeyRange);
    const publicKey = ecc.getPublicKey(secretKey, true);
    if (publicKey === null) throw new Error(secretKeyRange);

    // Everything is validated before any nonce is derived, so nonce-only calls
    // refuse too. Invalid keys and tweaks are reported first, as in BIP327.
    const ctx = keyAgg(publicKeys, ...tweaks);
    assertSignerIncluded(publicKey, publicKeys);
    if (!isValidPubNonce(aggOtherNonce)) throw new InvalidContributionError(null, 'aggothernonce');

    let secretKeyPrime;
    if (rand !== undefined) {
      secretKeyPrime = ecc.taggedHash(TAGS.musig_aux, rand);
      for (let i = 0; i < 32; i++) {
        secretKeyPrime[i] = secretKeyPrime[i] ^ secretKey[i];
      }
    } else {
      secretKeyPrime = secretKey;
    }
    const aggPublicKey = ecc.pointX(ctx.aggPublicKey);

    const mLength = new Uint8Array(8);
    new DataView(mLength.buffer).setBigUint64(0, BigInt(msg.length));

    const secretNonce = new Uint8Array(97);
    const publicNonce = new Uint8Array(66);
    for (let i = 0; i < 2; i++) {
      const kH = ecc.taggedHash(
        TAGS.musig_deterministic_nonce,
        ...[secretKeyPrime, aggOtherNonce, aggPublicKey, mLength, msg, Uint8Array.of(i)]
      );
      const k = ecc.scalarMod(kH);
      if (compare32b(SCALAR_0, k) === 0) throw new Error('0 secret nonce');
      const pub = ecc.getPublicKey(k, true);
      if (pub === null) throw new Error('Secret nonce has no corresponding public nonce');

      secretNonce.set(k, i * 32);
      publicNonce.set(pub, i * 33);
    }
    secretNonce.set(publicKey, 64);

    if (nonceOnly) return { publicNonce };

    _nonceCache.set(publicNonce, secretNonce);
    const aggNonce = nonceAgg([aggOtherNonce, publicNonce]);
    const sessionKey = startSigningSessionInner(aggNonce, msg, publicKeys, ctx);
    const sig = partialSign({
      secretKey,
      publicNonce,
      sessionKey,
      verify,
    });

    return { sig, sessionKey, publicNonce };
  }

  // Structural (length and scalar range) checks. Point validity is checked where
  // keys and nonces are used: checkPublicKeys, isValidPubNonce, isValidAggNonce.
  const pubKeyArgs = ['publicKey', 'publicKeys'] as const;
  const scalarArgs = ['tweak', 'sig', 'sigs', 'tacc', 'gacc'] as const;
  const otherArgs32b = ['xOnlyPublicKey', 'rand', 'sessionId'] as const;
  const args32b = ['secretKey', ...scalarArgs, ...otherArgs32b] as const;
  const pubNonceArgs = [
    'publicNonce',
    'publicNonces',
    'aggNonce',
    'aggOtherNonce',
    'finalNonce',
  ] as const;
  const otherArgs = ['aggPublicKey'] as const;
  type ArgName =
    | (typeof pubKeyArgs)[number]
    | (typeof args32b)[number]
    | (typeof pubNonceArgs)[number]
    | (typeof otherArgs)[number];
  type Args = { [A in ArgName]?: Uint8Array | Uint8Array[] };

  const argLengths = new Map<string, number>();
  args32b.forEach((a) => argLengths.set(a, 32));
  pubKeyArgs.forEach((a) => argLengths.set(a, 33));
  pubNonceArgs.forEach((a) => argLengths.set(a, 66));
  argLengths.set('aggPublicKey', 65);
  const scalarNames = new Set<string>();
  scalarArgs.forEach((n) => scalarNames.add(n));

  function checkArgs(args: Args): void {
    for (let [name, values] of Object.entries(args)) {
      if (values === undefined) continue;
      values = Array.isArray(values) ? values : [values];
      if (values.length === 0) throw new TypeError(`0-length ${name}s not supported`);
      for (const value of values) {
        if (argLengths.get(name) !== value.length)
          throw new TypeError(`Invalid ${name} length (${value.length})`);
        if (name === 'secretKey') {
          if (!ecc.isSecret(value)) throw new TypeError(`Invalid secretKey`);
        } else if (scalarNames.has(name)) {
          for (let i = 0; i < value.length; i += 32)
            if (!ecc.isScalar(value.subarray(i, i + 32))) throw new TypeError(`Invalid ${name}`);
        }
      }
    }
  }

  // Shared nonce derivation (BIP327 NonceGen). Returns both the public nonce and
  // the secret nonce so callers can either cache it internally (nonceGen) or take
  // ownership of the secret to persist it themselves (nonceGenExtractable).
  function computeNonce({
    sessionId = makeSessionId(),
    secretKey,
    publicKey,
    xOnlyPublicKey,
    msg,
    extraInput,
  }: {
    sessionId?: Uint8Array;
    secretKey?: Uint8Array;
    publicKey: Uint8Array;
    xOnlyPublicKey?: Uint8Array;
    msg?: Uint8Array;
    extraInput?: Uint8Array;
  }): { publicNonce: Uint8Array; secretNonce: Uint8Array } {
    if (extraInput !== undefined && extraInput.length > Math.pow(2, 32) - 1)
      throw new TypeError('extraInput is limited to 2^32-1 bytes');
    // No need to check msg, its max size is larger than JS typed array limit
    checkArgs({ sessionId, secretKey, publicKey, xOnlyPublicKey });
    if (!isCompressedPoint(publicKey)) throw new TypeError('Invalid publicKey');
    let rand: Uint8Array;
    if (secretKey !== undefined) {
      rand = ecc.taggedHash(TAGS.musig_aux, sessionId);
      for (let i = 0; i < 32; i++) {
        rand[i] = rand[i] ^ secretKey[i];
      }
    } else {
      rand = sessionId;
    }

    if (xOnlyPublicKey === undefined) xOnlyPublicKey = new Uint8Array();

    const mPrefixed = [Uint8Array.of(0)];
    if (msg !== undefined) {
      mPrefixed[0][0] = 1;
      mPrefixed.push(new Uint8Array(8));
      new DataView(mPrefixed[1].buffer).setBigUint64(0, BigInt(msg.length));
      mPrefixed.push(msg);
    }

    if (extraInput === undefined) extraInput = new Uint8Array();
    const eLength = new Uint8Array(4);
    new DataView(eLength.buffer).setUint32(0, extraInput.length);

    const secretNonce = new Uint8Array(97);
    const publicNonce = new Uint8Array(66);
    for (let i = 0; i < 2; i++) {
      const kH = ecc.taggedHash(
        TAGS.musig_nonce,
        rand,
        Uint8Array.of(publicKey.length),
        publicKey,
        Uint8Array.of(xOnlyPublicKey.length),
        xOnlyPublicKey,
        ...mPrefixed,
        eLength,
        extraInput,
        Uint8Array.of(i)
      );
      const k = ecc.scalarMod(kH);
      if (compare32b(SCALAR_0, k) === 0) throw new Error('0 secret nonce');
      const pub = ecc.getPublicKey(k, true);
      if (pub === null) throw new Error('Secret nonce has no corresponding public nonce');

      secretNonce.set(k, i * 32);
      publicNonce.set(pub, i * 33);
    }
    secretNonce.set(publicKey, 64);
    return { publicNonce, secretNonce };
  }

  return {
    getXOnlyPubkey: (ctx: KeyGenContext | SessionKey): Uint8Array => {
      if ('aggPublicKey' in ctx) return ecc.pointX(ctx.aggPublicKey);
      return ecc.pointX(getSessionValues(ctx).aggPublicKey);
    },
    getPlainPubkey: (ctx: KeyGenContext | SessionKey): Uint8Array => {
      if ('aggPublicKey' in ctx) return ecc.pointCompress(ctx.aggPublicKey);
      return ecc.pointCompress(getSessionValues(ctx).aggPublicKey);
    },
    keySort: (publicKeys: Uint8Array[]): Uint8Array[] => {
      checkArgs({ publicKeys });
      // do not modify the original array
      return [...publicKeys].sort((a, b) => compare33b(a, b));
    },
    keyAgg,
    addTweaks: (ctx: KeyGenContext, ...tweaks: Tweak[]): KeyGenContext => {
      checkArgs(ctx);
      return tweaks.reduce((c, tweak) => addTweak(c, tweak), ctx);
    },

    nonceGen: (args: {
      sessionId?: Uint8Array;
      secretKey?: Uint8Array;
      publicKey: Uint8Array;
      xOnlyPublicKey?: Uint8Array;
      msg?: Uint8Array;
      extraInput?: Uint8Array;
    }): Uint8Array => {
      const { publicNonce, secretNonce } = computeNonce(args);
      _nonceCache.set(publicNonce, secretNonce);
      return publicNonce;
    },

    // Same as nonceGen, but returns the secret nonce too so the caller can own
    // its lifecycle (e.g. persist it in a DB between signing rounds) rather than
    // relying on the internal cache. It is still cached, so partialSign works
    // either with the returned publicNonce in-process or after addExternalNonce.
    // SECURITY: the secret nonce is as sensitive as a private key — store it
    // encrypted, use it exactly once, and never reuse it across signing sessions.
    nonceGenExtractable: (args: {
      sessionId?: Uint8Array;
      secretKey?: Uint8Array;
      publicKey: Uint8Array;
      xOnlyPublicKey?: Uint8Array;
      msg?: Uint8Array;
      extraInput?: Uint8Array;
    }): { publicNonce: Uint8Array; secretNonce: Uint8Array } => {
      const { publicNonce, secretNonce } = computeNonce(args);
      _nonceCache.set(publicNonce, secretNonce);
      return { publicNonce, secretNonce };
    },

    addExternalNonce: (publicNonce: Uint8Array, secretNonce: Uint8Array): void => {
      if (publicNonce.length !== 66)
        throw new TypeError(`Invalid publicNonce length (${publicNonce.length})`);
      checkSecretNonce(secretNonce);
      // The public nonce must be the one these secrets produce; otherwise
      // partialSign would sign with a nonce the other signers never saw.
      for (let i = 0; i < 2; i++) {
        const expected = ecc.getPublicKey(secretNonce.subarray(i * 32, (i + 1) * 32), true);
        if (expected === null || compare33b(expected, publicNonce.subarray(i * 33, (i + 1) * 33)))
          throw new Error('Public nonce does not match secret nonce');
      }
      _nonceCache.set(publicNonce, secretNonce);
    },

    deterministicNonceGen: (args: DeterministicSignArgsBase): { publicNonce: Uint8Array } =>
      deterministicSign({ ...args, nonceOnly: true }),

    deterministicSign,

    nonceAgg,

    startSigningSession: (
      aggNonce: Uint8Array,
      msg: Uint8Array,
      publicKeys: Uint8Array[],
      ...tweaks: Tweak[]
    ): SessionKey => {
      // As in BIP327, invalid keys or tweaks are reported before an invalid aggregate nonce.
      const ctx = keyAgg(publicKeys, ...tweaks);
      if (!isValidAggNonce(aggNonce)) throw new InvalidContributionError(null, 'aggnonce');
      return startSigningSessionInner(aggNonce, msg, publicKeys, ctx);
    },

    partialSign,

    partialVerify: ({
      sig,
      publicKey,
      publicNonce,
      sessionKey,
    }: {
      sig: Uint8Array;
      publicKey: Uint8Array;
      publicNonce: Uint8Array;
      sessionKey: SessionKey;
    }): boolean => {
      if (sig.length !== 32) throw new TypeError(`Invalid sig length (${sig.length})`);
      checkArgs({ publicKey });
      // The signer's position among the session's keys identifies who sent a bad nonce.
      const signer = assertSignerIncluded(publicKey, getSessionValues(sessionKey).publicKeys);
      if (!isValidPubNonce(publicNonce)) throw new InvalidContributionError(signer, 'pubnonce');
      // BIP327 PartialSigVerify: a signature outside the group order does not
      // verify. That is a failed verification, not an error.
      if (!ecc.isScalar(sig)) return false;

      const publicNonces: [Uint8Array, Uint8Array] = [
        publicNonce.subarray(0, 33),
        publicNonce.subarray(33),
      ];

      const valid = partialVerifyInner({
        sig,
        publicKey,
        publicNonces,
        sessionKey,
      });
      return valid;
    },

    signAgg: (sigs: Uint8Array[], sessionKey: SessionKey): Uint8Array => {
      if (sigs.length === 0) throw new TypeError('0-length sigs not supported');
      const { aggPublicKey, tacc, challenge, finalNonce } = getSessionValues(sessionKey);
      sigs.forEach((psig, i) => {
        if (psig.length !== 32 || !ecc.isScalar(psig))
          throw new InvalidContributionError(i, 'psig');
      });
      let sPart: Uint8Array = ecc.scalarMultiply(challenge, tacc);
      if (!ecc.hasEvenY(aggPublicKey)) {
        sPart = ecc.scalarNegate(sPart);
      }
      const aggS = sigs.reduce((a, b) => ecc.scalarAdd(a, b), sPart);
      const sig = new Uint8Array(64);
      sig.set(ecc.pointX(finalNonce), 0);
      sig.set(aggS, 32);
      return sig;
    },
  };
}
