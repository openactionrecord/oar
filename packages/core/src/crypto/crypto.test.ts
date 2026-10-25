import { describe, expect, it } from 'vitest';
import { canonicalJson } from './canonical.js';
import { commit, commitmentFor, verifyCommitment } from './commitment.js';
import { canonicalDigest, isSha256Digest, sha256Hex } from './hash.js';
import { findPublicKey, generatePrivateKey, publicKeyHex, signCanonical, toJwk, verifyCanonical } from './keys.js';
import { hexToBytes } from './encoding.js';

describe('canonical JSON (RFC 8785)', () => {
  it('sorts keys and removes whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, 2], c: 'x' } })).toBe('{"a":{"c":"x","d":[3,2]},"b":1}');
  });

  it('is independent of key insertion order', () => {
    expect(canonicalJson({ x: 1, y: 2 })).toBe(canonicalJson({ y: 2, x: 1 }));
  });

  it('formats numbers like ECMAScript (RFC 8785 section 3.2.2.3)', () => {
    expect(canonicalJson([1.0, -0, 1e21, 1e-7, 333333333.3333333])).toBe('[1,0,1e+21,1e-7,333333333.3333333]');
  });

  it('serialises strings with minimal escaping', () => {
    expect(canonicalJson({ s: 'é\n"\u2028' })).toBe('{"s":"é\\n\\"\u2028"}');
  });

  it('sorts keys by UTF-16 code units', () => {
    expect(canonicalJson({ '\u20ac': 1, '\r': 2, '1': 3, '\ud83d\ude00': 4 })).toBe('{"\\r":2,"1":3,"\u20ac":1,"\ud83d\ude00":4}');
  });

  it('drops undefined object properties like JSON', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('rejects values JSON cannot represent', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalJson({ a: Infinity })).toThrow(/a: non-finite/);
    expect(() => canonicalJson([undefined])).toThrow(TypeError);
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
    expect(() => canonicalJson({ n: 10n })).toThrow(TypeError);
  });
});

describe('hashing', () => {
  it('matches a known SHA-256 vector', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('digests canonical JSON with a sha256: prefix', () => {
    expect(canonicalDigest({ b: 2, a: 1 })).toBe('sha256:' + sha256Hex('{"a":1,"b":2}'));
    expect(isSha256Digest(canonicalDigest({}))).toBe(true);
    expect(isSha256Digest('sha256:abc')).toBe(false);
  });

});

describe('commitments', () => {
  const value = { params: { type: 'refund', amountCents: 38_000 }, idempotencyKey: 'k-1' };

  it('verifies with the right salt and value', () => {
    const { commitment, salt } = commit(value);
    expect(salt).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyCommitment(commitment, salt, value)).toBe(true);
  });

  it('uses a fresh salt each time, so equal values give different commitments', () => {
    expect(commit(value).commitment).not.toBe(commit(value).commitment);
  });

  it('follows the documented formula', () => {
    const salt = 'a'.repeat(64);
    expect(commitmentFor(value, salt)).toBe('sha256:' + sha256Hex(canonicalJson({ salt, value })));
  });

  it('fails with a changed value, a wrong salt or a malformed commitment', () => {
    const { commitment, salt } = commit(value);
    expect(verifyCommitment(commitment, salt, { ...value, idempotencyKey: 'k-2' })).toBe(false);
    expect(verifyCommitment(commitment, 'b'.repeat(64), value)).toBe(false);
    expect(verifyCommitment(commitment, 'not-hex', value)).toBe(false);
    expect(verifyCommitment('sha256:zz', salt, value)).toBe(false);
  });

  it('does not reveal the value in the commitment', () => {
    const { commitment } = commit({ email: 'someone@example.com' });
    expect(commitment).not.toContain('example');
  });
});

describe('Ed25519 keys and signatures', () => {
  const privateKey = generatePrivateKey();
  const key = { kid: 'k1', privateKey };
  const jwks = { keys: [toJwk(key)] };
  const pub = findPublicKey(jwks, 'k1')!;

  it('signs canonical bytes, so key order does not matter', () => {
    const sig = signCanonical({ a: 1, b: 2 }, privateKey);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyCanonical({ b: 2, a: 1 }, sig, pub)).toBe(true);
  });

  it('rejects a changed message, a different key or a malformed signature', () => {
    const sig = signCanonical({ a: 1 }, privateKey);
    expect(verifyCanonical({ a: 2 }, sig, pub)).toBe(false);
    const other = findPublicKey({ keys: [toJwk({ kid: 'k1', privateKey: generatePrivateKey() })] }, 'k1')!;
    expect(verifyCanonical({ a: 1 }, sig, other)).toBe(false);
    expect(verifyCanonical({ a: 1 }, 'zz', pub)).toBe(false);
    expect(verifyCanonical({ a: 1 }, sig.slice(0, 64), pub)).toBe(false);
  });

  it('publishes a JWK with only the public key', () => {
    const jwk = toJwk(key);
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig', kid: 'k1' });
    expect(Buffer.from(jwk.x, 'base64url').toString('hex')).toBe(publicKeyHex(privateKey));
    expect(JSON.stringify(jwk)).not.toContain(privateKey);
  });

  it('matches the RFC 8032 test vector 1', () => {
    const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    expect(publicKeyHex(seed)).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
  });

  it('finds keys by kid and ignores unknown or malformed ones', () => {
    expect(findPublicKey(jwks, 'missing')).toBeUndefined();
    expect(findPublicKey({ keys: [{ ...jwks.keys[0]!, x: 'short' }] }, 'k1')).toBeUndefined();
    expect(findPublicKey({ keys: [{ ...jwks.keys[0]!, x: '!!!' }] }, 'k1')).toBeUndefined();
  });

  it('rejects private keys of the wrong length', () => {
    expect(() => signCanonical({}, 'abcd')).toThrow(/32 bytes/);
    expect(() => hexToBytes('xyz')).toThrow(/hex/);
  });
});
