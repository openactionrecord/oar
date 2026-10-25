import { ed25519 } from '@noble/curves/ed25519.js';
import { canonicalBytes } from './canonical.js';
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, hexToBytes } from './encoding.js';

// Ed25519 signing keys. Private keys are 32-byte hex seeds: keep them secret and never log them.

export interface SigningKey {
  kid: string;
  /** 32-byte hex seed. Secret. */
  privateKey: string;
}

export interface Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  /** base64url public key. */
  x: string;
  kid: string;
  alg: 'EdDSA';
  use: 'sig';
}

export interface Jwks {
  keys: Jwk[];
}

export function generatePrivateKey(): string {
  return bytesToHex(ed25519.utils.randomSecretKey());
}

export function publicKeyHex(privateKey: string): string {
  return bytesToHex(ed25519.getPublicKey(hexToBytes(privateKey, 32)));
}

/** Signs the RFC 8785 canonical bytes of `value`; returns a hex signature. */
export function signCanonical(value: unknown, privateKey: string): string {
  return bytesToHex(ed25519.sign(canonicalBytes(value), hexToBytes(privateKey, 32)));
}

/** Verifies a hex signature over the canonical bytes of `value`. Never throws. */
export function verifyCanonical(value: unknown, signatureHex: string, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(hexToBytes(signatureHex, 64), canonicalBytes(value), publicKey);
  } catch {
    return false;
  }
}

export function toJwk(key: SigningKey): Jwk {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: bytesToBase64Url(ed25519.getPublicKey(hexToBytes(key.privateKey, 32))),
    kid: key.kid,
    alg: 'EdDSA',
    use: 'sig',
  };
}

/** Finds the public key for `kid` in a key set; undefined if missing or malformed. */
export function findPublicKey(jwks: Jwks, kid: string): Uint8Array | undefined {
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return undefined;
  try {
    const bytes = base64UrlToBytes(jwk.x);
    return bytes.length === 32 ? bytes : undefined;
  } catch {
    return undefined;
  }
}

/** A new Ed25519 signing key. Store `privateKey` as a secret (an environment variable or a key manager). */
export function generateSigningKey(kid: string): SigningKey {
  if (!kid) throw new TypeError('kid: give the key a name, for example "my-app-2026"');
  return { kid, privateKey: generatePrivateKey() };
}

/** The public key set to publish (for example at /.well-known/aar-keys.json) so others can check your records. */
export function publicKeys(...keys: SigningKey[]): Jwks {
  return { keys: keys.map(toJwk) };
}
