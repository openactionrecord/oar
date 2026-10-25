import { randomBytes, timingSafeEqual } from 'node:crypto';
import { canonicalDigest, isSha256Digest } from './hash.js';
import { bytesToHex } from './encoding.js';

// Salted commitments keep amounts, addresses and customer details out of records (SPEC.md, "Commitments").
// commitment = "sha256:" + hex(sha256(canonicalize({ salt, value }))), with a fresh 32-byte salt.

export interface Commitment {
  commitment: string;
  /** Hex salt. Keep it with the writer of the record; share it only to disclose the value. Never put it in a record. */
  salt: string;
}

export function newSalt(): string {
  return bytesToHex(randomBytes(32));
}

export function commitmentFor(value: unknown, salt: string): string {
  if (!/^[0-9a-f]{64}$/.test(salt)) throw new TypeError('Salt must be 32 bytes of lower-case hex');
  return canonicalDigest({ salt, value });
}

export function commit(value: unknown): Commitment {
  const salt = newSalt();
  return { commitment: commitmentFor(value, salt), salt };
}

export function verifyCommitment(commitment: string, salt: string, value: unknown): boolean {
  if (!isSha256Digest(commitment)) return false;
  let expected: string;
  try {
    expected = commitmentFor(value, salt);
  } catch {
    return false;
  }
  return timingSafeEqual(Buffer.from(expected), Buffer.from(commitment));
}
