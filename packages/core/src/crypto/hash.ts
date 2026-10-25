import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.js';

export const SHA256_PREFIX = 'sha256:';

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** "sha256:<hex>" of the RFC 8785 canonical form of `value`. */
export function canonicalDigest(value: unknown): string {
  return SHA256_PREFIX + sha256Hex(canonicalBytes(value));
}

export function isSha256Digest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}
