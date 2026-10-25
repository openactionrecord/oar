import { base64UrlToBytes, bytesToHex } from './crypto/encoding.js';
import type { Jwk, Jwks } from './crypto/keys.js';
import type { OarRecord, SignedCheckpoint } from './record.js';
import { verify, type DisclosureField, type DisclosureInput, type VerificationKeys, type VerificationReport, type VerifyOptions } from './verify.js';

// An evidence bundle: one self-contained JSON file that anyone can verify offline. It carries the records, the
// public keys, the sealing service's checkpoints (if any) and, optionally, disclosures that open commitments.
//
// Format "oar-bundle/0.1". Evidence packages written as "aar-evidence/0.1" (which call the records "receipts")
// are read too.

export const BUNDLE_FORMAT = 'oar-bundle/0.1';
export const LEGACY_BUNDLE_FORMATS = ['aar-evidence/0.1'] as const;

export type BundlePurpose = 'dispute' | 'audit' | 'insurance' | 'board' | 'debugging';

export interface Bundle {
  format: typeof BUNDLE_FORMAT | (typeof LEGACY_BUNDLE_FORMATS)[number];
  generated_at: string;
  org: { id: string; name: string };
  purpose?: BundlePurpose;
  scope: {
    action_id?: string;
    from?: string;
    to?: string;
    /** True only when the bundle holds every record up to its latest checkpoint. */
    complete: boolean;
  };
  records: OarRecord[];
  disclosures: DisclosureInput[];
  checkpoints: SignedCheckpoint[];
  keys: VerificationKeys;
}

const FIELDS: readonly DisclosureField[] = ['instance', 'consumption', 'target_ref', 'state_before', 'state_after'];

export class BundleError extends Error {
  override name = 'BundleError';
}

/** Reads a bundle (or a legacy evidence package). Throws a BundleError that says what is wrong. */
export function parseBundle(raw: unknown): Bundle {
  const problems: string[] = [];
  const obj = (raw ?? {}) as Record<string, unknown>;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new BundleError('Not a bundle: expected a JSON object.');

  const format = obj.format;
  if (format !== BUNDLE_FORMAT && !LEGACY_BUNDLE_FORMATS.includes(format as never)) {
    problems.push(`format: expected "${BUNDLE_FORMAT}", got ${JSON.stringify(format)}`);
  }
  const records = (obj.records ?? obj.receipts) as unknown;
  if (!Array.isArray(records)) problems.push('records: expected an array of records');
  else records.forEach((r, i) => {
    if (typeof r !== 'object' || r === null || !('payload' in r) || !('issuer_sig' in r)) problems.push(`records[${i}]: expected { payload, issuer_sig, seal? }`);
  });
  const keys = obj.keys as Record<string, unknown> | undefined;
  if (!keys || !isJwks(keys.issuer)) problems.push('keys.issuer: expected a JWK set ({ "keys": [...] })');
  if (keys && keys.sealer !== undefined && !isJwks(keys.sealer)) problems.push('keys.sealer: expected a JWK set');
  const disclosures = (obj.disclosures ?? []) as unknown;
  if (!Array.isArray(disclosures)) problems.push('disclosures: expected an array');
  else disclosures.forEach((d, i) => {
    const x = d as Record<string, unknown>;
    if (typeof x?.receiptId !== 'string' || typeof x.salt !== 'string' || !FIELDS.includes(x.field as DisclosureField)) {
      problems.push(`disclosures[${i}]: expected { receiptId, field, salt, value }`);
    }
  });
  const checkpoints = (obj.checkpoints ?? []) as unknown;
  if (!Array.isArray(checkpoints)) problems.push('checkpoints: expected an array');
  const scope = (obj.scope ?? { complete: false }) as Bundle['scope'];
  if (typeof scope.complete !== 'boolean') problems.push('scope.complete: expected true or false');

  if (problems.length > 0) throw new BundleError(`Not a valid bundle:\n- ${problems.join('\n- ')}`);
  const org = (obj.org ?? { id: 'unknown', name: 'unknown' }) as Bundle['org'];
  return {
    format: format as Bundle['format'],
    generated_at: String(obj.generated_at ?? ''),
    org: { id: String(org.id ?? 'unknown'), name: String(org.name ?? org.id ?? 'unknown') },
    ...(obj.purpose ? { purpose: obj.purpose as BundlePurpose } : {}),
    scope,
    records: records as OarRecord[],
    disclosures: disclosures as DisclosureInput[],
    checkpoints: checkpoints as SignedCheckpoint[],
    keys: { issuer: keys!.issuer as Jwks, ...(keys!.sealer ? { sealer: keys!.sealer as Jwks } : {}) },
  };
}

function isJwks(v: unknown): v is Jwks {
  return typeof v === 'object' && v !== null && Array.isArray((v as Jwks).keys) && (v as Jwks).keys.every(isJwk);
}

function isJwk(k: unknown): k is Jwk {
  const j = k as Jwk;
  return typeof j === 'object' && j !== null && j.kty === 'OKP' && j.crv === 'Ed25519' && typeof j.x === 'string' && typeof j.kid === 'string';
}

/**
 * Verifies a bundle. By default it uses the keys inside the bundle; pass `keys` you obtained independently (for
 * example from the issuer's published key set) to rule out a substituted bundle. Everything is recomputed.
 */
export function verifyBundle(input: unknown, options: VerifyOptions & { keys?: VerificationKeys } = {}): VerificationReport {
  const bundle = parseBundle(input);
  const { keys, ...rest } = options;
  return verify(bundle.records, bundle.disclosures, bundle.checkpoints, keys ?? bundle.keys, { partial: !bundle.scope.complete, ...rest });
}

/** Short, comparable fingerprints of a key set: "kid: <first 16 hex of the public key>". */
export function keyFingerprints(jwks: Jwks): string[] {
  return jwks.keys.map((k) => {
    let hex = 'invalid';
    try {
      hex = bytesToHex(base64UrlToBytes(k.x)).slice(0, 16);
    } catch {
      // Leave as invalid.
    }
    return `${k.kid}: ${hex}`;
  });
}
