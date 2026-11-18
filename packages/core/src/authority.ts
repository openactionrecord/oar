import { canonicalDigest, isSha256Digest } from './crypto/hash.js';
import type { Payload } from './record.js';

// Authority set (SPEC.md section 4.5): the outside artifacts a decision relied on (a delegated authorization, a
// credential proof, a session, an OAuth grant, an approval service's result), bound to the one action by the signed
// decision record, and re-checked at the moment the action commits.

export const AUTHORITY_PURPOSE = 'oar.authorities';

export type AuthorityStatus = 'valid' | 'expired' | 'revoked' | 'invalid' | 'unknown';
export const AUTHORITY_STATUSES: readonly AuthorityStatus[] = ['valid', 'expired', 'revoked', 'invalid', 'unknown'];

export interface Authority {
  /** The kind of artifact, for example "aauth", "x401", "poppy", "oauth-rar", "sim-check", "mandate". */
  type: string;
  /** Who issued it: a URL, domain or other stable identifier. Not personal data. */
  issuer: string;
  /** "sha256:<hex>" of the artifact's bytes exactly as received. */
  digest: string;
  /** The artifact's own validity window, RFC 3339 UTC. */
  not_before?: string;
  expires_at?: string;
  /** When the receiver checked it, RFC 3339 UTC, and what it found. */
  checked_at: string;
  status: AuthorityStatus;
}

export interface AuthorityCheck {
  /** When the authority set was checked again, just before the action committed. RFC 3339 UTC. */
  checked_at: string;
  /** `authoritySetDigest` of the authority set this check covers. */
  set_digest: string;
  /** "current": every authority still valid; "changed": at least one changed, so the action did not run. */
  result: 'current' | 'changed';
  /** For "changed": which authorities changed, by index, and to what. */
  changes?: { index: number; status: AuthorityStatus }[];
}

export function authoritySetDigest(authorities: readonly Authority[]): string {
  return canonicalDigest({ v: 1, purpose: AUTHORITY_PURPOSE, authorities });
}

const isTime = (v: unknown): v is string => typeof v === 'string' && !Number.isNaN(Date.parse(v));
const isStatus = (v: unknown): v is AuthorityStatus => typeof v === 'string' && (AUTHORITY_STATUSES as readonly string[]).includes(v);
const ACCEPTED = new Set(['allowed', 'approved']);

function checkSet(authorities: unknown): string[] {
  if (!Array.isArray(authorities) || authorities.length === 0) return ['The authority set is malformed: it must be a non-empty list.'];
  const problems: string[] = [];
  authorities.forEach((a: Partial<Authority>, i) => {
    if (typeof a !== 'object' || a === null || typeof a.type !== 'string' || !a.type || typeof a.issuer !== 'string' || !a.issuer || !isSha256Digest(a.digest) || !isTime(a.checked_at) || !isStatus(a.status)) {
      problems.push(`Authority ${i + 1} is malformed: it needs type, issuer, a sha256 digest, checked_at and a status.`);
      return;
    }
    if ((a.not_before !== undefined && !isTime(a.not_before)) || (a.expires_at !== undefined && !isTime(a.expires_at))) problems.push(`Authority ${i + 1} has an invalid validity window.`);
    else if (a.status === 'valid' && a.expires_at && Date.parse(a.expires_at) <= Date.parse(a.checked_at)) problems.push(`Authority ${i + 1} is recorded as valid, but it had expired when it was checked.`);
    else if (a.status === 'valid' && a.not_before && Date.parse(a.not_before) > Date.parse(a.checked_at)) problems.push(`Authority ${i + 1} is recorded as valid, but it was not yet valid when it was checked.`);
  });
  return problems;
}

/** The nearest record at or before this one, following decision_ref, that carries an authority set. */
function withAuthorities(payload: Payload, byId: ReadonlyMap<string, Payload>): Payload | undefined {
  let current: Payload | undefined = payload;
  for (let i = 0; current && i < 16; i++) {
    if (current.authorities !== undefined) return current;
    current = current.decision_ref ? byId.get(current.decision_ref) : undefined;
  }
  return undefined;
}

/**
 * Check 8 (SPEC.md section 6): problems with one record's authority set or authority check, or undefined when
 * there is nothing to check. `byId` maps receipt ids to the payloads of the bundle's records.
 */
export function checkAuthority(payload: Payload, byId: ReadonlyMap<string, Payload>): string[] | undefined {
  const problems: string[] = [];
  let checked = false;

  if (payload.authorities !== undefined) {
    checked = true;
    const set = checkSet(payload.authorities);
    problems.push(...set);
    if (!set.length && ACCEPTED.has(payload.result) && payload.authorities.some((a) => a.status !== 'valid')) {
      problems.push(`The action was ${payload.result}, but not every authority it relied on was valid.`);
    }
  }

  if (payload.phase === 'execution') {
    const source = payload.decision_ref ? withAuthorities(byId.get(payload.decision_ref) ?? ({} as Payload), byId) : undefined;
    const c = payload.authority_check;
    if (c !== undefined) {
      checked = true;
      if (!isTime(c.checked_at) || !isSha256Digest(c.set_digest) || (c.result !== 'current' && c.result !== 'changed')) {
        problems.push('The authority check is malformed.');
      } else if (!source?.authorities) {
        problems.push('The authority check names no authority set: no earlier record of this action carries one.');
      } else {
        if (authoritySetDigest(source.authorities) !== c.set_digest) problems.push('The authority check covers a different authority set than the decision relied on.');
        if (c.result === 'current') {
          const stale = source.authorities.findIndex((a) => a.expires_at !== undefined && Date.parse(a.expires_at) <= Date.parse(c.checked_at));
          if (stale >= 0) problems.push(`The authority check says every authority was current, but authority ${stale + 1} had expired by then.`);
          if (payload.result === 'refused') problems.push('The authority check says every authority was current, but the action was recorded as refused.');
        } else if (payload.result !== 'refused') {
          problems.push('An authority changed before the action committed, but the action was not recorded as refused.');
        }
      }
    } else if (source?.authorities && payload.result === 'executed') {
      checked = true;
      problems.push('The action ran without its authority set being checked again at the moment it committed.');
    }
  }

  return checked ? problems : undefined;
}
