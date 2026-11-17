import { canonicalDigest, isSha256Digest } from './crypto/hash.js';
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, hexToBytes } from './crypto/encoding.js';
import type { Payload } from './record.js';

// Approval binding (SPEC.md section 4.3): the value an approver's device or an outside approval service is asked
// to confirm. It is derived from the held action, the exact action instance, what the approver was shown and a
// fresh nonce, so a confirmation of it cannot be reused for another action, amount or recipient.

export const APPROVAL_PURPOSE = 'oar.approval';

export type BoundDecision = 'approve' | 'reject';

export interface ApprovalBinding {
  /** Binding version. 2 adds what the approver was shown, and allows a binding without the decision. */
  v: 2;
  /** 32 random bytes, lower-case hex. Fresh for every request. */
  nonce: string;
  /** Present when the approver's own device signs the decision (a passkey): the decision it signed. */
  decision?: BoundDecision;
  /** "sha256:<hex>" of the binding input. Its 32 bytes are the WebAuthn challenge, or the value sent to the outside service. */
  digest: string;
}

/** Proof from an outside approval service (a bank app, a SIM check, a digital identity wallet). */
export interface ApprovalEvidence {
  /** Who checked the approver, for example "sim-check" or "bank-app". */
  provider: string;
  /** The format of the proof, for example "jws" or "provider-json". */
  format: string;
  /** "sha256:<hex>" of the proof's bytes, exactly as received. */
  digest: string;
  /** The proof's identifier in the provider's system, optional. */
  id?: string;
}

export interface BindingInput {
  /** The held decision's `receipt_id`. */
  actionId: string;
  instanceCommitment: string;
  /** Commitment to what the approver was shown, if recorded. */
  displayCommitment?: string;
  nonce: string;
  decision?: BoundDecision;
}

export function bindingDigest(input: BindingInput): string {
  return canonicalDigest({
    v: 2,
    purpose: APPROVAL_PURPOSE,
    action_id: input.actionId,
    instance_commitment: input.instanceCommitment,
    display_commitment: input.displayCommitment ?? null,
    nonce: input.nonce,
    ...(input.decision ? { decision: input.decision } : {}),
  });
}

/** The WebAuthn challenge for a binding: the 32 digest bytes, base64url. */
export function bindingChallenge(digest: string): string {
  return bytesToBase64Url(hexToBytes(digest.slice('sha256:'.length), 32));
}

/** The digest a WebAuthn challenge stands for (the reverse of `bindingChallenge`). */
export function challengeDigest(challenge: string): string {
  return `sha256:${bytesToHex(base64UrlToBytes(challenge))}`;
}

/**
 * Checks one record's approval evidence. Returns undefined when there is nothing to check, or a list of
 * problems (empty when it passes).
 */
export function checkApproval(payload: Payload): string[] | undefined {
  const approval = payload.approval;
  if (!approval || (approval.binding === undefined && approval.method !== 'external')) return undefined;
  const problems: string[] = [];
  if (approval.method === 'external') {
    const e = approval.evidence;
    if (!e || typeof e.provider !== 'string' || !e.provider || typeof e.format !== 'string' || !e.format || !isSha256Digest(e.digest)) {
      problems.push('An approval by an outside service must name the provider and format and carry the digest of its proof.');
    }
    if (!approval.binding) problems.push('An approval by an outside service must carry the binding it was asked to confirm.');
  }
  const b = approval.binding;
  if (b) {
    if (b.v !== 2 || typeof b.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(b.nonce) || !isSha256Digest(b.digest)) {
      problems.push('The approval binding is malformed.');
    } else if (typeof payload.decision_ref !== 'string') {
      problems.push('The approval binding names no held action (decision_ref is missing).');
    } else {
      const expected = bindingDigest({
        actionId: payload.decision_ref,
        instanceCommitment: payload.instance_commitment,
        ...(approval.display_commitment ? { displayCommitment: approval.display_commitment } : {}),
        nonce: b.nonce,
        ...(b.decision ? { decision: b.decision } : {}),
      });
      if (expected !== b.digest) problems.push('The approval binding does not match this action, what the approver was shown, or its nonce.');
      if (b.decision === 'approve' && payload.result !== 'approved') problems.push('The approver signed an approval, but the record says otherwise.');
      if (b.decision === 'reject' && payload.result !== 'rejected') problems.push('The approver signed a rejection, but the record says otherwise.');
    }
  }
  return problems;
}
