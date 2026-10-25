import { canonicalDigest } from './crypto/hash.js';
import { findPublicKey, signCanonical, verifyCanonical, type Jwks, type SigningKey } from './crypto/keys.js';

// Open Action Record (OAR), version 0.3. See SPEC.md.
//
// One action produces a short life of records: a decision (allowed, held or denied), optionally a person's
// approval or rejection, an execution with commitments to the affected state before and after, and a
// confirmation read back from the system of record. Each record is signed by its issuer, may be countersigned
// by a separate sealing service, and links to the agent's previous record.
//
// Wire names keep the prefix of the format's first name, Agent Action Receipts: `aar_version`,
// `/.well-known/aar-keys.json`. Records written by earlier implementations (including "0.2-mvp") still verify.

export const OAR_VERSION = '0.3';
export const OAR_VERSIONS = ['0.2-mvp', '0.3'] as const;
export type OarVersion = (typeof OAR_VERSIONS)[number];

export type Phase = 'decision' | 'execution' | 'confirmation';
export type RecordResult =
  /** Decision records. */
  | 'allowed'
  | 'denied'
  | 'held'
  /** Approval records (phase "decision"): a person's decision on a held action. */
  | 'approved'
  | 'rejected'
  | 'expired'
  /** Execution records. */
  | 'executed'
  | 'failed'
  /** Confirmation records: the system of record shows what the execution record says, or it does not. */
  | 'confirmed'
  | 'not_confirmed';

export type ApprovalMethod = 'standing_mandate' | 'button' | 'passkey';

/** A receipt in another format that this OAR record adds approval and outcome evidence to. */
export interface ExternalRef {
  /** Short name of the other format, for example "acta", "scitt", "agent-receipts", "pipelock". */
  format: string;
  /** "sha256:<hex>" of the other receipt's bytes, exactly as it was issued. */
  digest: string;
  /** Optional identifier of the other receipt in its own system. */
  id?: string;
}

export interface Payload {
  aar_version: OarVersion;
  /** "urn:uuid:...". */
  receipt_id: string;
  phase: Phase;
  org_id: string;
  agent_id: string;
  run_id: string;
  /** `type` is the kind of action ("refund", "db.delete"); `target` names the system it acts on ("stripe"). Never personal data. */
  action: { type: string; target: string };
  /** Commitment to the exact action instance: its parameters and idempotency key. The same for every record of one action. */
  instance_commitment: string;
  /** "sha256:<hex>" of the rules (policy) that decided. */
  authorization_ref: string;
  /** Who or what authorized: "approver:<ref>" or "policy:<id>". */
  principal: string;
  approval?: {
    method: ApprovalMethod;
    approver?: string;
    at: string;
    /** Passkey approvals: "sha256:<hex>" of the WebAuthn assertion, kept in full by the issuer. */
    assertion_digest?: string;
  };
  /** Commitment to limit usage at decision time (for example today's total before and after). */
  consumption_commitment?: string;
  result: RecordResult;
  /** Machine-readable reasons, for example "within_limits", "over_approval_limit", "outcome_confirmed". */
  reasons: string[];
  /** False when the decision was recorded but not enforced (observe mode). */
  enforced: boolean;
  /** Approval, execution and confirmation records: the `receipt_id` of the record this one follows from. */
  decision_ref?: string;
  /** Execution and confirmation records: commitment to the identifier of what changed (a refund ID, a row key). */
  target_ref_commitment?: string;
  /** Execution records: commitments to the affected state just before and just after the change. */
  state_before_commitment?: string;
  state_after_commitment?: string;
  /** Optional: the receipt in another format that this record adds evidence to. */
  external_ref?: ExternalRef;
  issued_at: string;
  /** Hash of this agent's previous record. Omitted on the agent's first record. */
  prev_receipt_hash?: string;
}

export interface IssuerSignature {
  alg: 'EdDSA';
  kid: string;
  sig: string;
}

export interface Seal {
  sealer_kid: string;
  seq: number;
  sealed_at: string;
  sig: string;
}

/** A signed record. `seal` is present when a separate sealing service countersigned it. */
export interface OarRecord {
  payload: Payload;
  issuer_sig: IssuerSignature;
  seal?: Seal;
}

export interface Checkpoint {
  count: number;
  head_digest: string;
  at: string;
}

export interface SignedCheckpoint extends Checkpoint {
  sealer_kid: string;
  sig: string;
  /** Outside timestamps on this checkpoint. Not covered by the sealer's signature. */
  anchors?: CheckpointAnchor[];
}

/** An RFC 3161 timestamp from an outside authority over the signed checkpoint. */
export interface CheckpointAnchor {
  type: 'rfc3161';
  /** The authority's name, from its signing certificate. */
  tsa: string;
  /** When the authority signed, RFC 3339 UTC. */
  gen_time: string;
  /** The timestamp token (CMS SignedData), DER, base64. */
  token: string;
}

/** sha256 of the canonical payload: the only thing a sealing service needs to see. */
export function payloadHash(payload: Payload): string {
  return canonicalDigest(payload);
}

/** Hash of a whole record, used as the next record's `prev_receipt_hash`. */
export function recordHash(record: OarRecord): string {
  return canonicalDigest(record);
}

/** Issuer step: sign the canonical payload. */
export function signRecord(payload: Payload, issuer: SigningKey): OarRecord {
  return { payload, issuer_sig: { alg: 'EdDSA', kid: issuer.kid, sig: signCanonical(payload, issuer.privateKey) } };
}

export function verifyIssuerSignature(record: OarRecord, issuerKeys: Jwks): boolean {
  const { issuer_sig: sig } = record;
  if (sig?.alg !== 'EdDSA') return false;
  const key = findPublicKey(issuerKeys, sig.kid);
  return key !== undefined && verifyCanonical(record.payload, sig.sig, key);
}

/** What the sealing service signs for each seal. */
export function sealStatement(digest: string, seq: number, sealedAt: string): { digest: string; seq: number; sealed_at: string } {
  return { digest, seq, sealed_at: sealedAt };
}

/** Sealing step: countersign a payload digest at a sequence number. */
export function createSeal(digest: string, seq: number, sealedAt: string, sealer: SigningKey): Seal {
  if (!Number.isSafeInteger(seq) || seq < 1) throw new RangeError('seq must be a positive integer');
  return { sealer_kid: sealer.kid, seq, sealed_at: sealedAt, sig: signCanonical(sealStatement(digest, seq, sealedAt), sealer.privateKey) };
}

/** True when the seal is a valid sealer signature over this record's payload digest. */
export function verifySeal(record: OarRecord, sealerKeys: Jwks): boolean {
  const { seal } = record;
  if (!seal) return false;
  const key = findPublicKey(sealerKeys, seal.sealer_kid);
  if (!key) return false;
  return verifyCanonical(sealStatement(payloadHash(record.payload), seal.seq, seal.sealed_at), seal.sig, key);
}

/**
 * The sealing service's append-only log is hash-chained: each head covers every earlier seal. Checkpoints sign
 * the head, so a missing or truncated record changes the recomputed head.
 */
export function nextLogHead(prevHead: string | null, entry: { seq: number; digest: string; sealed_at: string }): string {
  return canonicalDigest({ prev: prevHead, ...sealStatement(entry.digest, entry.seq, entry.sealed_at) });
}

export function signCheckpoint(checkpoint: Checkpoint, sealer: SigningKey): SignedCheckpoint {
  const body: Checkpoint = { count: checkpoint.count, head_digest: checkpoint.head_digest, at: checkpoint.at };
  return { ...body, sealer_kid: sealer.kid, sig: signCanonical(body, sealer.privateKey) };
}

export function verifyCheckpoint(checkpoint: SignedCheckpoint, sealerKeys: Jwks): boolean {
  const key = findPublicKey(sealerKeys, checkpoint.sealer_kid);
  if (!key) return false;
  const body: Checkpoint = { count: checkpoint.count, head_digest: checkpoint.head_digest, at: checkpoint.at };
  return verifyCanonical(body, checkpoint.sig, key);
}
