import { verifyCommitment } from './crypto/commitment.js';
import type { Jwks } from './crypto/keys.js';
import {
  recordHash,
  nextLogHead,
  payloadHash,
  verifyCheckpoint,
  verifyIssuerSignature,
  verifySeal,
  type OarRecord,
  type Payload,
  type SignedCheckpoint,
} from './record.js';
import { anchorDigest, verifyTimestampToken, type TimestampResult } from './timestamp/timestamp.js';
import { TSA_ROOTS, type TsaRoot } from './timestamp/tsa-roots.js';

// Verification (SPEC.md, "Verification"): issuer signature, seal, chain, checkpoint coverage, optional
// disclosures, and the outside timestamp on the checkpoint covering each record.
//
// Records may be issuer-signed only (no sealing service). They still verify, at a lower evidence level, unless
// `requireSeal` is set. Every report states the level it reached, so a stripped seal cannot pass unnoticed.

export type CheckName = 'issuer_signature' | 'seal' | 'chain' | 'checkpoint' | 'disclosures' | 'timestamp';
export type CheckResult = 'pass' | 'fail' | 'not_checked';

export const CHECK_LABELS: Record<CheckName, string> = {
  issuer_signature: 'Issuer signature',
  seal: 'Seal',
  chain: 'Chain',
  checkpoint: 'Checkpoint coverage',
  disclosures: 'Disclosures',
  timestamp: 'Outside timestamp',
};

export type DisclosureField = 'instance' | 'consumption' | 'target_ref' | 'state_before' | 'state_after';

export interface DisclosureInput {
  /** The receipt's `receipt_id` ("urn:uuid:..."). */
  receiptId: string;
  field: DisclosureField;
  salt: string;
  value: unknown;
}

export interface VerificationKeys {
  issuer: Jwks;
  /** The sealing service's keys. Omit for issuer-signed records. */
  sealer?: Jwks;
}

/**
 * How strong the evidence is:
 * - "issuer-signed": signed by the party that wrote it; any later change shows, but the writer could rewrite its own history.
 * - "sealed": also countersigned by a separate sealing service and covered by its hash-chained log.
 * - "timestamped": sealed, and the covering checkpoint carries an outside RFC 3161 timestamp, so nobody can change,
 *   delete or backdate it without it showing.
 */
export type EvidenceLevel = 'issuer-signed' | 'sealed' | 'timestamped';

export const LEVEL_LABELS: Record<EvidenceLevel, string> = {
  'issuer-signed': 'Issuer-signed',
  sealed: 'Sealed by a separate service',
  timestamped: 'Sealed and timestamped by an outside authority',
};

export interface VerifyOptions {
  /**
   * Set when verifying a subset of records (an evidence package for one action). Gaps in the chain and
   * missing earlier records are then reported as not checked rather than failures.
   */
  partial?: boolean;
  /** Root certificates accepted for outside timestamps. Defaults to the bundled DigiCert roots. */
  tsaRoots?: readonly TsaRoot[];
  /** Fail records that carry no seal. Default false: they pass at the "issuer-signed" level. */
  requireSeal?: boolean;
}

export interface ReceiptReport {
  receiptId: string;
  agentId: string;
  seq?: number;
  checks: Record<CheckName, CheckResult>;
  result: 'pass' | 'fail';
  /** The evidence level this record reached (meaningful when it passed). */
  level: EvidenceLevel;
  messages: string[];
}

export interface VerificationReport {
  result: 'pass' | 'fail';
  receipts: ReceiptReport[];
  checkpoint?: { count: number; at: string };
  /** The latest checkpoint with a valid outside timestamp: who signed it, when, and how many seals it covers. */
  timestamp?: { tsa: string; at: string; count: number };
  /** Checks that failed anywhere, for headlines like "Chain check failed". */
  failedChecks: CheckName[];
  /** The lowest evidence level among the records (the level the whole set can claim). */
  level: EvidenceLevel;
  messages: string[];
}

const COMMITMENT_FIELD: Record<DisclosureField, keyof Payload> = {
  instance: 'instance_commitment',
  consumption: 'consumption_commitment',
  target_ref: 'target_ref_commitment',
  state_before: 'state_before_commitment',
  state_after: 'state_after_commitment',
};

interface Entry {
  envelope: OarRecord;
  report: ReceiptReport;
  sealValid: boolean;
}

export function verify(
  envelopes: readonly OarRecord[],
  disclosures: readonly DisclosureInput[] | undefined,
  checkpoints: readonly SignedCheckpoint[],
  keys: VerificationKeys,
  options: VerifyOptions = {},
): VerificationReport {
  const messages: string[] = [];
  let reportFailed = false;

  const entries: Entry[] = envelopes.map((envelope) => {
    const report: ReceiptReport = {
      receiptId: String(envelope.payload?.receipt_id ?? 'unknown'),
      agentId: String(envelope.payload?.agent_id ?? 'unknown'),
      ...(envelope.seal ? { seq: envelope.seal.seq } : {}),
      checks: { issuer_signature: 'fail', seal: 'fail', chain: 'not_checked', checkpoint: 'not_checked', disclosures: 'not_checked', timestamp: 'not_checked' },
      result: 'pass',
      level: 'issuer-signed',
      messages: [],
    };

    if (verifyIssuerSignature(envelope, keys.issuer)) {
      report.checks.issuer_signature = 'pass';
    } else {
      report.messages.push('The issuer signature does not match this record. It was changed after signing or signed with an unknown key.');
    }

    const sealValid = keys.sealer !== undefined && verifySeal(envelope, keys.sealer);
    if (sealValid) {
      report.checks.seal = 'pass';
    } else if (!envelope.seal) {
      if (options.requireSeal) {
        report.messages.push('This record has not been sealed.');
      } else {
        report.checks.seal = 'not_checked';
        report.messages.push('Issuer-signed only: not countersigned by a separate sealing service.');
      }
    } else {
      report.messages.push('The seal does not match this record. It was changed after sealing or sealed with an unknown key.');
    }

    return { envelope, report, sealValid };
  });

  checkChains(entries, options);

  const sealerKeys = keys.sealer ?? { keys: [] };
  const coverage = checkCheckpoints(entries, checkpoints, sealerKeys, options);
  messages.push(...coverage.messages);
  if (coverage.failed) reportFailed = true;

  const stamps = checkTimestamps(entries, checkpoints, sealerKeys, options);
  messages.push(...stamps.messages);
  if (stamps.failed) reportFailed = true;

  const disclosureMessages = checkDisclosures(entries, disclosures ?? []);
  messages.push(...disclosureMessages);

  const failedChecks = new Set<CheckName>();
  for (const { report } of entries) {
    for (const [name, result] of Object.entries(report.checks) as [CheckName, CheckResult][]) {
      if (result === 'fail') failedChecks.add(name);
    }
    report.result = Object.values(report.checks).includes('fail') ? 'fail' : 'pass';
    report.level = report.checks.timestamp === 'pass' ? 'timestamped' : report.checks.seal === 'pass' ? 'sealed' : 'issuer-signed';
  }
  const order: EvidenceLevel[] = ['issuer-signed', 'sealed', 'timestamped'];
  const level = entries.length === 0 ? 'issuer-signed' : order[Math.min(...entries.map((e) => order.indexOf(e.report.level)))]!;
  if (coverage.failed) failedChecks.add('checkpoint');
  if (stamps.failed) failedChecks.add('timestamp');

  const failed = reportFailed || entries.some((e) => e.report.result === 'fail');
  const failedList = [...failedChecks];
  messages.unshift(
    failed
      ? `Verification failed: ${failedList.map((c) => CHECK_LABELS[c]).join(', ')} check failed.`
      : `All ${entries.length} records passed verification. Evidence level: ${LEVEL_LABELS[level]}.`,
  );

  return {
    result: failed ? 'fail' : 'pass',
    receipts: entries.map((e) => e.report),
    ...(coverage.checkpoint ? { checkpoint: coverage.checkpoint } : {}),
    ...(stamps.timestamp ? { timestamp: stamps.timestamp } : {}),
    failedChecks: failedList,
    level,
    messages,
  };
}

/** Each agent's records form a hash chain through `prev_receipt_hash`, ordered by seal sequence. */
function checkChains(entries: Entry[], options: VerifyOptions): void {
  const byAgent = new Map<string, Entry[]>();
  for (const entry of entries) {
    const list = byAgent.get(entry.report.agentId) ?? [];
    list.push(entry);
    byAgent.set(entry.report.agentId, list);
  }

  for (const list of byAgent.values()) {
    const ordered = [...list].sort(chainOrder);
    ordered.forEach((entry, i) => {
      const { report } = entry;
      const prevHash = entry.envelope.payload.prev_receipt_hash;
      const previous = ordered[i - 1];

      if (!previous) {
        if (prevHash === undefined) {
          report.checks.chain = 'pass';
        } else if (options.partial) {
          report.messages.push('The earlier record in the chain is not included, so this link was not checked.');
        } else {
          report.checks.chain = 'fail';
          report.messages.push("The record before this one in the agent's chain is missing.");
        }
        return;
      }

      if (prevHash !== undefined && prevHash === recordHash(previous.envelope)) {
        report.checks.chain = 'pass';
      } else if (options.partial && prevHash !== undefined) {
        report.messages.push('The earlier record in the chain is not included, so this link was not checked.');
      } else {
        report.checks.chain = 'fail';
        report.messages.push(
          prevHash === undefined
            ? "This record claims to be the agent's first, but earlier records exist."
            : "This record does not link to the previous record in the agent's chain. A record was changed, removed or inserted.",
        );
      }
    });
  }
}

function chainOrder(a: Entry, b: Entry): number {
  const seqA = a.envelope.seal?.seq ?? Number.POSITIVE_INFINITY;
  const seqB = b.envelope.seal?.seq ?? Number.POSITIVE_INFINITY;
  if (seqA !== seqB) return seqA - seqB;
  return String(a.envelope.payload.issued_at).localeCompare(String(b.envelope.payload.issued_at));
}

interface CoverageResult {
  failed: boolean;
  messages: string[];
  checkpoint?: { count: number; at: string };
}

function checkCheckpoints(
  entries: Entry[],
  checkpoints: readonly SignedCheckpoint[],
  sealerKeys: Jwks,
  options: VerifyOptions,
): CoverageResult {
  const messages: string[] = [];
  let failed = false;

  const valid = checkpoints.filter((cp) => verifyCheckpoint(cp, sealerKeys));
  if (valid.length < checkpoints.length) {
    failed = true;
    messages.push(`${checkpoints.length - valid.length} checkpoint(s) have an invalid sealer signature.`);
  }

  const latest = valid.reduce<SignedCheckpoint | undefined>((best, cp) => (!best || cp.count > best.count ? cp : best), undefined);
  if (!latest) {
    for (const { report, envelope } of entries) if (envelope.seal) report.messages.push('No checkpoint is available yet, so coverage was not checked.');
    return { failed, messages };
  }
  const summary = { count: latest.count, at: latest.at };

  const covered = entries.filter((e) => e.envelope.seal && e.envelope.seal.seq <= latest.count);
  for (const { envelope, report } of entries) {
    if (!envelope.seal) report.messages.push('Not sealed, so not covered by a checkpoint.');
    else if (envelope.seal.seq > latest.count) report.messages.push('Not yet covered by a checkpoint.');
  }

  if (options.partial) {
    // A subset cannot recompute the log head; a valid seal numbered within the checkpoint is the evidence.
    for (const { report, sealValid } of covered) {
      report.checks.checkpoint = sealValid ? 'pass' : 'fail';
      if (!sealValid) report.messages.push('Coverage cannot be confirmed because the seal is invalid.');
    }
    return { failed, messages, checkpoint: summary };
  }

  // Full set: every seq from 1 to count must be present exactly once, and the log head must match.
  const bySeq = new Map<number, Entry>();
  const duplicates = new Set<number>();
  for (const entry of covered) {
    const seq = entry.envelope.seal!.seq;
    if (bySeq.has(seq)) duplicates.add(seq);
    bySeq.set(seq, entry);
  }
  const missing: number[] = [];
  for (let seq = 1; seq <= latest.count; seq++) if (!bySeq.has(seq)) missing.push(seq);

  let headMatches = false;
  if (missing.length === 0 && duplicates.size === 0) {
    let head: string | null = null;
    for (let seq = 1; seq <= latest.count; seq++) {
      const { envelope } = bySeq.get(seq)!;
      head = nextLogHead(head, { seq, digest: payloadHash(envelope.payload), sealed_at: envelope.seal!.sealed_at });
    }
    headMatches = head === latest.head_digest;
  }

  const ok = headMatches;
  if (!ok) {
    failed = true;
    if (missing.length > 0) {
      messages.push(`${missing.length} record(s) covered by the latest checkpoint are missing (seq ${formatSeqs(missing)}).`);
    } else if (duplicates.size > 0) {
      messages.push(`More than one record uses the same seal number (seq ${formatSeqs([...duplicates])}).`);
    } else {
      messages.push("The records do not match the sealer's latest checkpoint.");
    }
  }
  // When nothing is missing and the mismatch is explained by records whose own seal no longer matches, point
  // at those records only; untouched records still match what the sealer recorded.
  const culprits = !ok && missing.length === 0 && duplicates.size === 0 ? covered.filter((e) => !e.sealValid) : [];
  for (const entry of covered) {
    const { report } = entry;
    if (ok || (culprits.length > 0 && entry.sealValid)) {
      report.checks.checkpoint = 'pass';
    } else {
      report.checks.checkpoint = 'fail';
      report.messages.push(
        culprits.length > 0
          ? `This record does not match what the sealer recorded at checkpoint ${latest.count}.`
          : "The set of records does not match the sealer's latest checkpoint.",
      );
    }
  }
  return { failed, messages, checkpoint: summary };
}

interface TimestampCheck {
  failed: boolean;
  messages: string[];
  timestamp?: { tsa: string; at: string; count: number };
}

/**
 * Each sealed record is timestamped by the first checkpoint with an outside timestamp that covers it. The token
 * must verify, and in a complete set the records must recompute that checkpoint's log head. Records not yet
 * covered are reported as pending, not as failures.
 */
function checkTimestamps(entries: Entry[], checkpoints: readonly SignedCheckpoint[], sealerKeys: Jwks, options: VerifyOptions): TimestampCheck {
  const messages: string[] = [];
  const anchored = checkpoints
    .filter((cp) => (cp.anchors?.length ?? 0) > 0 && verifyCheckpoint(cp, sealerKeys))
    .sort((a, b) => a.count - b.count);
  const heads = options.partial ? undefined : logHeads(entries);

  const results = new Map<SignedCheckpoint, TimestampResult>();
  for (const cp of anchored) {
    const anchor = cp.anchors!.find((a) => a.type === 'rfc3161');
    let result: TimestampResult = anchor
      ? verifyTimestampToken(anchor.token, anchorDigest(cp), options.tsaRoots ?? TSA_ROOTS)
      : { ok: false, reason: 'The timestamp is of an unsupported type.' };
    if (result.ok && heads?.has(cp.count) && heads.get(cp.count) !== cp.head_digest) {
      result = { ok: false, reason: 'The records do not match the timestamped checkpoint.' };
    }
    results.set(cp, result);
    if (!result.ok) messages.push(`The outside timestamp on checkpoint ${cp.count} does not verify: ${result.reason}`);
  }

  let pending = 0;
  for (const { envelope, report, sealValid } of entries) {
    if (!envelope.seal || !sealValid) continue;
    const cp = anchored.find((c) => c.count >= envelope.seal!.seq);
    if (!cp) {
      pending++;
      report.messages.push('Sealed; outside timestamp pending.');
      continue;
    }
    const result = results.get(cp)!;
    report.checks.timestamp = result.ok ? 'pass' : 'fail';
    if (!result.ok) report.messages.push(`The outside timestamp covering this record does not verify: ${result.reason}`);
  }

  const latest = [...anchored].reverse().find((cp) => results.get(cp)?.ok);
  const ok = latest ? (results.get(latest) as Extract<TimestampResult, { ok: true }>) : undefined;
  if (latest && ok) messages.push(`Timestamped by ${ok.tsa} at ${ok.genTime}: the records up to seal ${latest.count} existed then and have not changed since.`);
  if (pending > 0) {
    messages.push(
      latest
        ? `${pending} record${pending === 1 ? ' is' : 's are'} newer than the latest outside timestamp, so ${pending === 1 ? 'its timestamp is' : 'their timestamps are'} pending until the next one.`
        : 'No outside timestamp covers these records yet.',
    );
  }
  return {
    failed: [...results.values()].some((r) => !r.ok),
    messages,
    ...(latest && ok ? { timestamp: { tsa: ok.tsa, at: ok.genTime, count: latest.count } } : {}),
  };
}

/** The sealer's log head after each seq, recomputed from the records, as far as they run without a gap. */
function logHeads(entries: Entry[]): Map<number, string> {
  const bySeq = new Map<number, Entry>();
  for (const entry of entries) if (entry.envelope.seal) bySeq.set(entry.envelope.seal.seq, entry);
  const heads = new Map<number, string>();
  let head: string | null = null;
  for (let seq = 1; bySeq.has(seq); seq++) {
    const { envelope } = bySeq.get(seq)!;
    head = nextLogHead(head, { seq, digest: payloadHash(envelope.payload), sealed_at: envelope.seal!.sealed_at });
    heads.set(seq, head);
  }
  return heads;
}

function formatSeqs(seqs: number[]): string {
  const shown = seqs.slice(0, 10).join(', ');
  return seqs.length > 10 ? `${shown} and ${seqs.length - 10} more` : shown;
}

function checkDisclosures(entries: Entry[], disclosures: readonly DisclosureInput[]): string[] {
  const messages: string[] = [];
  const byId = new Map(entries.map((e) => [e.report.receiptId, e]));

  for (const disclosure of disclosures) {
    const entry = byId.get(disclosure.receiptId);
    if (!entry) {
      messages.push(`A disclosure refers to a record that is not included (${disclosure.receiptId}).`);
      continue;
    }
    const { report, envelope } = entry;
    const commitment = envelope.payload[COMMITMENT_FIELD[disclosure.field]];
    const ok = typeof commitment === 'string' && verifyCommitment(commitment, disclosure.salt, disclosure.value);
    if (ok) {
      if (report.checks.disclosures !== 'fail') report.checks.disclosures = 'pass';
    } else {
      report.checks.disclosures = 'fail';
      report.messages.push(`The disclosed ${disclosure.field.replace('_', ' ')} details do not match the record.`);
    }
  }
  return messages;
}
