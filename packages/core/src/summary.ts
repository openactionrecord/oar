import type { DisclosureInput, VerificationReport } from './verify.js';
import type { OarRecord } from './record.js';

// Turns records into the story of each action, in plain words: what was asked, who approved it, what changed,
// and whether the system of record confirms it.

export type Outcome =
  | 'confirmed'
  | 'not_confirmed'
  | 'executed_unconfirmed'
  | 'failed'
  | 'awaiting_approval'
  | 'denied'
  | 'rejected'
  | 'expired'
  | 'allowed_not_executed';

export const OUTCOME_LABELS: Record<Outcome, string> = {
  confirmed: 'Done, and confirmed in the system of record',
  not_confirmed: 'Executed, but the system of record does NOT show it',
  executed_unconfirmed: 'Executed; no confirmation recorded',
  failed: 'Execution failed',
  awaiting_approval: 'Held, waiting for a person',
  denied: 'Blocked by the rules',
  rejected: 'Rejected by a person',
  expired: 'Approval expired',
  allowed_not_executed: 'Allowed; no execution recorded',
};

export interface ActionStep {
  phase: 'decision' | 'approval' | 'execution' | 'confirmation';
  result: string;
  at: string;
  by: string;
  reasons: string[];
  /** Plain-language line, for example "Approved by approver:jordan (passkey)". */
  text: string;
  verified?: boolean;
}

export interface ActionSummary {
  /** The decision record's id, or the earliest record's id. */
  id: string;
  agent: string;
  type: string;
  target: string;
  outcome: Outcome;
  outcomeText: string;
  /** True when the outcome claim rests only on records that verified. */
  verified?: boolean;
  approvedBy?: string;
  approvalMethod?: string;
  /** State commitments were recorded on execution. */
  stateRecorded: boolean;
  /** Disclosed before/after state, when the bundle discloses them. */
  before?: unknown;
  after?: unknown;
  external?: { format: string; digest: string; id?: string };
  steps: ActionStep[];
}

export function summarize(records: readonly OarRecord[], disclosures: readonly DisclosureInput[] = [], report?: VerificationReport): ActionSummary[] {
  const passed = new Map(report?.receipts.map((r) => [r.receiptId, r.result === 'pass']) ?? []);
  const groups = new Map<string, OarRecord[]>();
  for (const r of records) {
    const key = actionKey(r, records);
    const list = groups.get(key) ?? [];
    list.push(r);
    groups.set(key, list);
  }

  const out: ActionSummary[] = [];
  for (const list of groups.values()) {
    const ordered = [...list].sort((a, b) => (a.seal && b.seal ? a.seal.seq - b.seal.seq : a.payload.issued_at.localeCompare(b.payload.issued_at)));
    const first = ordered[0]!.payload;
    const decision = ordered.find((r) => r.payload.phase === 'decision' && ['allowed', 'held', 'denied'].includes(r.payload.result));
    const approval = [...ordered].reverse().find((r) => r.payload.phase === 'decision' && ['approved', 'rejected', 'expired'].includes(r.payload.result));
    const execution = [...ordered].reverse().find((r) => r.payload.phase === 'execution');
    const confirmation = [...ordered].reverse().find((r) => r.payload.phase === 'confirmation');

    let outcome: Outcome;
    if (confirmation) outcome = confirmation.payload.result === 'confirmed' ? 'confirmed' : 'not_confirmed';
    else if (execution) outcome = execution.payload.result === 'executed' ? 'executed_unconfirmed' : 'failed';
    else if (approval) outcome = approval.payload.result === 'rejected' ? 'rejected' : approval.payload.result === 'expired' ? 'expired' : 'allowed_not_executed';
    else if (decision?.payload.result === 'denied') outcome = 'denied';
    else if (decision?.payload.result === 'held') outcome = 'awaiting_approval';
    else outcome = 'allowed_not_executed';

    const disclosed = (id: string | undefined, field: DisclosureInput['field']) =>
      id === undefined ? undefined : disclosures.find((d) => d.receiptId === id && d.field === field);
    const before = disclosed(execution?.payload.receipt_id, 'state_before');
    const after = disclosed(execution?.payload.receipt_id, 'state_after');
    const steps = ordered.map((r) => step(r, passed.get(r.payload.receipt_id)));
    const verifiedIds = ordered.map((r) => passed.get(r.payload.receipt_id));
    const external = ordered.find((r) => r.payload.external_ref)?.payload.external_ref;

    out.push({
      id: (decision ?? ordered[0]!).payload.receipt_id,
      agent: first.agent_id,
      type: first.action?.type,
      target: first.action?.target,
      outcome,
      outcomeText: OUTCOME_LABELS[outcome],
      ...(report ? { verified: verifiedIds.every((v) => v === true) } : {}),
      ...(approval?.payload.approval?.approver ? { approvedBy: approval.payload.approval.approver, approvalMethod: approval.payload.approval.method } : {}),
      stateRecorded: Boolean(execution?.payload.state_before_commitment && execution.payload.state_after_commitment),
      ...(before ? { before: before.value } : {}),
      ...(after ? { after: after.value } : {}),
      ...(external ? { external } : {}),
      steps,
    });
  }
  return out;
}

function step(r: OarRecord, verified: boolean | undefined): ActionStep {
  const p = r.payload;
  const isApproval = p.phase === 'decision' && ['approved', 'rejected', 'expired'].includes(p.result);
  const phase: ActionStep['phase'] = isApproval ? 'approval' : p.phase;
  const reasons = Array.isArray(p.reasons) ? p.reasons : [];
  const why = reasons.length ? ` (${reasons.join(', ')})` : '';
  let text: string;
  switch (phase) {
    case 'decision':
      text = p.result === 'allowed' ? `Allowed by ${p.principal}${why}` : p.result === 'held' ? `Held for approval by ${p.principal}${why}` : `Blocked by ${p.principal}${why}`;
      if (p.enforced === false) text += ', observe mode: not enforced';
      break;
    case 'approval':
      text = `${p.result === 'approved' ? 'Approved' : p.result === 'rejected' ? 'Rejected' : 'Expired'}${p.approval?.approver ? ` by approver:${p.approval.approver}` : ''}${p.approval?.method ? ` (${p.approval.method})` : ''}`;
      break;
    case 'execution':
      text = p.result === 'executed'
        ? `Executed${p.state_before_commitment && p.state_after_commitment ? '; state before and after recorded' : ''}`
        : `Execution failed${why}`;
      break;
    default:
      text = p.result === 'confirmed' ? 'Confirmed in the system of record' : `NOT confirmed in the system of record${why}`;
  }
  return { phase, result: p.result, at: p.issued_at, by: p.principal, reasons, text, ...(verified !== undefined ? { verified } : {}) };
}

/**
 * Which action a record belongs to: follow `decision_ref` back to the action's first record and use its id. When
 * the chain leaves the set (a partial bundle), the id it points to is used, so the remaining records still group.
 * Instance commitments are not used: writers may re-salt them on every record.
 */
export function actionKey(record: OarRecord, records: readonly OarRecord[]): string {
  const byId = new Map(records.map((r) => [r.payload?.receipt_id, r]));
  let current = record;
  for (let i = 0; i < 16; i++) {
    const ref = current.payload?.decision_ref;
    const parent = ref ? byId.get(ref) : undefined;
    if (!parent) break;
    current = parent;
  }
  return current.payload?.decision_ref ?? current.payload?.receipt_id ?? current.payload?.instance_commitment;
}
