import { describe, expect, it } from 'vitest';
import { commit } from './crypto/commitment.js';
import { createLedger } from './testing/ledger.js';
import { verify } from './verify.js';

// AAR v0.3: the execution record commits to the state before and after the change, and a sealed confirmation
// follows. Older v0.2-mvp records keep verifying.

function executedWithState() {
  const ledger = createLedger();
  const before = commit({ order: 'o-1', totalCents: 12_000, refundedCents: 0 });
  const after = commit({ order: 'o-1', totalCents: 12_000, refundedCents: 2_500 });
  const decision = ledger.issue('agent:a');
  const execution = ledger.issue('agent:a', {
    phase: 'execution',
    result: 'executed',
    decision_ref: decision.payload.receipt_id,
    state_before_commitment: before.commitment,
    state_after_commitment: after.commitment,
  });
  ledger.issue('agent:a', { phase: 'confirmation', result: 'confirmed', reasons: ['outcome_confirmed'], decision_ref: execution.payload.receipt_id });
  ledger.disclosures.push(
    { receiptId: execution.payload.receipt_id, field: 'state_before', salt: before.salt, value: { order: 'o-1', totalCents: 12_000, refundedCents: 0 } },
    { receiptId: execution.payload.receipt_id, field: 'state_after', salt: after.salt, value: { order: 'o-1', totalCents: 12_000, refundedCents: 2_500 } },
  );
  ledger.checkpoint();
  return ledger;
}

describe('AAR v0.3', () => {
  it('a decision, an execution with before and after state, and a confirmation verify together', () => {
    const l = executedWithState();
    const report = verify(l.envelopes, l.disclosures, l.checkpoints, l.keys);
    expect(report.result).toBe('pass');
    expect(report.receipts[1]!.checks.disclosures).toBe('pass');
  });

  it('a changed "after" value is caught: the disclosure no longer matches the record', () => {
    const l = executedWithState();
    const tampered = l.disclosures.map((d) => (d.field === 'state_after' ? { ...d, value: { order: 'o-1', totalCents: 12_000, refundedCents: 250_000 } } : d));
    const report = verify(l.envelopes, tampered, l.checkpoints, l.keys);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toEqual(['disclosures']);
    expect(report.receipts[1]!.messages.join(' ')).toMatch(/state after/);
  });

  it('a changed confirmation result is caught by its signature, seal and the chain', () => {
    const l = executedWithState();
    const envelopes = l.envelopes.map((e) => (e.payload.phase === 'confirmation' ? { ...e, payload: { ...e.payload, result: 'not_confirmed' as const } } : e));
    const report = verify(envelopes, l.disclosures, l.checkpoints, l.keys);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toEqual(expect.arrayContaining(['issuer_signature', 'seal']));
  });

  it('records written as v0.2-mvp still verify', () => {
    const l = createLedger();
    l.issue('agent:a', { aar_version: '0.2-mvp' });
    l.issue('agent:a', { aar_version: '0.2-mvp', phase: 'execution', result: 'executed' });
    l.checkpoint();
    expect(verify(l.envelopes, l.disclosures, l.checkpoints, l.keys).result).toBe('pass');
  });
});
