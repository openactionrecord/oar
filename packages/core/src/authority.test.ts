import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { authoritySetDigest, checkAuthority } from './authority.js';
import { verifyBundle } from './bundle.js';
import { generateSigningKey } from './crypto/keys.js';
import type { Payload } from './record.js';
import { createRecorder } from './recorder.js';
import { loadStandaloneVerifier } from './standalone.js';
import { outcomeClass, summarize } from './summary.js';

const subtle = webcrypto.subtle as never;
const authorities = [
  { type: 'aauth', issuer: 'https://person.example', artifact: 'grant', expiresAt: '2099-01-01T00:00:00Z' },
  { type: 'x401', issuer: 'https://wallet.example', artifact: 'proof' },
];
const setup = () => createRecorder({ issuer: generateSigningKey('i'), org: 'demo', agent: 'payments-agent' });

describe('authority set (SPEC.md section 4.5)', () => {
  it('records the authorities a decision relied on and their re-check at commitment', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { amountCents: 420_000 }, result: 'allowed', authorities });
    const exec = await oar.execute(action, { authorityCheck: { statuses: ['valid', 'valid'] } });
    await oar.confirm(action, { confirmed: true });
    const bundle = await oar.bundle();
    const decision = bundle.records[0]!.payload;
    expect(decision.authorities).toHaveLength(2);
    expect(exec.payload.authority_check).toMatchObject({ result: 'current', set_digest: authoritySetDigest(decision.authorities!) });
    const report = verifyBundle(bundle);
    expect(report.result).toBe('pass');
    expect(report.receipts.map((r) => r.checks.authority)).toEqual(['pass', 'pass', 'not_checked']);
    expect((await loadStandaloneVerifier()(bundle, subtle)).result).toBe('pass');
    expect(summarize(bundle.records)[0]!.outcomeClass).toBe('committed');
  });

  it('refuses an action whose authority changed before it committed', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { amountCents: 1 }, result: 'allowed', authorities });
    const exec = await oar.execute(action, { authorityCheck: { statuses: ['valid', 'revoked'] } });
    expect(exec.payload).toMatchObject({ result: 'refused', reasons: ['authority_revoked'], authority_check: { result: 'changed', changes: [{ index: 1, status: 'revoked' }] } });
    await expect(oar.confirm(action, { confirmed: true })).rejects.toThrow();
    const bundle = await oar.bundle();
    expect(verifyBundle(bundle).result).toBe('pass');
    const [s] = summarize(bundle.records);
    expect(s!.outcome).toBe('refused');
    expect(s!.outcomeClass).toBe('refused');
  });

  it('requires a re-check, and catches inconsistent ones', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { amountCents: 1 }, result: 'allowed', authorities });
    await expect(oar.execute(action, {})).rejects.toThrow(/authorityCheck/);
    const exec = await oar.execute(action, { authorityCheck: { statuses: ['valid', 'valid'] } });
    const decision = (await oar.bundle()).records[0]!.payload;
    const byId = new Map<string, Payload>([[decision.receipt_id, decision]]);

    const missing = structuredClone(exec.payload);
    delete missing.authority_check;
    expect(checkAuthority(missing, byId)).toEqual(['The action ran without its authority set being checked again at the moment it committed.']);

    const ranAnyway = structuredClone(exec.payload);
    ranAnyway.authority_check!.result = 'changed';
    expect(checkAuthority(ranAnyway, byId)).toContain('An authority changed before the action committed, but the action was not recorded as refused.');

    const otherSet = structuredClone(exec.payload);
    otherSet.authority_check!.set_digest = `sha256:${'0'.repeat(64)}`;
    expect(checkAuthority(otherSet, byId)).toContain('The authority check covers a different authority set than the decision relied on.');

    const allowedAnyway = structuredClone(decision);
    allowedAnyway.authorities![1]!.status = 'revoked';
    expect(checkAuthority(allowedAnyway, byId)).toContain('The action was allowed, but not every authority it relied on was valid.');
  });

  it('classes every outcome as committed, refused or unresolved', () => {
    expect(outcomeClass('confirmed')).toBe('committed');
    for (const o of ['denied', 'rejected', 'expired', 'refused'] as const) expect(outcomeClass(o)).toBe('refused');
    for (const o of ['not_confirmed', 'executed_unconfirmed', 'failed', 'awaiting_approval', 'approved_not_executed', 'allowed_not_executed'] as const) expect(outcomeClass(o)).toBe('unresolved');
  });
});
