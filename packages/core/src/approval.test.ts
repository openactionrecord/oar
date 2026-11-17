import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { bindingChallenge, challengeDigest, checkApproval } from './approval.js';
import { verifyBundle } from './bundle.js';
import { generateSigningKey } from './crypto/keys.js';
import { signRecord, type OarRecord } from './record.js';
import { createRecorder } from './recorder.js';
import { createLocalSealer } from './sealer.js';
import { loadStandaloneVerifier } from './standalone.js';
import { summarize } from './summary.js';

const subtle = webcrypto.subtle as never;
const issuer = generateSigningKey('bank-issuer-1');

function setup() {
  const sealer = createLocalSealer({ key: generateSigningKey('bank-sealer-1') });
  return createRecorder({ issuer, org: 'demo-bank', agent: 'payments-agent', sealer });
}

const display = { text: 'Pay $48,000.00 to payee P-1002', amountCents: 4_800_000, payee: 'P-1002' };

describe('approval binding (SPEC.md section 4.3)', () => {
  it('records an approval by an outside service, bound to the action and to what the approver saw', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'wire_transfer', target: 'core-banking', params: { payee: 'P-1002', amountCents: 4_800_000 }, result: 'held', reasons: ['over_approval_limit'] });
    const request = await oar.requestApproval(action, { display });
    expect(request.binding).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(challengeDigest(request.challenge)).toBe(request.binding);

    const proof = JSON.stringify({ result: 'approved', binding: request.binding, provider_ref: 'chk-7781' });
    const record = await oar.approve(action, { approver: 'treasury-lead', evidence: { provider: 'sim-check', format: 'provider-json', proof, id: 'chk-7781' } });
    expect(record.payload.approval).toMatchObject({ method: 'external', binding: { v: 2, digest: request.binding }, evidence: { provider: 'sim-check', format: 'provider-json', id: 'chk-7781' } });
    expect(record.payload.approval?.display_commitment).toMatch(/^sha256:/);
    expect(JSON.stringify(record)).not.toContain('P-1002');

    await oar.execute(action, {});
    const bundle = await oar.bundle({ disclose: 'all' });
    expect(bundle.disclosures.filter((d) => d.field === 'display')).toHaveLength(1);
    const report = verifyBundle(bundle);
    expect(report.result).toBe('pass');
    expect(report.receipts.find((r) => r.receiptId === record.payload.receipt_id)?.checks.approval).toBe('pass');
    expect(report.receipts.find((r) => r.receiptId === action.id)?.checks.approval).toBe('not_checked');
    const alone = await loadStandaloneVerifier()(bundle, subtle);
    expect(alone.result).toBe('pass');
    expect(alone.receipts.find((r) => r.receiptId === record.payload.receipt_id)?.checks.approval).toBe('pass');
    expect(summarize(bundle.records).find((s) => s.approvedBy)?.steps.map((s) => s.text)).toContain('Approved by approver:treasury-lead (checked by sim-check)');
  });

  it('binds a passkey challenge to the decision, and keeps only the display opening of the challenge used', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'wire_transfer', target: 'core-banking', params: { payee: 'P-1002', amountCents: 4_800_000 }, result: 'held' });
    const approveChallenge = await oar.requestApproval(action, { display, decision: 'approve' });
    const rejectChallenge = await oar.requestApproval(action, { display, decision: 'reject' });
    expect(approveChallenge.challenge).not.toBe(rejectChallenge.challenge);
    expect(bindingChallenge(rejectChallenge.binding)).toBe(rejectChallenge.challenge);
    const record = await oar.approve(action, { approver: 'treasury-lead', approved: false, assertion: { placeholder: 'WebAuthn assertion over the reject challenge' } });
    expect(record.payload.approval).toMatchObject({ method: 'passkey', binding: { decision: 'reject', digest: rejectChallenge.binding } });
    const bundle = await oar.bundle({ disclose: 'all' });
    expect(bundle.disclosures.filter((d) => d.field === 'display')).toHaveLength(1);
    expect(verifyBundle(bundle).result).toBe('pass');
  });

  it('refuses an outside approval without a request, so the service always confirmed this exact action', async () => {
    const oar = setup();
    const action = await oar.decide({ type: 'payout', target: 'payments', params: { amountCents: 100 }, result: 'held' });
    await expect(oar.approve(action, { approver: 'ops', evidence: { provider: 'sim-check', format: 'provider-json', proof: '{}' } })).rejects.toThrow(/requestApproval/);
  });

  it('fails a binding written for another action, a signed rejection recorded as approved, and outside approvals without evidence', async () => {
    const oar = setup();
    const a = await oar.decide({ type: 'payout', target: 'payments', params: { amountCents: 100 }, result: 'held' });
    const b = await oar.decide({ type: 'payout', target: 'payments', params: { amountCents: 999_999 }, result: 'held' });
    const forB = await oar.requestApproval(b, {});
    await oar.requestApproval(a, { decision: 'reject' });
    const approvalA = await oar.approve(a, { approver: 'ops', approved: false });

    const moved = structuredClone(approvalA.payload);
    moved.approval!.binding = { v: 2, nonce: '0'.repeat(64), digest: forB.binding };
    expect(checkApproval(moved)).toEqual(['The approval binding does not match this action, what the approver was shown, or its nonce.']);

    const flipped = structuredClone(approvalA.payload);
    flipped.result = 'approved';
    expect(checkApproval(flipped)).toContain('The approver signed a rejection, but the record says otherwise.');

    const bare = structuredClone(approvalA.payload);
    bare.approval = { method: 'external', approver: 'ops', at: bare.approval!.at };
    expect(checkApproval(bare)).toHaveLength(2);

    // Re-signed by the issuer, so only the approval check can catch it: every verifier must.
    const resigned: OarRecord = signRecord(flipped, issuer);
    const bundle = await oar.bundle();
    bundle.records = bundle.records.map((r) => (r.payload.receipt_id === flipped.receipt_id ? { ...resigned, ...(r.seal ? { seal: r.seal } : {}) } : r));
    const report = verifyBundle(bundle);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toContain('approval');
    const alone = await loadStandaloneVerifier()(bundle, subtle);
    expect(alone.failedChecks).toContain('approval');
  });
});
