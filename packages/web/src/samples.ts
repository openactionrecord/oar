import { createHash } from 'node:crypto';
import { createLocalSealer, createRecorder, type Bundle, type SigningKey } from '@openactionrecord/core';

// Sample bundles for the playground. Fixed keys and randomness, so the page builds the same every time.
// SAMPLE KEYS ONLY.

const ISSUER: SigningKey = { kid: 'example-store-agent', privateKey: '33'.repeat(32) };
const SEALER: SigningKey = { kid: 'example-sealing-service', privateKey: '44'.repeat(32) };

export async function sampleBundles(): Promise<{ valid: Bundle; issuerSigned: Bundle }> {
  return { valid: await story(true), issuerSigned: await story(false) };
}

async function story(sealed: boolean): Promise<Bundle> {
  let t = Date.parse('2026-10-25T14:00:00.000Z');
  let n = 0;
  const h = (s: string) => createHash('sha256').update(s).digest('hex');
  const now = () => new Date((t += 1_500));
  const sealer = sealed ? createLocalSealer({ key: SEALER, now }) : undefined;
  const oar = createRecorder({
    issuer: ISSUER,
    org: 'example-store',
    orgName: 'Example Store',
    agent: 'support-agent',
    run: 'run:sample',
    policyId: 'store-rules-v3',
    policy: { refundApprovalAboveCents: 125_000, maxDiscountPercent: 20 },
    ...(sealer ? { sealer } : {}),
    now,
    randomId: () => {
      const x = h(`sample:${sealed}:id:${++n}`);
      return `${x.slice(0, 8)}-${x.slice(8, 12)}-4${x.slice(13, 16)}-8${x.slice(17, 20)}-${x.slice(20, 32)}`;
    },
    randomSalt: () => h(`sample:${sealed}:salt:${++n}`),
  });

  const orders: Record<string, { order: string; totalCents: number; refundedCents: number }> = {
    '1142': { order: '1142', totalCents: 190_000, refundedCents: 0 },
    '1187': { order: '1187', totalCents: 4_500, refundedCents: 0 },
  };
  await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1142', amountCents: 190_000 },
    idempotencyKey: 'refund-1142',
    check: () => ({ result: 'held', reasons: ['over_approval_limit'] }),
    approve: () => ({ approver: 'jordan', approved: true }),
    readState: () => ({ ...orders['1142']! }),
    execute: () => {
      orders['1142']!.refundedCents += 190_000;
      return { id: 're_0001' };
    },
    targetRef: (r) => r.id,
    confirm: () => true,
  });
  await oar.run({
    type: 'discount_code',
    target: 'store',
    params: { percent: 80 },
    idempotencyKey: 'discount-80',
    check: () => ({ result: 'denied', reasons: ['over_maximum_discount'] }),
    execute: () => 'never runs',
  });
  await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1187', amountCents: 4_500 },
    idempotencyKey: 'refund-1187',
    readState: () => ({ ...orders['1187']! }),
    execute: () => ({ id: 're_0002' }), // the payment API says "succeeded", but nothing was refunded
    targetRef: (r) => r.id,
    confirm: () => false,
  });
  return oar.bundle({ disclose: 'all', purpose: 'debugging' });
}
