// Record an agent's refund end to end, write a bundle, and verify it.
// Run: npx tsx examples/quickstart.ts
import { writeFile } from 'node:fs/promises';
import { createRecorder, generateSigningKey, summarize, verifyBundle } from '@openactionrecord/core';

// A stand-in for your payment API. Swap in Stripe, Shopify, your database...
const payments = {
  orders: new Map([['1142', { totalCents: 190_000, refundedCents: 0 }]]),
  refunds: new Map<string, number>(),
  orderState(order: string) {
    const o = this.orders.get(order)!;
    return { order, totalCents: o.totalCents, refundedCents: o.refundedCents };
  },
  refund(order: string, cents: number) {
    this.orders.get(order)!.refundedCents += cents;
    const id = `re_${this.refunds.size + 1}`;
    this.refunds.set(id, cents);
    return { id, status: 'succeeded' as const };
  },
};

// 1. A signing key for your agent. In production, load it from a secret, and publish its public key.
const oar = createRecorder({ issuer: generateSigningKey('my-agent-2026'), org: 'acme', agent: 'support-bot' });

// 2. Wrap the action. Every step is recorded: the rule's decision, the approval, state before and after, the confirmation.
const out = await oar.run({
  type: 'refund',
  target: 'payments',
  params: { order: '1142', amountCents: 190_000 },
  check: (p) => (Number(p.amountCents) > 125_000 ? { result: 'held', reasons: ['over_approval_limit'] } : { result: 'allowed' }),
  approve: async () => ({ approver: 'jordan', approved: true }), // ask a person: Slack, email, your dashboard
  readState: () => payments.orderState('1142'),
  execute: () => payments.refund('1142', 190_000),
  targetRef: (refund) => refund.id,
  confirm: (refund) => payments.refunds.has(refund.id), // read the system of record back
});
console.log(`status: ${out.status}, confirmed: ${out.confirmed}`);

// 3. A bundle anyone can verify offline. By default it discloses nothing: no amounts, no order numbers.
const bundle = await oar.bundle();
await writeFile('evidence.json', JSON.stringify(bundle, null, 2));

const report = verifyBundle(bundle);
console.log(report.messages[0]);
for (const action of summarize(bundle.records, bundle.disclosures, report)) {
  console.log(`${action.type} → ${action.target}: ${action.outcomeText}`);
  for (const step of action.steps) console.log(`  ${step.phase.padEnd(12)} ${step.text}`);
}
console.log('\nWrote evidence.json. Check it with: npx @openactionrecord/cli verify evidence.json');
