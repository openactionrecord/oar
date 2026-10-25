// Already sign tool calls with another receipt format? Keep it. Point OAR at it with `external` and add the
// approval and outcome evidence it does not carry.
// Run: npx tsx examples/add-to-another-receipt.ts
import { createRecorder, generateSigningKey, sha256Hex, verifyBundle } from '@openactionrecord/core';

// The receipt your gateway already produced, exactly as issued (bytes or text).
const otherReceipt = '{"v":1,"tool":"payments.refund","decision":"allow","sig":"..."}';
const digest = `sha256:${sha256Hex(otherReceipt)}`;

const oar = createRecorder({ issuer: generateSigningKey('my-agent-2026'), org: 'acme', agent: 'support-bot' });
await oar.run({
  type: 'refund',
  target: 'payments',
  params: { order: '1187', amountCents: 4_500 },
  external: { format: 'acta', digest, id: 'rcpt-42' },
  readState: () => ({ refundedCents: 0 }),
  execute: () => ({ id: 're_9' }),
  targetRef: (r) => r.id,
  confirm: () => false, // the read-back does not show the refund
});

const bundle = await oar.bundle();
console.log(verifyBundle(bundle).messages[0]);
console.log('external_ref:', bundle.records[0]!.payload.external_ref);
console.log('outcome:', bundle.records.at(-1)!.payload.result, '— the other receipt said "allow"; OAR shows nothing was refunded.');

