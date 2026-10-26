import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { createLocalSealer, createRecorder, generateSigningKey, summarize, verifyBundle, type Bundle } from '@openactionrecord/core';
import { standaloneVerifierHtml } from '@openactionrecord/core/standalone';
import { c, line, printActions, printReport, PASS, FAIL } from './print.js';

// `oar demo`: one minute, nothing to set up. An AI support agent at an online store takes three actions; OAR
// records each one, the bundle verifies, an edit to it is caught, and an agent's false claim of success shows up.

const pause = (ms: number) => (process.stdout.isTTY ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

/** A pretend payment system: one order, and refunds that may or may not really happen. */
function paymentSystem() {
  const orders = new Map([
    ['1142', { totalCents: 190_000, refundedCents: 0 }],
    ['1187', { totalCents: 4_500, refundedCents: 0 }],
  ]);
  const refunds = new Map<string, { order: string; cents: number }>();
  let n = 0;
  return {
    read: (order: string) => () => ({ order, ...orders.get(order)! }),
    refund(order: string, cents: number) {
      const id = `re_${(++n).toString().padStart(4, '0')}`;
      orders.get(order)!.refundedCents += cents;
      refunds.set(id, { order, cents });
      return { id, status: 'succeeded' };
    },
    /** A bug: the API answers "succeeded" but nothing is refunded. */
    brokenRefund: () => ({ id: `re_${(++n).toString().padStart(4, '0')}`, status: 'succeeded' }),
    hasRefund: (id: string) => refunds.has(id),
  };
}

export async function demo(dir: string, options: { offline?: boolean } = {}): Promise<number> {
  line();
  line(c.bold('Open Action Record · demo'));
  line(c.dim('An AI support agent works for an online store. Its rules: refunds over $1,250 need a person; discounts are capped at 20%.'));
  line(c.dim('Every action it takes is recorded: what was asked, who approved it, what actually changed, and whether the payment system confirms it.'));
  line();

  const issuer = generateSigningKey('store-agent-2026');
  const sealer = createLocalSealer({ key: generateSigningKey('store-sealer-2026') });
  const oar = createRecorder({ issuer, sealer, org: 'example-store', orgName: 'Example Store', agent: 'support-agent', policyId: 'store-rules-v3', policy: { refundApprovalAboveCents: 125_000, maxDiscountPercent: 20 } });
  const pay = paymentSystem();

  line(`${c.cyan('1.')} A customer's $1,900 order arrived damaged. The agent refunds it.`);
  await pause(250);
  const refund = await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1142', amountCents: 190_000 },
    check: (p) => ((p.amountCents as number) > 125_000 ? { result: 'held', reasons: ['over_approval_limit'] } : { result: 'allowed' }),
    approve: async () => {
      line(`   ${c.dim('held: over the $1,250 approval limit → Jordan, the support lead, approves')}`);
      await pause(250);
      return { approver: 'jordan', approved: true };
    },
    readState: pay.read('1142'),
    execute: () => pay.refund('1142', 190_000),
    targetRef: (r) => r.id,
    confirm: (r) => pay.hasRefund(r.id),
  });
  line(`   ${PASS} refunded, and the payment system confirms it`);
  await pause(200);

  line(`${c.cyan('2.')} A customer asks for 80% off. The agent tries to create the code.`);
  await pause(250);
  await oar.run({
    type: 'discount_code',
    target: 'store',
    params: { percent: 80 },
    check: (p) => ((p.percent as number) > 20 ? { result: 'denied', reasons: ['over_maximum_discount'] } : { result: 'allowed' }),
    execute: () => 'never runs',
  });
  line(`   ${FAIL} blocked: over the 20% maximum (recorded, not executed)`);
  await pause(200);

  line(`${c.cyan('3.')} A $45 refund. The payment API answers "succeeded"… but a bug means nothing was refunded.`);
  await pause(250);
  const ghost = await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1187', amountCents: 4_500 },
    readState: pay.read('1187'),
    execute: () => pay.brokenRefund(),
    targetRef: (r) => r.id,
    confirm: (r) => pay.hasRefund(r.id),
  });
  line(`   ${ghost.confirmed ? PASS : FAIL} the agent reported success; the read-back shows ${c.bold('no refund')}. Recorded as NOT confirmed.`);
  line();

  if (!options.offline) {
    line(c.dim("Asking DigiCert's free public timestamp service to timestamp the sealing service's checkpoint (one request; only a hash is sent)…"));
    try {
      const anchor = await sealer.anchor({ timeoutMs: 5_000 });
      line(`   ${PASS} timestamped by ${anchor?.tsa} at ${anchor?.gen_time}`);
    } catch (error) {
      line(`   ${c.yellow('●')} skipped: ${error instanceof Error ? error.message : 'no answer'} The records are still sealed.`);
    }
    line();
  }

  await mkdir(dir, { recursive: true });
  const shareable = await oar.bundle({ purpose: 'dispute' });
  const debugging = await oar.bundle({ disclose: 'all', purpose: 'debugging' });
  const files = {
    bundle: join(dir, 'evidence.json'),
    full: join(dir, 'evidence-with-details.json'),
    tampered: join(dir, 'evidence-tampered.json'),
    html: join(dir, 'verify.html'),
    keys: join(dir, 'aar-keys.json'),
  };
  await writeFile(files.bundle, JSON.stringify(shareable, null, 2));
  await writeFile(files.full, JSON.stringify(debugging, null, 2));
  await writeFile(files.keys, JSON.stringify(await oar.keys(), null, 2));
  await writeFile(files.html, standaloneVerifierHtml(JSON.stringify(shareable)));

  line(c.bold(`Wrote ${shareable.records.length} records to ${rel(files.bundle)}`) + c.dim(' (amounts, order numbers and refund IDs are committed, not written in clear)'));
  line();
  line(c.bold('Verify it:'));
  const report = verifyBundle(debugging);
  printReport(report);
  printActions(summarize(debugging.records, debugging.disclosures, report));
  line();

  line(c.bold('Now someone edits the record to pretend the $1,900 refund never needed approval:'));
  const tampered: Bundle = structuredClone(shareable);
  const held = tampered.records.find((r) => r.payload.result === 'held')!;
  held.payload.result = 'allowed';
  held.payload.reasons = ['within_limits'];
  await writeFile(files.tampered, JSON.stringify(tampered, null, 2));
  printReport(verifyBundle(tampered));
  line();

  line(c.bold('Next:'));
  line(`  npx @openactionrecord/cli verify ${rel(files.bundle)}     ${c.dim('# the bundle you would share: proves what happened, discloses nothing')}`);
  line(`  open ${rel(files.html)}                              ${c.dim('# the same check, offline in a browser')}`);
  line(`  npm install @openactionrecord/core     ${c.dim('# record your own agent: https://github.com/openactionrecord/oar')}`);
  line();
  return refund.status === 'completed' && report.result === 'pass' ? 0 : 1;
}

function rel(path: string): string {
  const r = relative(process.cwd(), path);
  return r.startsWith('..') ? path : r;
}
