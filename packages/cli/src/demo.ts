import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { createLocalSealer, createRecorder, generateSigningKey, summarize, verifyBundle, type Bundle } from '@openactionrecord/core';
import { standaloneVerifierHtml } from '@openactionrecord/core/standalone';
import { c, line, printActions, printReport, PASS, FAIL } from './print.js';

// `oar demo`: one minute, nothing to set up. An AI agent takes a few actions; OAR records each one, the bundle
// verifies, an edit to it is caught, and an agent's false claim of success shows up. Two scenarios: an AI support
// agent at an online store (the default) and an AI operations agent on a production database (`--database`).

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

/** A pretend production database: a sessions table to clean up, a customers table, backups, and a schema. */
function productionDatabase() {
  const tables = new Map([
    ['sessions', { rows: 5_000, expired: 120 }],
    ['customers', { rows: 48_210, expired: 0 }],
  ]);
  const columns = new Set(['id', 'email', 'created_at']);
  return {
    readTable: (table: string) => () => ({ table, ...tables.get(table)! }),
    readSchema: () => ({ table: 'customers', columns: [...columns].sort() }),
    deleteExpired(table: string) {
      const t = tables.get(table)!;
      const deleted = t.expired;
      t.rows -= deleted;
      t.expired = 0;
      return { deleted };
    },
    /** A bug: the migration tool answers "applied" but the column is never added. */
    brokenMigration: () => ({ migration: '2026_11_add_loyalty_tier', status: 'applied' }),
    hasColumn: (name: string) => columns.has(name),
    expiredLeft: (table: string) => tables.get(table)!.expired,
  };
}

/** A pretend payout system, and the authorization server that issued the agent's delegated token. */
function payoutSystem() {
  const paid = new Map<string, { payee: string; cents: number }>();
  const revoked = new Set<string>();
  let n = 0;
  return {
    pay(payee: string, cents: number) {
      const id = `po_${(++n).toString().padStart(4, '0')}`;
      paid.set(id, { payee, cents });
      return { id, status: 'paid' };
    },
    wasPaid: (id: string) => paid.has(id),
    paidCount: () => paid.size,
    revoke: (token: string) => revoked.add(token),
    /** Token introspection: is this delegated token still active? */
    introspect: (token: string) => (revoked.has(token) ? 'revoked' : 'valid') as 'valid' | 'revoked',
  };
}

export type DemoScenario = 'store' | 'database' | 'payouts';

export async function demo(dir: string, options: { offline?: boolean; scenario?: DemoScenario } = {}): Promise<number> {
  if (options.scenario === 'database') return databaseDemo(dir, options);
  if (options.scenario === 'payouts') return payoutsDemo(dir, options);
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

  return finish(oar, sealer, dir, options, {
    tamperText: 'Now someone edits the record to pretend the $1,900 refund never needed approval:',
    note: ' (amounts, order numbers and refund IDs are committed, not written in clear)',
    ok: refund.status === 'completed',
  });
}

type Recorder = ReturnType<typeof createRecorder>;
type Sealer = ReturnType<typeof createLocalSealer>;

/** Shared by both scenarios: timestamp, write the bundle, verify it, then show that an edit is caught. */
async function finish(
  oar: Recorder,
  sealer: Sealer,
  dir: string,
  options: { offline?: boolean },
  text: { tamperText: string; note: string; ok: boolean },
): Promise<number> {
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

  line(c.bold(`Wrote ${shareable.records.length} records to ${rel(files.bundle)}`) + c.dim(text.note));
  line();
  line(c.bold('Verify it:'));
  const report = verifyBundle(debugging);
  printReport(report);
  printActions(summarize(debugging.records, debugging.disclosures, report));
  line();

  line(c.bold(text.tamperText));
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
  return text.ok && report.result === 'pass' ? 0 : 1;
}

/** `oar demo --database`: an AI operations agent on a production database. */
async function databaseDemo(dir: string, options: { offline?: boolean }): Promise<number> {
  line();
  line(c.bold('Open Action Record · demo: a production database'));
  line(c.dim('An AI operations agent works on a production database. Its rules: routine cleanups run; deleting a table needs a person; deleting backups is never allowed.'));
  line(c.dim('Every action it takes is recorded: what was asked, who approved it, what actually changed, and whether the database confirms it.'));
  line();

  const issuer = generateSigningKey('ops-agent-2026');
  const sealer = createLocalSealer({ key: generateSigningKey('ops-sealer-2026') });
  const oar = createRecorder({ issuer, sealer, org: 'example-co', orgName: 'Example Co', agent: 'ops-agent', policyId: 'database-rules-v2', policy: { destructiveChangesNeedApproval: true, backupDeletion: 'never' } });
  const db = productionDatabase();

  line(`${c.cyan('1.')} The agent deletes 120 expired sessions, a routine cleanup.`);
  await pause(250);
  const cleanup = await oar.run({
    type: 'delete_rows',
    target: 'database',
    params: { table: 'sessions', where: 'expired', rows: 120 },
    check: () => ({ result: 'allowed', reasons: ['routine_cleanup'] }),
    readState: db.readTable('sessions'),
    execute: () => db.deleteExpired('sessions'),
    confirm: () => db.expiredLeft('sessions') === 0,
  });
  line(`   ${PASS} deleted, and the database confirms it`);
  await pause(200);

  line(`${c.cyan('2.')} The agent tries to delete the customers table.`);
  await pause(250);
  await oar.run({
    type: 'drop_table',
    target: 'database',
    params: { table: 'customers' },
    check: () => ({ result: 'held', reasons: ['destructive_change'] }),
    approve: async () => {
      line(`   ${c.dim('held: deleting a table needs a person → Maya, the database owner, rejects it')}`);
      await pause(250);
      return { approver: 'maya', approved: false };
    },
    readState: db.readTable('customers'),
    execute: () => 'never runs',
  });
  line(`   ${FAIL} rejected: the table was never deleted (recorded)`);
  await pause(200);

  line(`${c.cyan('3.')} The agent tries to delete the database backups.`);
  await pause(250);
  await oar.run({
    type: 'delete_backups',
    target: 'database',
    params: { scope: 'all' },
    check: () => ({ result: 'denied', reasons: ['no_rule_allows_backup_deletion'] }),
    execute: () => 'never runs',
  });
  line(`   ${FAIL} blocked: no rule allows deleting backups (recorded, not executed)`);
  await pause(200);

  line(`${c.cyan('4.')} A schema migration. The migration tool answers "applied"… but a bug means the column was never added.`);
  await pause(250);
  const ghost = await oar.run({
    type: 'run_migration',
    target: 'database',
    params: { migration: '2026_11_add_loyalty_tier' },
    check: () => ({ result: 'allowed', reasons: ['approved_migration'] }),
    readState: db.readSchema,
    execute: () => db.brokenMigration(),
    targetRef: (r) => r.migration,
    confirm: () => db.hasColumn('loyalty_tier'),
  });
  line(`   ${ghost.confirmed ? PASS : FAIL} the agent reported success; the read-back shows ${c.bold('no new column')}. Recorded as NOT confirmed.`);
  line();

  return finish(oar, sealer, dir, options, {
    tamperText: 'Now someone edits the record to pretend deleting the customers table never needed a person:',
    note: ' (table names, row counts and migration names are committed, not written in clear)',
    ok: cleanup.status === 'completed',
  });
}

/** `oar demo --payouts`: an AI payments agent acting for a person, whose permission is revoked mid-action. */
async function payoutsDemo(dir: string, options: { offline?: boolean }): Promise<number> {
  line();
  line(c.bold('Open Action Record · demo: payouts, and a permission revoked mid-action'));
  line(c.dim("An AI payments agent pays suppliers for Sam, a finance manager, using a token Sam delegated to it. Its rules: payouts to a new payee need Sam's approval."));
  line(c.dim('Every payout records the token it relied on, by digest, and checks that token again just before the money moves.'));
  line();

  const issuer = generateSigningKey('payments-agent-2026');
  const sealer = createLocalSealer({ key: generateSigningKey('payments-sealer-2026') });
  const oar = createRecorder({ issuer, sealer, org: 'example-co', orgName: 'Example Co', agent: 'payments-agent', policyId: 'payout-rules-v1', policy: { newPayeeNeedsApproval: true } });
  const pay = payoutSystem();
  const token = 'eyJhbGciOiJFZERTQSJ9.delegated-payout-token-for-sam.c2ln';
  const authorities = [{ type: 'delegated-token', issuer: 'https://auth.example-co.com', artifact: token, expiresAt: new Date(Date.now() + 3_600_000).toISOString() }];

  line(`${c.cyan('1.')} The agent pays a known supplier $4,200 with Sam's delegated token.`);
  await pause(250);
  const first = await oar.decide({ type: 'payout', target: 'payments', params: { payee: 'P-1001', amountCents: 420_000 }, result: 'allowed', reasons: ['known_payee', 'within_limits'], authorities });
  const firstPaid = pay.pay('P-1001', 420_000);
  await oar.execute(first, { targetRef: firstPaid.id, authorityCheck: { statuses: [pay.introspect(token)] } });
  await oar.confirm(first, { confirmed: pay.wasPaid(firstPaid.id) });
  line(`   ${PASS} the token is still valid at the moment of payment; paid, and the payment system confirms it`);
  await pause(200);

  line(`${c.cyan('2.')} The agent sets up $9,800 to a new payee. Sam approves it on their phone.`);
  await pause(250);
  const second = await oar.decide({ type: 'payout', target: 'payments', params: { payee: 'P-2077', amountCents: 980_000 }, result: 'held', reasons: ['new_payee'], authorities });
  await oar.approve(second, { approver: 'sam', approved: true });
  line(`   ${c.dim('approved by Sam… then, a minute later, Sam spots a fraud warning and revokes the agent\'s token')}`);
  pay.revoke(token);
  await pause(250);
  await oar.execute(second, { authorityCheck: { statuses: [pay.introspect(token)] } });
  line(`   ${FAIL} the re-check just before the money moves finds the token ${c.bold('revoked')}: nothing is paid. Recorded as refused.`);
  line(`   ${c.dim(`payouts made: ${pay.paidCount()} (only the first)`)}`);
  line();

  return finish(oar, sealer, dir, options, {
    tamperText: "Now someone edits the record to pretend the new payee never needed Sam's approval:",
    note: ' (payees, amounts and the token are committed or digested, not written in clear)',
    ok: pay.paidCount() === 1,
  });
}

function rel(path: string): string {
  const r = relative(process.cwd(), path);
  return r.startsWith('..') ? path : r;
}
