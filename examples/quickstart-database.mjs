// Open Action Record quickstart: record an agent's database actions, then verify them.
// Needs Node.js 22.13 or later (it uses the built-in SQLite). Run:
//   npm install @openactionrecord/core
//   node quickstart.mjs
import { writeFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { createLocalSealer, createRecorder, generateSigningKey, summarize, verifyBundle } from '@openactionrecord/core';

// 1. A real (in-memory) database standing in for yours.
const db = new DatabaseSync(':memory:');
db.exec(`
  create table sessions (id integer primary key, expired integer);
  create table customers (id integer primary key, email text);
  insert into sessions (expired) select value % 2 from json_each('[1,2,3,4,5,6,7,8,9,10]');
  insert into customers (email) values ('A@Example.com'), ('b@example.com');
`);
const count = (sql) => db.prepare(sql).get().n;

// 2. A recorder: your agent's signing key, and (optional) a separate sealing service with its own key.
const sealer = createLocalSealer({ key: generateSigningKey('sealer-2026') });
const oar = createRecorder({
  issuer: generateSigningKey('ops-agent-2026'),
  sealer,
  org: 'acme',
  agent: 'ops-agent',
  policyId: 'database-rules-v1',
});

// 3. Your rules: routine cleanups run, dropping a table needs a person, anything else that deletes data is blocked.
const rules = (p) =>
  p.action === 'drop_table' ? { result: 'held', reasons: ['destructive_change'] }
  : ['delete_expired', 'normalize_emails'].includes(p.action) ? { result: 'allowed', reasons: ['routine_change'] }
  : { result: 'denied', reasons: ['no_rule_allows_it'] };

// Action A: allowed, and confirmed by reading the database back.
const cleanup = await oar.run({
  type: 'delete_rows', target: 'sqlite', params: { action: 'delete_expired', table: 'sessions' },
  check: rules,
  readState: () => ({ expired: count('select count(*) n from sessions where expired = 1') }),
  execute: () => db.prepare('delete from sessions where expired = 1').run().changes,
  confirm: () => count('select count(*) n from sessions where expired = 1') === 0,
});
console.log('A. cleanup:', cleanup.status, 'confirmed =', cleanup.confirmed);

// Action B: held for a person, who says no. The table is never dropped.
const drop = await oar.run({
  type: 'drop_table', target: 'sqlite', params: { action: 'drop_table', table: 'customers' },
  check: rules,
  approve: () => ({ approver: 'maya', approved: false }), // in real life: ask a person (Slack, email, your dashboard)
  execute: () => db.exec('drop table customers'),
});
console.log('B. drop table:', drop.status, '| customers still there:', count('select count(*) n from customers'));

// Action C: blocked by the rules. It never runs.
const wipe = await oar.run({
  type: 'delete_rows', target: 'sqlite', params: { action: 'delete_all', table: 'customers' },
  check: rules,
  execute: () => db.exec('delete from customers'),
});
console.log('C. delete all customers:', wipe.status);

// Action D: the agent's tool says "done", but nothing changed. The read-back catches it.
const ghost = await oar.run({
  type: 'update_rows', target: 'sqlite', params: { action: 'normalize_emails', table: 'customers' },
  check: rules,
  readState: () => ({ notLowercase: count('select count(*) n from customers where email <> lower(email)') }),
  execute: () => ({ status: 'done' }), // a bug: the tool reports success but never runs the update
  confirm: () => count('select count(*) n from customers where email <> lower(email)') === 0, // read back: are all emails lowercase now?
});
console.log('D. update that never happened: confirmed =', ghost.confirmed);

// 4. Optional: have an outside authority timestamp the records (DigiCert's free RFC 3161 service; only a hash is sent).
try {
  const stamp = await sealer.anchor({ timeoutMs: 10_000 });
  console.log(`\nTimestamped by ${stamp?.tsa} at ${stamp?.gen_time}`);
} catch (error) {
  console.log(`\nTimestamp skipped (${error instanceof Error ? error.message : error}); the records are still signed and sealed.`);
}

// 5. Share and verify. The default bundle discloses nothing in clear; it still proves what happened.
const bundle = await oar.bundle();
await writeFile('evidence.json', JSON.stringify(bundle, null, 2));
const report = verifyBundle(bundle);
console.log(`\n${report.result.toUpperCase()}: ${report.messages[0]}`);
for (const a of summarize(bundle.records, bundle.disclosures, report)) console.log(` - ${a.type}: ${a.outcomeText}`);
console.log('\nWrote evidence.json. Check it yourself: npx @openactionrecord/cli verify evidence.json');
