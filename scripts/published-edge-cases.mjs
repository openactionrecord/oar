// Edge cases against the published @openactionrecord/core, run in a fresh project by the live-check workflow.
import { DatabaseSync } from 'node:sqlite';
import { createLocalSealer, createRecorder, generateSigningKey, summarize, verifyBundle, publicKeys } from '@openactionrecord/core';
import { writeFileSync } from 'node:fs';

let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  (' + detail + ')' : ''}`); if (!ok) failures++; };

const db = new DatabaseSync(':memory:');
db.exec("create table orders (id text primary key, total integer, refunded integer); insert into orders values ('1142', 190000, 0), ('1187', 4500, 0);");
const row = (id) => ({ ...db.prepare('select * from orders where id = ?').get(id) });

const issuer = generateSigningKey('edge-agent');
const sealer = createLocalSealer({ key: generateSigningKey('edge-sealer') });
const oar = createRecorder({ issuer, sealer, org: 'edge', agent: 'agent-1', policyId: 'rules-v1' });

// 1. Held, approved by a person, executed and confirmed.
const approved = await oar.run({
  type: 'refund', target: 'orders', params: { order: '1142', cents: 190000 },
  check: () => ({ result: 'held', reasons: ['over_limit'] }),
  approve: () => ({ approver: 'jordan', approved: true }),
  readState: () => row('1142'),
  execute: () => db.prepare("update orders set refunded = refunded + 190000 where id = '1142'").run().changes,
  confirm: () => row('1142').refunded === 190000,
});
check('held, approved, executed and confirmed', approved.status === 'completed' && approved.confirmed === true);

// 2. Held with nobody to approve: stops at "held" and never runs.
let ran = false;
const pending = await oar.run({ type: 'refund', target: 'orders', params: { order: '1187', cents: 4500 }, check: () => ({ result: 'held' }), execute: () => { ran = true; } });
check('held without an approver waits and never runs', pending.status === 'held' && !ran);

// 3. The action throws (a real SQL error): recorded as failed, and the error reaches the agent.
let thrown = false;
try {
  await oar.run({ type: 'refund', target: 'orders', params: { order: '9999' }, execute: () => db.exec('update no_such_table set x = 1') });
} catch { thrown = true; }
check('a failing action is re-thrown to the agent', thrown);

// 4. Async rules, async read-back.
const asyncRun = await oar.run({
  type: 'refund', target: 'orders', params: { order: '1187', cents: 500 },
  check: async () => ({ result: 'allowed' }),
  readState: async () => row('1187'),
  execute: async () => db.prepare("update orders set refunded = refunded + 500 where id = '1187'").run().changes,
  confirm: async () => row('1187').refunded === 500,
});
check('async check, read and confirm work', asyncRun.confirmed === true);

// 5. The bundle verifies, and the summary shows each outcome, including the failure.
const bundle = await oar.bundle();
const report = verifyBundle(bundle);
check('shareable bundle verifies', report.result === 'pass', report.messages[0]);
const outcomes = summarize(bundle.records, bundle.disclosures, report).map((a) => a.outcome);
check('outcomes recorded: confirmed, awaiting approval, failed', outcomes.includes('confirmed') && outcomes.includes('awaiting_approval') && outcomes.includes('failed'), outcomes.join(', '));
check('nothing disclosed by default', (bundle.disclosures ?? []).length === 0);
check('order numbers are not in the shareable bundle in clear', !JSON.stringify(bundle).includes('"1142"'));

// 6. A debugging bundle discloses values, and they still verify.
const full = await oar.bundle({ disclose: 'all' });
check('full bundle with disclosed values verifies', verifyBundle(full).result === 'pass');

// 7. Tampering: change a decision, change a disclosed value, delete a record, reorder records.
const clone = () => structuredClone(full);
const t1 = clone(); const h = t1.records.find((r) => r.payload.result === 'held'); h.payload.result = 'allowed';
check('changed decision is caught', verifyBundle(t1).result === 'fail');
const t2 = clone(); const d = t2.disclosures.find((x) => x.field === 'state_after'); d.value.refunded = 1;
check('changed disclosed value is caught', verifyBundle(t2).result === 'fail');
const t3 = clone(); t3.records.splice(1, 1);
check('deleted record is caught', verifyBundle(t3).result === 'fail');
const t4 = clone(); [t4.records[0], t4.records[1]] = [t4.records[1], t4.records[0]];
check('array order in the file does not matter: the chain is checked in its own order', verifyBundle(t4).result === 'pass');
const t5 = clone(); const r1 = t5.records.find((r) => r.payload.prev_receipt_hash); r1.payload.prev_receipt_hash = '0'.repeat(64);
check('a broken chain link is caught', verifyBundle(t5).result === 'fail');

// 8. A bundle re-signed by someone else's key passes on its own keys, but fails against the keys you trust.
const trusted = await oar.keys();
check('verifies against the issuer keys you trust', verifyBundle(bundle, { keys: trusted }).result === 'pass');
const imposter = createRecorder({ issuer: generateSigningKey('edge-agent'), org: 'edge', agent: 'agent-1' });
await imposter.run({ type: 'refund', target: 'orders', params: { order: '1142' }, execute: () => 'x' });
check('a look-alike issuer with another key is rejected', verifyBundle(await imposter.bundle(), { keys: trusted }).result === 'fail');

writeFileSync('edge-evidence.json', JSON.stringify(bundle, null, 2));
console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
process.exit(failures ? 1 : 0);
