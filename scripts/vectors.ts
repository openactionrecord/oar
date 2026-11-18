// Generates the test vectors in vectors/. Run with `pnpm vectors`. Deterministic: the same code produces the
// same files, byte for byte. TEST KEYS ONLY: never use these keys for anything real.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  anchorDigest,
  createLocalSealer,
  verifyTimestampToken,
  createRecorder,
  signRecord,
  summarize,
  verifyBundle,
  type Bundle,
  type RecorderOptions,
  type SigningKey,
  type TsaRoot,
} from '@openactionrecord/core';
import { createTestTsa, type TestTsaKeys } from '@openactionrecord/core/testing';

const dir = fileURLToPath(new URL('../vectors/', import.meta.url));
const ISSUER: SigningKey = { kid: 'oar-test-issuer', privateKey: '11'.repeat(32) };
const SEALER: SigningKey = { kid: 'oar-test-sealer', privateKey: '22'.repeat(32) };

/** Deterministic clock, ids and salts. */
function determinism(seed: string) {
  let t = Date.parse('2026-10-25T14:00:00.000Z');
  let n = 0;
  let s = 0;
  return {
    now: () => new Date((t += 1_000)),
    randomId: () => {
      const h = createHash('sha256').update(`${seed}:id:${++n}`).digest('hex');
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
    },
    randomSalt: () => createHash('sha256').update(`${seed}:salt:${++s}`).digest('hex'),
  };
}

function recorder(seed: string, sealed: boolean, extra: Partial<RecorderOptions> = {}) {
  const d = determinism(seed);
  const sealer = sealed ? createLocalSealer({ key: SEALER, now: d.now }) : undefined;
  const oar = createRecorder({
    issuer: ISSUER,
    org: 'example-store',
    orgName: 'Example Store (test vectors)',
    agent: 'support-agent',
    run: 'run:test-1',
    policyId: 'store-rules-v1',
    policy: { refundApprovalAboveCents: 125_000, maxDiscountPercent: 20 },
    ...(sealer ? { sealer } : {}),
    ...d,
    ...extra,
  });
  return { oar, sealer };
}

function ledger() {
  const order = { order: '1142', totalCents: 190_000, refundedCents: 0 };
  return {
    read: () => ({ ...order }),
    refund: (cents: number) => {
      order.refundedCents += cents;
      return { id: 're_test_0001', status: 'succeeded' };
    },
  };
}

async function refundLifecycle(roots: TsaRoot[], tsaKeys: TestTsaKeys): Promise<Bundle> {
  const { oar, sealer } = recorder('refund-lifecycle', true);
  const store = ledger();
  await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1142', amountCents: 190_000 },
    idempotencyKey: 'refund-1142-1',
    check: () => ({ result: 'held', reasons: ['over_approval_limit'] }),
    approve: () => ({ approver: 'jordan', approved: true, method: 'passkey', assertion: { placeholder: 'a WebAuthn assertion goes here in real use' } }),
    readState: store.read,
    execute: () => store.refund(190_000),
    targetRef: (r) => r.id,
    confirm: () => true,
  });
  // Timestamp the latest checkpoint directly (a request would carry a random nonce, and vectors must repeat).
  const tsa = await createTestTsa({ keys: tsaKeys });
  const cp = sealer!.checkpoints().at(-1)!;
  const genTime = new Date('2026-10-25T14:10:00Z');
  const token = await tsa.issue(anchorDigest(cp), genTime);
  const checked = verifyTimestampToken(token, anchorDigest(cp), roots);
  if (!checked.ok) throw new Error(checked.reason);
  cp.anchors = [{ type: 'rfc3161', tsa: checked.tsa, gen_time: checked.genTime, token }];
  return oar.bundle({ disclose: 'all', purpose: 'dispute' });
}

async function main(): Promise<void> {
  await mkdir(dir, { recursive: true });
  // The test timestamp authority's keys are fixed, so its root and tokens are repeatable.
  const keysFile = `${dir}test-tsa-keys.json`;
  const tsaKeys: TestTsaKeys = existsSync(keysFile) ? JSON.parse(readFileSync(keysFile, 'utf8')) : (await createTestTsa()).keys;
  const tsa = await createTestTsa({ keys: tsaKeys });
  const roots = tsa.roots;

  const vectors: { file: string; description: string; bundle: Bundle; options?: { requireSeal?: boolean }; expect: { result: 'pass' | 'fail'; level?: string; failedChecks?: string[]; outcomes?: string[] } }[] = [];
  const add = (v: (typeof vectors)[number]) => vectors.push(v);

  const lifecycle = await refundLifecycle(roots, tsaKeys);
  add({ file: 'refund-lifecycle.json', description: 'A $1,900 refund: held over the approval limit, approved with a passkey, executed with state before and after, confirmed; sealed, checkpointed and timestamped by the test authority. All values disclosed.', bundle: lifecycle, expect: { result: 'pass', level: 'timestamped', outcomes: ['confirmed'] } });

  const editedRecord = structuredClone(lifecycle);
  const held = editedRecord.records.find((r) => r.payload.result === 'held')!;
  held.payload.result = 'allowed';
  held.payload.reasons = ['within_limits'];
  add({ file: 'tampered-record.json', description: 'refund-lifecycle with the held decision rewritten as "allowed".', bundle: editedRecord, expect: { result: 'fail', failedChecks: ['chain', 'checkpoint', 'issuer_signature', 'seal', 'timestamp'] } });

  const editedDisclosure = structuredClone(lifecycle);
  const after = editedDisclosure.disclosures.find((d) => d.field === 'state_after')!;
  (after.value as { refundedCents: number }).refundedCents = 19_000;
  add({ file: 'tampered-disclosure.json', description: 'refund-lifecycle with the disclosed state after the change edited ($190 refunded instead of $1,900).', bundle: editedDisclosure, expect: { result: 'fail', failedChecks: ['disclosures'] } });

  const removed = structuredClone(lifecycle);
  removed.records.splice(1, 1);
  add({ file: 'removed-record.json', description: 'refund-lifecycle with the approval record removed.', bundle: removed, expect: { result: 'fail', failedChecks: ['chain', 'checkpoint'] } });

  // Section 8: a retention statement, and a bundle field no verifier knows, change nothing.
  const retained = structuredClone(lifecycle) as Bundle & Record<string, unknown>;
  retained.retention = { keep_until: '2027-05-25T00:00:00Z', basis: 'AI Act Article 19, six months' };
  retained.x_future_field = { note: 'verifiers ignore bundle fields they do not know' };
  add({ file: 'retention.json', description: 'refund-lifecycle with a retention statement and an unknown bundle field. Both are ignored by verification.', bundle: retained, expect: { result: 'pass', level: 'timestamped', outcomes: ['confirmed'] } });

  // Section 11.1: erasing the openings of personal values leaves every record verifiable.
  const erased = structuredClone(lifecycle);
  erased.disclosures = erased.disclosures.filter((d) => d.field !== 'state_before' && d.field !== 'state_after');
  add({ file: 'erased-values.json', description: 'refund-lifecycle after erasure: the disclosures of the state before and after are deleted. The records still verify.', bundle: erased, expect: { result: 'pass', level: 'timestamped', outcomes: ['confirmed'] } });

  {
    const { oar } = recorder('issuer-signed', false);
    await oar.run({ type: 'store_credit', target: 'store', params: { customer: 'c-77', cents: 12_500 }, idempotencyKey: 'credit-1', execute: () => ({ id: 'cr_1' }), targetRef: (r) => r.id, confirm: () => true });
    const bundle = await oar.bundle();
    add({ file: 'issuer-signed.json', description: 'A store credit recorded without a sealing service: issuer-signed only. Nothing disclosed.', bundle, expect: { result: 'pass', level: 'issuer-signed', outcomes: ['confirmed'] } });
    add({ file: 'issuer-signed.json', description: 'The same bundle verified with seals required.', bundle, options: { requireSeal: true }, expect: { result: 'fail', failedChecks: ['seal'] } });
  }

  {
    const { oar } = recorder('not-confirmed', true);
    await oar.run({ type: 'refund', target: 'payments', params: { order: '1187', amountCents: 4_500 }, idempotencyKey: 'refund-1187-1', readState: () => ({ order: '1187', refundedCents: 0 }), execute: () => ({ id: 're_ghost' }), targetRef: (r) => r.id, confirm: () => false });
    await oar.run({ type: 'discount_code', target: 'store', params: { percent: 80 }, idempotencyKey: 'discount-1', check: () => ({ result: 'denied', reasons: ['over_maximum_discount'] }), execute: () => 'never' });
    add({ file: 'not-confirmed.json', description: 'A refund the payment API reported as succeeded but the read-back does not show, and a blocked 80% discount. The records verify; the outcomes are "not_confirmed" and "denied".', bundle: await oar.bundle({ disclose: 'all' }), expect: { result: 'pass', level: 'sealed', outcomes: ['not_confirmed', 'denied'] } });
  }

  {
    const { oar } = recorder('external-ref', true);
    const other = '{"v":1,"tool":"payments.refund","decision":"allow","sig":"(a receipt in another format)"}';
    const digest = `sha256:${createHash('sha256').update(other).digest('hex')}`;
    await oar.run({ type: 'refund', target: 'payments', params: { amountCents: 2_000 }, idempotencyKey: 'ext-1', external: { format: 'acta', digest, id: 'acta-rcpt-42' }, execute: () => 'ok', confirm: () => true });
    add({ file: 'external-ref.json', description: 'OAR approval and outcome evidence added to a receipt in another format (external_ref with the digest of its bytes).', bundle: await oar.bundle(), expect: { result: 'pass', level: 'sealed', outcomes: ['confirmed'] } });
  }

  {
    // Section 4.3: a payment held over the limit, approved through an outside service (a SIM check), bound to
    // the action and to what the approver was shown.
    const { oar } = recorder('approval-external', true);
    const action = await oar.decide({ type: 'wire_transfer', target: 'core-banking', params: { payee: 'P-1002', amountCents: 4_800_000 }, idempotencyKey: 'wire-1', result: 'held', reasons: ['over_approval_limit'] });
    const request = await oar.requestApproval(action, { display: { text: 'Pay $48,000.00 to payee P-1002', amountCents: 4_800_000, payee: 'P-1002' } });
    const proof = JSON.stringify({ result: 'approved', binding: request.binding, ref: 'chk-0001' });
    await oar.approve(action, { approver: 'treasury-lead', evidence: { provider: 'sim-check', format: 'provider-json', proof, id: 'chk-0001' } });
    await oar.execute(action, { targetRef: 'wire-77' });
    await oar.confirm(action, { confirmed: true });
    add({ file: 'approval-external.json', description: 'A $48,000 wire held over the limit and approved through an outside service (a SIM check). The approval binding covers the action and what the approver was shown; the proof is recorded by digest. All values disclosed.', bundle: await oar.bundle({ disclose: 'all' }), expect: { result: 'pass', level: 'sealed', outcomes: ['confirmed'] } });
  }

  {
    // The issuer records "approved" although the approver's passkey signed a rejection, and re-signs the record.
    // Signatures pass; only the approval check catches it.
    const { oar } = recorder('approval-flipped', false);
    const action = await oar.decide({ type: 'change_payout_details', target: 'core-banking', params: { account: 'A-31' }, idempotencyKey: 'payout-1', result: 'held', reasons: ['payee_details_changed'] });
    await oar.requestApproval(action, { decision: 'reject' });
    await oar.approve(action, { approver: 'ops-lead', approved: false, assertion: { placeholder: 'a WebAuthn assertion over the reject challenge' } });
    const bundle = await oar.bundle();
    const last = bundle.records[bundle.records.length - 1]!;
    last.payload.result = 'approved';
    last.payload.reasons = ['approved_by_person'];
    bundle.records[bundle.records.length - 1] = signRecord(last.payload, ISSUER);
    add({ file: 'approval-flipped.json', description: 'An approver signed a rejection with a passkey; the issuer recorded and re-signed it as approved. Only the approval binding check fails.', bundle, expect: { result: 'fail', failedChecks: ['approval'] } });
  }

  // Section 4.5: a payout that relied on two outside artifacts, a delegated authorization and a credential proof,
  // both checked again at the moment it committed.
  const authorities = [
    { type: 'aauth', issuer: 'https://person.example', artifact: 'aauth grant: payout up to $5,000 to payee P-1001', expiresAt: '2026-10-26T14:00:00Z' },
    { type: 'x401', issuer: 'https://wallet.example', artifact: 'x401 proof: verified business customer' },
  ];
  {
    const { oar } = recorder('authority-current', true);
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { payee: 'P-1001', amountCents: 420_000 }, idempotencyKey: 'payout-1', result: 'allowed', authorities });
    await oar.execute(action, { targetRef: 'po_1001', authorityCheck: { statuses: ['valid', 'valid'] } });
    await oar.confirm(action, { confirmed: true });
    add({ file: 'authority-current.json', description: 'A payout that relied on two outside artifacts (a delegated authorization and a credential proof), both checked again just before it committed, then confirmed. Outcome class: committed.', bundle: await oar.bundle({ disclose: 'all' }), expect: { result: 'pass', level: 'sealed', outcomes: ['confirmed'] } });
  }
  {
    const { oar } = recorder('authority-revoked', true);
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { payee: 'P-1001', amountCents: 420_000 }, idempotencyKey: 'payout-2', result: 'allowed', authorities });
    await oar.execute(action, { authorityCheck: { statuses: ['revoked', 'valid'] } });
    add({ file: 'authority-revoked.json', description: 'The person revoked the delegated authorization between the decision and the payout. The re-check found it, so the payout was refused and nothing ran. Outcome class: refused.', bundle: await oar.bundle(), expect: { result: 'pass', level: 'sealed', outcomes: ['refused'] } });
  }
  {
    // The issuer drops the re-check from the execution record and re-signs it. Only the authority check catches it.
    const { oar } = recorder('authority-not-rechecked', false);
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { payee: 'P-1001', amountCents: 420_000 }, idempotencyKey: 'payout-3', result: 'allowed', authorities });
    await oar.execute(action, { authorityCheck: { statuses: ['valid', 'valid'] } });
    const bundle = await oar.bundle();
    const last = bundle.records[bundle.records.length - 1]!;
    delete last.payload.authority_check;
    bundle.records[bundle.records.length - 1] = signRecord(last.payload, ISSUER);
    add({ file: 'authority-not-rechecked.json', description: 'A payout that ran without its authorities being checked again at the moment it committed (the issuer removed the check and re-signed). Only the authority check fails.', bundle, expect: { result: 'fail', failedChecks: ['authority'] } });
  }
  {
    // The re-check claims every authority was current, a day after the delegated authorization expired.
    const { oar } = recorder('authority-stale', false);
    const action = await oar.decide({ type: 'vendor_payout', target: 'payments', params: { payee: 'P-1001', amountCents: 420_000 }, idempotencyKey: 'payout-4', result: 'allowed', authorities });
    await oar.execute(action, { authorityCheck: { statuses: ['valid', 'valid'] } });
    const bundle = await oar.bundle();
    const last = bundle.records[bundle.records.length - 1]!;
    last.payload.authority_check!.checked_at = '2026-10-27T09:00:00.000Z';
    bundle.records[bundle.records.length - 1] = signRecord(last.payload, ISSUER);
    add({ file: 'authority-stale.json', description: 'The re-check says every authority was current, but the delegated authorization had already expired. Only the authority check fails.', bundle, expect: { result: 'fail', failedChecks: ['authority'] } });
  }

  // Check every expectation before writing anything.
  for (const v of vectors) {
    const report = verifyBundle(v.bundle, { tsaRoots: roots, ...(v.options ?? {}) });
    const problems: string[] = [];
    if (report.result !== v.expect.result) problems.push(`result ${report.result}`);
    if (v.expect.level && report.level !== v.expect.level) problems.push(`level ${report.level}`);
    if (v.expect.failedChecks && [...report.failedChecks].sort().join() !== [...v.expect.failedChecks].sort().join()) problems.push(`failed ${report.failedChecks.join()}`);
    if (v.expect.outcomes && summarize(v.bundle.records).map((s) => s.outcome).join() !== v.expect.outcomes.join()) problems.push('outcomes');
    if (problems.length) throw new Error(`${v.file}: ${problems.join('; ')}`);
  }

  const written = new Set<string>();
  for (const v of vectors) {
    if (written.has(v.file)) continue;
    written.add(v.file);
    await writeFile(`${dir}${v.file}`, `${JSON.stringify(v.bundle, null, 2)}\n`);
  }
  await writeFile(keysFile, `${JSON.stringify(tsaKeys, null, 2)}\n`);
  await writeFile(`${dir}test-tsa-roots.json`, `${JSON.stringify(roots, null, 2)}\n`);
  const manifest = {
    description: 'Open Action Record test vectors. Every verifier must reach the expected result on every case. TEST KEYS ONLY.',
    test_private_keys_hex: { [ISSUER.kid]: ISSUER.privateKey, [SEALER.kid]: SEALER.privateKey },
    tsa_roots_file: 'test-tsa-roots.json',
    cases: vectors.map((v) => ({ file: v.file, description: v.description, options: { tsa_roots: 'test', ...(v.options?.requireSeal ? { require_seal: true } : {}) }, expect: v.expect })),
  };
  await writeFile(`${dir}manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Wrote ${written.size} vector files and ${vectors.length} cases to vectors/`);
}

await main();
