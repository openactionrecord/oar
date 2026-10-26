import { describe, expect, it } from 'vitest';
import { generateSigningKey } from './crypto/keys.js';
import { canonicalDigest } from './crypto/hash.js';
import { verifyBundle, parseBundle } from './bundle.js';
import { createRecorder, type RecorderOptions } from './recorder.js';
import { createLocalSealer } from './sealer.js';
import { loadStandaloneVerifier } from './standalone.js';
import { summarize } from './summary.js';
import { createTestTsa } from './testing/tsa.js';
import { webcrypto } from 'node:crypto';

const subtle = webcrypto.subtle as never;

function setup(extra: Partial<RecorderOptions> = {}, sealed = true) {
  const issuer = generateSigningKey('shop-issuer-1');
  const sealer = sealed ? createLocalSealer({ key: generateSigningKey('shop-sealer-1') }) : undefined;
  const oar = createRecorder({ issuer, org: 'maple-and-pine', agent: 'rex', ...(sealer ? { sealer } : {}), policy: { refund: { approveAboveCents: 125_000 } }, ...extra });
  return { oar, sealer };
}

/** A fake payment system with an order and its refunds. */
function fakeStore() {
  const order = { id: '1142', totalCents: 190_000, refundedCents: 0 };
  return {
    order,
    read: () => ({ order: order.id, totalCents: order.totalCents, refundedCents: order.refundedCents }),
    refund(cents: number) {
      order.refundedCents += cents;
      return { id: 're_123', amountCents: cents, status: 'succeeded' };
    },
  };
}

describe('Recorder.run: a refund end to end', () => {
  it('records the decision, approval, execution and confirmation, and they verify', async () => {
    const { oar } = setup();
    const store = fakeStore();
    const out = await oar.run({
      type: 'refund',
      target: 'stripe',
      params: { order: '1142', amountCents: 190_000 },
      check: (p) => ((p.amountCents as number) > 125_000 ? { result: 'held', reasons: ['over_approval_limit'] } : { result: 'allowed' }),
      approve: () => ({ approver: 'jordan', approved: true }),
      readState: store.read,
      execute: () => store.refund(190_000),
      targetRef: (r) => r.id,
      confirm: (r) => r.status === 'succeeded',
    });

    expect(out.status).toBe('completed');
    expect(out.confirmed).toBe(true);
    expect(oar.records.map((r) => `${r.payload.phase}:${r.payload.result}`)).toEqual([
      'decision:held',
      'decision:approved',
      'execution:executed',
      'confirmation:confirmed',
    ]);
    // Nothing sensitive is written in clear.
    // (Look for the values as JSON values: random hex in signatures and hashes can contain the same digits.)
    const text = JSON.stringify(oar.records);
    expect(text).not.toMatch(/:190000[,}]/);
    expect(text).not.toContain('"re_123"');
    expect(text).not.toContain('"1142"');

    const bundle = await oar.bundle();
    const report = verifyBundle(bundle);
    expect(report.result).toBe('pass');
    expect(report.level).toBe('sealed');
    expect(bundle.scope.complete).toBe(true);
    expect(bundle.disclosures).toEqual([]);

    const [story] = summarize(bundle.records, bundle.disclosures, report);
    expect(story).toMatchObject({ type: 'refund', target: 'stripe', outcome: 'confirmed', approvedBy: 'jordan', stateRecorded: true, verified: true });
    expect(story!.steps.map((s) => s.text)).toEqual([
      'Held for approval by policy:default (over_approval_limit)',
      'Approved by approver:jordan (button)',
      'Executed; state before and after recorded',
      'Confirmed in the system of record',
    ]);
  });

  it('discloses state when asked, and the summary shows what changed', async () => {
    const { oar } = setup();
    const store = fakeStore();
    await oar.run({ type: 'refund', target: 'stripe', params: { order: '1142', amountCents: 5_000 }, readState: store.read, execute: () => store.refund(5_000) });
    const bundle = await oar.bundle({ disclose: 'all' });
    const report = verifyBundle(bundle);
    expect(report.result).toBe('pass');
    expect(report.receipts.every((r) => r.checks.disclosures !== 'fail')).toBe(true);
    const [story] = summarize(bundle.records, bundle.disclosures, report);
    expect(story!.before).toEqual({ order: '1142', totalCents: 190_000, refundedCents: 0 });
    expect(story!.after).toEqual({ order: '1142', totalCents: 190_000, refundedCents: 5_000 });
    expect(story!.outcome).toBe('executed_unconfirmed');
  });

  it('a changed disclosure fails verification', async () => {
    const { oar } = setup();
    const store = fakeStore();
    await oar.run({ type: 'refund', target: 'stripe', params: { order: '1142', amountCents: 5_000 }, readState: store.read, execute: () => store.refund(5_000) });
    const bundle = await oar.bundle({ disclose: ['state_after'] });
    (bundle.disclosures[0]!.value as { refundedCents: number }).refundedCents = 1;
    const report = verifyBundle(bundle);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toContain('disclosures');
  });

  it('a changed record fails, in both verifiers', async () => {
    const { oar } = setup();
    await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 100 }, execute: () => 'ok' });
    const bundle = await oar.bundle();
    bundle.records[0]!.payload.result = 'denied';
    expect(verifyBundle(bundle).result).toBe('fail');
    const standalone = await loadStandaloneVerifier()(bundle, subtle);
    expect(standalone.result).toBe('fail');
  });

  it('the standalone verifier agrees on a valid bundle', async () => {
    const { oar } = setup();
    const store = fakeStore();
    await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 100 }, readState: store.read, execute: () => store.refund(100), confirm: () => true });
    const bundle = await oar.bundle({ disclose: 'all' });
    const ref = verifyBundle(bundle);
    const alt = await loadStandaloneVerifier()(JSON.parse(JSON.stringify(bundle)), subtle);
    expect(alt.result).toBe(ref.result);
    expect(alt.level).toBe(ref.level);
    expect(alt.receipts.map((r) => r.checks)).toEqual(ref.receipts.map((r) => r.checks));
  });
});

describe('Recorder.run: every path is recorded', () => {
  it('a denied action is recorded and not executed', async () => {
    const { oar } = setup();
    let ran = false;
    const out = await oar.run({ type: 'discount', target: 'shopify', params: { percent: 80 }, check: () => ({ result: 'denied', reasons: ['over_maximum'] }), execute: () => (ran = true) });
    expect(out.status).toBe('denied');
    expect(ran).toBe(false);
    expect(oar.records.map((r) => r.payload.result)).toEqual(['denied']);
    const [story] = summarize(oar.records);
    expect(story!.outcome).toBe('denied');
  });

  it('a held action without an approver stops at held, and can be approved later', async () => {
    const { oar } = setup();
    const out = await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 200_000 }, check: () => ({ result: 'held' }), execute: () => 'x' });
    expect(out.status).toBe('held');
    await oar.approve(out.action, { approver: 'jordan' });
    await oar.execute(out.action, { before: { refunded: 0 }, after: { refunded: 200_000 }, targetRef: 're_9' });
    await oar.confirm(out.action, { confirmed: true });
    expect(verifyBundle(await oar.bundle()).result).toBe('pass');
    expect(summarize(oar.records)[0]!.outcome).toBe('confirmed');
  });

  it('a rejection is recorded and nothing runs', async () => {
    const { oar } = setup();
    let ran = false;
    const out = await oar.run({
      type: 'refund', target: 'stripe', params: { amountCents: 200_000 },
      check: () => ({ result: 'held' }), approve: () => ({ approver: 'jordan', approved: false }), execute: () => (ran = true),
    });
    expect(out.status).toBe('rejected');
    expect(ran).toBe(false);
    expect(oar.records.map((r) => r.payload.result)).toEqual(['held', 'rejected']);
  });

  it('a failed execution is recorded, then the error is re-thrown', async () => {
    const { oar } = setup();
    await expect(oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 1 }, execute: () => { throw new Error('card declined'); } })).rejects.toThrow('card declined');
    expect(oar.records.map((r) => r.payload.result)).toEqual(['allowed', 'failed']);
    expect(verifyBundle(await oar.bundle()).result).toBe('pass');
  });

  it('an agent that claims success without effect is caught by the confirmation', async () => {
    const { oar } = setup();
    const out = await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 500 }, execute: () => ({ id: 're_ghost' }), targetRef: (r) => r.id, confirm: () => false });
    expect(out.confirmed).toBe(false);
    const [story] = summarize(oar.records);
    expect(story!.outcome).toBe('not_confirmed');
    expect(story!.outcomeText).toMatch(/does NOT show it/);
  });

  it('refuses steps out of order', async () => {
    const { oar } = setup();
    const action = await oar.decide({ type: 'refund', target: 'stripe', params: {}, result: 'denied' });
    await expect(oar.execute(action)).rejects.toThrow(/Only an allowed or approved action/);
    await expect(oar.approve(action, { approver: 'jordan' })).rejects.toThrow(/Only a held action/);
  });

  it('refuses an email address as an approver reference', async () => {
    const { oar } = setup();
    const action = await oar.decide({ type: 'refund', target: 'stripe', params: {}, result: 'held' });
    await expect(oar.approve(action, { approver: 'jordan@example.com' })).rejects.toThrow(/not an email/);
  });
});

describe('Recorder: profiles and options', () => {
  it('issuer-signed records verify at the issuer-signed level, and fail when seals are required', async () => {
    const { oar } = setup({}, false);
    await oar.run({ type: 'store_credit', target: 'shopify', params: { cents: 12_500 }, execute: () => 'ok', confirm: () => true });
    const bundle = await oar.bundle();
    expect(bundle.keys.sealer).toBeUndefined();
    const report = verifyBundle(bundle);
    expect(report.result).toBe('pass');
    expect(report.level).toBe('issuer-signed');
    expect(verifyBundle(bundle, { requireSeal: true }).result).toBe('fail');
    const alt = await loadStandaloneVerifier()(bundle, subtle);
    expect(alt.result).toBe('pass');
    expect(alt.level).toBe('issuer-signed');
  });

  it('a removed record breaks the chain, even without a sealing service', async () => {
    const { oar } = setup({}, false);
    for (let i = 0; i < 3; i++) await oar.run({ type: 'store_credit', target: 'shopify', params: { i }, execute: () => i });
    const bundle = await oar.bundle();
    bundle.records.splice(1, 1);
    const report = verifyBundle(bundle);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toContain('chain');
  });

  it('adds evidence to a receipt in another format', async () => {
    const { oar } = setup();
    const other = { format: 'acta', bytes: '{"decision":"allow","tool":"refund"}' };
    const digest = canonicalDigest(other.bytes);
    await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 100 }, external: { format: 'acta', digest, id: 'rcpt-7' }, execute: () => 'ok', confirm: () => true });
    const bundle = await oar.bundle();
    expect(bundle.records[0]!.payload.external_ref).toEqual({ format: 'acta', digest, id: 'rcpt-7' });
    expect(verifyBundle(bundle).result).toBe('pass');
    expect(summarize(bundle.records)[0]!.external?.format).toBe('acta');
    await expect(oar.decide({ type: 'x', target: 'y', params: {}, result: 'allowed', external: { format: 'acta', digest: 'nope' } })).rejects.toThrow(/external/);
  });

  it('bundles one action on its own, as a partial bundle that still verifies', async () => {
    const { oar } = setup();
    const a = await oar.run({ type: 'refund', target: 'stripe', params: { n: 1 }, execute: () => 1 });
    await oar.run({ type: 'refund', target: 'stripe', params: { n: 2 }, execute: () => 2 });
    const bundle = await oar.bundle({ actionId: a.action.id, purpose: 'dispute' });
    expect(bundle.records).toHaveLength(2);
    expect(bundle.scope.complete).toBe(false);
    expect(verifyBundle(bundle).result).toBe('pass');
  });

  it('is reproducible with fixed clock, ids and salts', async () => {
    const make = async () => {
      let n = 0;
      const issuer = { kid: 'k', privateKey: '11'.repeat(32) };
      const oar = createRecorder({
        issuer, org: 'o', agent: 'a', run: 'run:1',
        now: () => new Date('2026-10-25T12:00:00.000Z'),
        randomId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
        randomSalt: () => 'ab'.repeat(32),
      });
      await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 1 }, execute: () => 1 });
      return JSON.stringify(oar.records);
    };
    expect(await make()).toBe(await make());
  });

  it('timestamps checkpoints with an outside authority, and both verifiers check the timestamp', async () => {
    const tsa = await createTestTsa();
    const fakeFetch = (async (_url: string, init: { body: Uint8Array }) => {
      const body = await tsa.respond(new Uint8Array(init.body), new Date('2026-10-25T12:00:00Z'));
      return new Response(Buffer.from(body), { status: 200 });
    }) as unknown as typeof fetch;
    const { oar, sealer } = setup();
    await oar.run({ type: 'refund', target: 'stripe', params: { amountCents: 1 }, execute: () => 1, confirm: () => true });
    const anchor = await sealer!.anchor({ fetch: fakeFetch, roots: tsa.roots });
    expect(anchor?.tsa).toBe('OAR Test Timestamp Authority');
    const bundle = await oar.bundle();
    const report = verifyBundle(bundle, { tsaRoots: tsa.roots });
    expect(report.result).toBe('pass');
    expect(report.level).toBe('timestamped');
    const alt = await loadStandaloneVerifier()(bundle, subtle, { tsaRoots: tsa.roots });
    expect(alt.level).toBe('timestamped');
    // Against the default (DigiCert) roots the test authority is not trusted.
    expect(verifyBundle(bundle).result).toBe('fail');
  });
});

describe('parseBundle', () => {
  it('says what is wrong with a bad file', () => {
    expect(() => parseBundle({ format: 'x', records: 'no' })).toThrow(/format: expected "oar-bundle\/0.1"[\s\S]*records: expected an array/);
  });

  it('reads legacy evidence packages that call records "receipts"', async () => {
    const { oar } = setup();
    await oar.run({ type: 'refund', target: 'stripe', params: {}, execute: () => 1 });
    const { records, ...rest } = await oar.bundle();
    const legacy = { ...rest, format: 'aar-evidence/0.1', receipts: records };
    expect(verifyBundle(legacy).result).toBe('pass');
    expect((await loadStandaloneVerifier()(legacy, subtle)).result).toBe('pass');
  });
});
