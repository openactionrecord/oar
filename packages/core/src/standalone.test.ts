import { describe, expect, it } from 'vitest';
import { commit } from './crypto/commitment.js';
import { loadStandaloneVerifier } from './standalone.js';
import { createLedger, type Ledger } from './testing/ledger.js';
import { createTestTsa, type TestTsa } from './testing/tsa.js';
import { anchorDigest } from './timestamp/timestamp.js';
import type { TsaRoot } from './timestamp/tsa-roots.js';
import { verify } from './verify.js';

// The standalone verifier (plain JavaScript on WebCrypto) must reach the same answer as the core verifier.

const standalone = loadStandaloneVerifier();
const subtle = globalThis.crypto.subtle;

function ledger(): Ledger {
  const l = createLedger();
  const before = commit({ refundedCents: 0 });
  const after = commit({ refundedCents: 2_500 });
  l.issue('agent:a');
  const execution = l.issue('agent:a', { phase: 'execution', result: 'executed', state_before_commitment: before.commitment, state_after_commitment: after.commitment });
  l.issue('agent:b');
  l.issue('agent:a', { phase: 'confirmation', result: 'confirmed', reasons: ['outcome_confirmed'] });
  l.disclosures.push(
    { receiptId: execution.payload.receipt_id, field: 'state_before', salt: before.salt, value: { refundedCents: 0 } },
    { receiptId: execution.payload.receipt_id, field: 'state_after', salt: after.salt, value: { refundedCents: 2_500 } },
  );
  l.checkpoint();
  return l;
}

const pkgOf = (l: Ledger, overrides: Partial<{ receipts: unknown[]; disclosures: unknown[]; complete: boolean }> = {}) => ({
  receipts: overrides.receipts ?? l.envelopes,
  disclosures: overrides.disclosures ?? l.disclosures,
  checkpoints: l.checkpoints,
  keys: l.keys,
  scope: { complete: overrides.complete ?? true },
});

async function both(l: Ledger, overrides: Parameters<typeof pkgOf>[1] = {}, tsaRoots?: TsaRoot[]) {
  const pkg = pkgOf(l, overrides);
  const core = verify(pkg.receipts as never, pkg.disclosures as never, l.checkpoints, l.keys, { partial: !pkg.scope.complete, ...(tsaRoots ? { tsaRoots } : {}) });
  const alone = await standalone(structuredClone(pkg), subtle, tsaRoots ? { tsaRoots } : undefined);
  return { core, alone };
}

/** Timestamps the ledger's latest checkpoint with the test authority. */
async function anchorLatest(l: Ledger, tsa: TestTsa, at = new Date('2026-10-18T14:10:00Z')): Promise<void> {
  const cp = l.checkpoints[l.checkpoints.length - 1]!;
  cp.anchors = [{ type: 'rfc3161', tsa: tsa.name, gen_time: at.toISOString(), token: await tsa.issue(anchorDigest(cp), at) }];
}

const sameAnswer = ({ core, alone }: Awaited<ReturnType<typeof both>>) => {
  expect(alone.result).toBe(core.result);
  expect([...alone.failedChecks].sort()).toEqual([...core.failedChecks].sort());
  expect(alone.receipts.map((r) => [r.receiptId, r.checks])).toEqual(core.receipts.map((r) => [r.receiptId, r.checks]));
};

describe('standalone verifier agrees with the core verifier', () => {
  it('on an untouched set', async () => {
    const result = await both(ledger());
    expect(result.alone.result).toBe('pass');
    sameAnswer(result);
  });

  it('when a payload was changed', async () => {
    const l = ledger();
    const receipts = structuredClone(l.envelopes);
    (receipts[1]!.payload as { result: string }).result = 'failed';
    sameAnswer(await both(l, { receipts }));
  });

  it('when a disclosed value was changed', async () => {
    const l = ledger();
    const disclosures = l.disclosures.map((d) => (d.field === 'state_after' ? { ...d, value: { refundedCents: 250_000 } } : d));
    const result = await both(l, { disclosures });
    expect(result.alone.failedChecks).toEqual(['disclosures']);
    sameAnswer(result);
  });

  it('when a record was removed', async () => {
    const l = ledger();
    sameAnswer(await both(l, { receipts: l.envelopes.filter((_, i) => i !== 1) }));
  });

  it('on a partial package (one action)', async () => {
    const l = ledger();
    sameAnswer(await both(l, { receipts: l.envelopes.slice(1, 2), complete: false }));
  });

  it('when a checkpoint signature was forged', async () => {
    const l = ledger();
    l.checkpoints[0] = { ...l.checkpoints[0]!, count: l.checkpoints[0]!.count + 1 };
    sameAnswer(await both(l));
  });
});

describe.each(['RSA', 'ECDSA'] as const)('outside timestamps, both verifiers (%s)', (algorithm) => {
  it('pass when the checkpoint is timestamped, and name the authority', async () => {
    const tsa = await createTestTsa({ algorithm });
    const l = ledger();
    await anchorLatest(l, tsa);
    const result = await both(l, {}, tsa.roots);
    expect(result.alone.result).toBe('pass');
    expect(result.alone.receipts.every((r) => r.checks.timestamp === 'pass')).toBe(true);
    expect(result.core.timestamp).toEqual({ tsa: tsa.name, at: '2026-10-18T14:10:00.000Z', count: 4 });
    expect(result.alone.timestamp).toEqual(result.core.timestamp);
    sameAnswer(result);
  });

  it('fail when the token was changed, and when its root is not accepted', async () => {
    const tsa = await createTestTsa({ algorithm });
    const l = ledger();
    await anchorLatest(l, tsa);
    const anchor = l.checkpoints[0]!.anchors![0]!;
    const bytes = Buffer.from(anchor.token, 'base64');
    bytes[bytes.length - 2] = bytes[bytes.length - 2]! ^ 0x01;
    anchor.token = bytes.toString('base64');
    const changed = await both(l, {}, tsa.roots);
    expect(changed.alone.failedChecks).toEqual(['timestamp']);
    sameAnswer(changed);

    const other = ledger();
    await anchorLatest(other, tsa);
    const untrusted = await both(other); // default roots: DigiCert only
    expect(untrusted.alone.result).toBe('fail');
    sameAnswer(untrusted);
  });

  it('fail when the timestamp belongs to another checkpoint', async () => {
    const tsa = await createTestTsa({ algorithm });
    const l = ledger();
    await anchorLatest(l, tsa);
    const forged = ledger();
    forged.checkpoints[0]!.anchors = l.checkpoints[0]!.anchors;
    const result = await both(forged, {}, tsa.roots);
    expect(result.alone.failedChecks).toEqual(['timestamp']);
    sameAnswer(result);
  });

  it('report records after the timestamped checkpoint as pending, and agree on a partial package', async () => {
    const tsa = await createTestTsa({ algorithm });
    const l = ledger();
    await anchorLatest(l, tsa);
    l.issue('agent:a');
    l.checkpoint();
    const result = await both(l, {}, tsa.roots);
    expect(result.alone.result).toBe('pass');
    expect(result.alone.receipts.at(-1)!.checks.timestamp).toBe('not_checked');
    sameAnswer(result);
    sameAnswer(await both(l, { receipts: l.envelopes.slice(1, 2), complete: false }, tsa.roots));
  });
});
