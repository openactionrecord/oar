import { describe, expect, it } from 'vitest';
import { generatePrivateKey, toJwk } from './crypto/keys.js';
import { createSeal, recordHash, payloadHash, signCheckpoint, signRecord, type OarRecord } from './record.js';
import { createLedger, type Ledger } from './testing/ledger.js';
import { verify, type CheckName } from './verify.js';

function ledgerWith(count: number, agents = ['agent:rex']): Ledger {
  const ledger = createLedger();
  for (let i = 0; i < count; i++) ledger.issue(agents[i % agents.length]!);
  ledger.checkpoint();
  return ledger;
}

function check(ledger: Ledger, envelopes = ledger.envelopes, options = {}) {
  return verify(envelopes, ledger.disclosures, ledger.checkpoints, ledger.keys, options);
}

function failedChecks(report: ReturnType<typeof verify>): CheckName[] {
  return [...report.failedChecks].sort();
}

const clone = <T>(value: T): T => structuredClone(value);

describe('verify: valid records', () => {
  it('passes every check for an untouched set', () => {
    const ledger = ledgerWith(12, ['agent:rex', 'agent:ivy']);
    const report = check(ledger);
    expect(report.result).toBe('pass');
    expect(report.failedChecks).toEqual([]);
    expect(report.checkpoint?.count).toBe(12);
    for (const r of report.receipts) {
      expect(r.checks).toEqual({ issuer_signature: 'pass', seal: 'pass', chain: 'pass', checkpoint: 'pass', disclosures: 'pass', timestamp: 'not_checked' });
    }
    expect(report.messages[0]).toBe('All 12 records passed verification. Evidence level: Sealed by a separate service.');
    expect(report.level).toBe('sealed');
  });

  it('marks disclosures not checked when none are given', () => {
    const ledger = ledgerWith(3);
    const report = verify(ledger.envelopes, undefined, ledger.checkpoints, ledger.keys);
    expect(report.result).toBe('pass');
    expect(report.receipts.every((r) => r.checks.disclosures === 'not_checked')).toBe(true);
  });

  it('reports records after the latest checkpoint as not yet covered', () => {
    const ledger = ledgerWith(3);
    ledger.issue('agent:rex');
    const report = check(ledger);
    expect(report.result).toBe('pass');
    const last = report.receipts.at(-1)!;
    expect(last.checks.checkpoint).toBe('not_checked');
    expect(last.messages).toContain('Not yet covered by a checkpoint.');
  });

  it('marks checkpoint coverage not checked when there is no checkpoint', () => {
    const ledger = createLedger();
    ledger.issue('agent:rex');
    const report = check(ledger);
    expect(report.result).toBe('pass');
    expect(report.receipts[0]!.checks.checkpoint).toBe('not_checked');
  });

  it('uses the latest of several checkpoints', () => {
    const ledger = createLedger();
    for (let i = 0; i < 3; i++) ledger.issue('agent:rex');
    ledger.checkpoint();
    for (let i = 0; i < 3; i++) ledger.issue('agent:rex');
    ledger.checkpoint();
    const report = check(ledger);
    expect(report.result).toBe('pass');
    expect(report.checkpoint?.count).toBe(6);
  });

  it('does not depend on the order envelopes are passed in', () => {
    const ledger = ledgerWith(6, ['agent:rex', 'agent:ivy']);
    expect(check(ledger, [...ledger.envelopes].reverse()).result).toBe('pass');
  });
});

describe('verify: tampering and failures', () => {
  it('a changed payload fails the issuer signature, seal, chain and checkpoint checks', () => {
    const ledger = ledgerWith(5);
    const envelopes = clone(ledger.envelopes);
    envelopes[2]!.payload.result = 'executed';
    const report = check(ledger, envelopes);
    expect(report.result).toBe('fail');
    expect(failedChecks(report)).toEqual(['chain', 'checkpoint', 'issuer_signature', 'seal']);
    expect(report.receipts[2]!.checks.issuer_signature).toBe('fail');
    expect(report.receipts[3]!.checks.chain).toBe('fail');
    // Checkpoint coverage points at the changed record only; untouched records still match the sealer.
    expect(report.receipts.map((r) => r.checks.checkpoint)).toEqual(['pass', 'pass', 'fail', 'pass', 'pass']);
    expect(report.receipts[2]!.messages).toContain('This record does not match what the sealer recorded at checkpoint 5.');
    expect(report.messages[0]).toMatch(/^Verification failed: .*Issuer signature/);
  });

  it('a record re-signed with a stolen-looking unknown issuer key fails the issuer signature check', () => {
    const ledger = ledgerWith(2);
    const envelopes = clone(ledger.envelopes);
    const forged = signRecord(envelopes[1]!.payload, { kid: 'oar-test-issuer', privateKey: generatePrivateKey() });
    envelopes[1] = { ...forged, seal: envelopes[1]!.seal! };
    const report = check(ledger, envelopes);
    expect(failedChecks(report)).toEqual(['issuer_signature']);
  });

  it('an unknown issuer kid fails the issuer signature check', () => {
    const ledger = ledgerWith(1);
    const envelopes = clone(ledger.envelopes);
    envelopes[0]!.issuer_sig.kid = 'someone-else';
    expect(failedChecks(check(ledger, envelopes))).toEqual(['issuer_signature']);
  });

  it('a wrong issuer algorithm fails the issuer signature check', () => {
    const ledger = ledgerWith(1);
    const envelopes = clone(ledger.envelopes);
    (envelopes[0]!.issuer_sig as { alg: string }).alg = 'none';
    expect(failedChecks(check(ledger, envelopes))).toEqual(['issuer_signature']);
  });

  it('a seal for a different record fails the seal check', () => {
    const ledger = ledgerWith(3);
    const envelopes = clone(ledger.envelopes);
    envelopes[1]!.seal = { ...envelopes[0]!.seal!, seq: envelopes[1]!.seal!.seq };
    const report = check(ledger, envelopes);
    expect(report.receipts[1]!.checks.seal).toBe('fail');
    expect(report.receipts[1]!.messages.join(' ')).toMatch(/seal does not match/);
  });

  it('a changed seal number fails the seal check', () => {
    const ledger = ledgerWith(3);
    const envelopes = clone(ledger.envelopes);
    envelopes[1]!.seal!.seq = 99;
    expect(check(ledger, envelopes).receipts[1]!.checks.seal).toBe('fail');
  });

  it('a seal from an unknown sealer key fails the seal check', () => {
    const ledger = ledgerWith(1);
    const envelopes = clone(ledger.envelopes);
    const env = envelopes[0]!;
    env.seal = createSeal(payloadHash(env.payload), 1, env.seal!.sealed_at, { kid: 'oar-test-sealer', privateKey: generatePrivateKey() });
    const report = check(ledger, envelopes);
    expect(report.receipts[0]!.checks.seal).toBe('fail');
  });

  it('an unsealed record fails the seal check when seals are required', () => {
    const ledger = ledgerWith(2);
    const envelopes = clone(ledger.envelopes);
    delete envelopes[1]!.seal;
    const report = check(ledger, envelopes, { requireSeal: true });
    expect(report.receipts[1]!.checks.seal).toBe('fail');
    expect(report.receipts[1]!.messages).toContain('This record has not been sealed.');
  });

  it('a seal stripped from a sealed set is still caught by checkpoint coverage', () => {
    const ledger = ledgerWith(2);
    const envelopes = clone(ledger.envelopes);
    delete envelopes[1]!.seal;
    const report = check(ledger, envelopes);
    expect(report.receipts[1]!.checks.seal).toBe('not_checked');
    expect(report.receipts[1]!.level).toBe('issuer-signed');
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toContain('checkpoint');
  });

  it('a removed record breaks the chain and checkpoint coverage', () => {
    const ledger = ledgerWith(5);
    const envelopes = ledger.envelopes.filter((_, i) => i !== 2);
    const report = check(ledger, envelopes);
    expect(failedChecks(report)).toEqual(['chain', 'checkpoint']);
    expect(report.messages.join(' ')).toMatch(/missing \(seq 3\)/);
  });

  it('truncating the newest records fails checkpoint coverage', () => {
    const ledger = ledgerWith(5);
    const report = check(ledger, ledger.envelopes.slice(0, 3));
    expect(failedChecks(report)).toEqual(['checkpoint']);
    expect(report.messages.join(' ')).toMatch(/2 record\(s\) .* missing \(seq 4, 5\)/);
  });

  it('a missing first record fails the chain check', () => {
    const ledger = ledgerWith(3);
    const report = check(ledger, ledger.envelopes.slice(1));
    expect(report.receipts[0]!.checks.chain).toBe('fail');
    expect(report.receipts[0]!.messages).toContain("The record before this one in the agent's chain is missing.");
  });

  it('an inserted record that claims to be first fails the chain check', () => {
    const ledger = ledgerWith(2);
    ledger.issue('agent:rex', { prev_receipt_hash: undefined });
    const report = check(ledger);
    expect(report.receipts.at(-1)!.checks.chain).toBe('fail');
    expect(report.receipts.at(-1)!.messages.join(' ')).toMatch(/claims to be the agent's first/);
  });

  it('a forked chain (two records with the same predecessor) fails the chain check', () => {
    const ledger = ledgerWith(2);
    ledger.issue('agent:rex', { prev_receipt_hash: recordHash(ledger.envelopes[0]!) });
    expect(failedChecks(check(ledger))).toEqual(['chain']);
  });

  it('two records with the same seal number fail checkpoint coverage', () => {
    const ledger = createLedger();
    ledger.issue('agent:rex');
    ledger.issue('agent:rex');
    const envelopes = clone(ledger.envelopes);
    const second = envelopes[1]!;
    second.seal = createSeal(payloadHash(second.payload), 1, second.seal!.sealed_at, ledger.sealer);
    const cp = signCheckpoint({ count: 2, head_digest: 'sha256:' + '1'.repeat(64), at: second.seal.sealed_at }, ledger.sealer);
    const report = verify(envelopes, undefined, [cp], ledger.keys);
    expect(report.failedChecks).toContain('checkpoint');
    expect(report.messages.join(' ')).toMatch(/same seal number|missing/);
  });

  it('a checkpoint with a wrong head fails checkpoint coverage', () => {
    const ledger = ledgerWith(3);
    const cp = signCheckpoint({ count: 3, head_digest: 'sha256:' + 'f'.repeat(64), at: '2026-10-15T15:00:00.000Z' }, ledger.sealer);
    const report = verify(ledger.envelopes, undefined, [cp], ledger.keys);
    expect(failedChecks(report)).toEqual(['checkpoint']);
    expect(report.messages.join(' ')).toMatch(/do not match the sealer's latest checkpoint/);
  });

  it('a checkpoint with an invalid signature fails', () => {
    const ledger = ledgerWith(3);
    const forged = { ...ledger.checkpoints[0]!, count: 2 };
    const report = verify(ledger.envelopes, undefined, [forged], ledger.keys);
    expect(report.result).toBe('fail');
    expect(report.failedChecks).toContain('checkpoint');
    expect(report.messages.join(' ')).toMatch(/invalid sealer signature/);
  });

  it('a disclosure with a changed value fails the disclosures check', () => {
    const ledger = ledgerWith(2);
    const disclosures = clone(ledger.disclosures);
    disclosures[0]!.value = { params: { type: 'store_credit', customerId: 'cust-1', amountCents: 99 }, idempotencyKey: 'x' };
    const report = verify(ledger.envelopes, disclosures, ledger.checkpoints, ledger.keys);
    expect(failedChecks(report)).toEqual(['disclosures']);
    expect(report.receipts[0]!.messages).toContain('The disclosed instance details do not match the record.');
  });

  it('a disclosure for a field the record does not commit to fails', () => {
    const ledger = ledgerWith(1);
    const disclosures = [{ ...ledger.disclosures[0]!, field: 'target_ref' as const }];
    expect(failedChecks(verify(ledger.envelopes, disclosures, ledger.checkpoints, ledger.keys))).toEqual(['disclosures']);
  });

  it('a disclosure for a record that is not included is reported but does not fail', () => {
    const ledger = ledgerWith(1);
    const disclosures = [{ ...ledger.disclosures[0]!, receiptId: 'urn:uuid:other' }];
    const report = verify(ledger.envelopes, disclosures, ledger.checkpoints, ledger.keys);
    expect(report.result).toBe('pass');
    expect(report.messages.join(' ')).toMatch(/not included/);
  });

  it('wrong sealer keys fail the seal and checkpoint checks', () => {
    const ledger = ledgerWith(2);
    const keys = { ...ledger.keys, sealer: { keys: [toJwk({ kid: 'oar-test-sealer', privateKey: generatePrivateKey() })] } };
    const report = verify(ledger.envelopes, undefined, ledger.checkpoints, keys);
    expect(failedChecks(report)).toEqual(['checkpoint', 'seal']);
  });
});

describe('verify: partial sets (evidence packages)', () => {
  function evidence(ledger: Ledger, indexes: number[]): OarRecord[] {
    return indexes.map((i) => ledger.envelopes[i]!);
  }

  it('passes a non-contiguous subset, marking unverifiable links as not checked', () => {
    const ledger = ledgerWith(8);
    const report = check(ledger, evidence(ledger, [2, 3, 6]), { partial: true });
    expect(report.result).toBe('pass');
    expect(report.receipts.map((r) => r.checks.chain)).toEqual(['not_checked', 'pass', 'not_checked']);
    expect(report.receipts.every((r) => r.checks.checkpoint === 'pass')).toBe(true);
  });

  it('still fails a tampered record in a subset', () => {
    const ledger = ledgerWith(4);
    const subset = clone(evidence(ledger, [1, 2]));
    subset[1]!.payload.reasons = ['within_limits', 'edited'];
    const report = check(ledger, subset, { partial: true });
    expect(report.result).toBe('fail');
    expect(failedChecks(report)).toEqual(['checkpoint', 'issuer_signature', 'seal']);
  });

  it('a subset that omits the first record passes without the full set', () => {
    const ledger = ledgerWith(3);
    expect(check(ledger, evidence(ledger, [2]), { partial: true }).result).toBe('pass');
    expect(check(ledger, evidence(ledger, [2])).result).toBe('fail');
  });
});
