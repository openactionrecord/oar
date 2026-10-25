// Test-only helper: simulates an issuer and a sealing service to build realistic, valid record sets.
import { commit } from '../crypto/commitment.js';
import { generatePrivateKey, toJwk, type Jwks, type SigningKey } from '../crypto/keys.js';
import {
  OAR_VERSION,
  createSeal,
  recordHash,
  nextLogHead,
  payloadHash,
  signCheckpoint,
  signRecord,
  type OarRecord,
  type Payload,
  type SignedCheckpoint,
} from '../record.js';
import type { DisclosureInput } from '../verify.js';

export interface Ledger {
  issuer: SigningKey;
  sealer: SigningKey;
  keys: { issuer: Jwks; sealer: Jwks };
  envelopes: OarRecord[];
  disclosures: DisclosureInput[];
  checkpoints: SignedCheckpoint[];
  /** Issues, signs, chains and seals one receipt for `agentId`. */
  issue(agentId: string, overrides?: Partial<Payload>): OarRecord;
  /** Signs a checkpoint over everything sealed so far. */
  checkpoint(): SignedCheckpoint;
}

export function createLedger(): Ledger {
  const issuer: SigningKey = { kid: 'oar-test-issuer', privateKey: generatePrivateKey() };
  const sealer: SigningKey = { kid: 'oar-test-sealer', privateKey: generatePrivateKey() };
  const lastByAgent = new Map<string, OarRecord>();
  let seq = 0;
  let head: string | null = null;
  let clock = Date.parse('2026-10-15T14:00:00.000Z');

  const ledger: Ledger = {
    issuer,
    sealer,
    keys: { issuer: { keys: [toJwk(issuer)] }, sealer: { keys: [toJwk(sealer)] } },
    envelopes: [],
    disclosures: [],
    checkpoints: [],

    issue(agentId, overrides = {}) {
      const receiptId = `urn:uuid:${crypto.randomUUID()}`;
      const instanceValue = { params: { type: 'store_credit', customerId: 'cust-1', amountCents: 2_500 }, idempotencyKey: receiptId };
      const instance = commit(instanceValue);
      const consumptionValue = { dailyMoneyUsedBeforeCents: 0, dailyMoneyUsedAfterCents: 2_500, dailyMoneyLimitCents: 100_000 };
      const consumption = commit(consumptionValue);
      const prev = lastByAgent.get(agentId);
      const issuedAt = new Date((clock += 1_000)).toISOString();

      const payload: Payload = {
        aar_version: OAR_VERSION,
        receipt_id: receiptId,
        phase: 'decision',
        org_id: 'org-1',
        agent_id: agentId,
        run_id: 'run:1',
        action: { type: 'store_credit', target: 'store.credits' },
        instance_commitment: instance.commitment,
        authorization_ref: 'sha256:' + '0'.repeat(64),
        principal: 'policy:policy-1',
        approval: { method: 'standing_mandate', at: issuedAt },
        consumption_commitment: consumption.commitment,
        result: 'allowed',
        reasons: ['within_limits'],
        enforced: true,
        issued_at: issuedAt,
        ...(prev ? { prev_receipt_hash: recordHash(prev) } : {}),
        ...overrides,
      };

      const signed = signRecord(payload, issuer);
      seq += 1;
      const digest = payloadHash(payload);
      const sealedAt = new Date(clock + 10).toISOString();
      const envelope: OarRecord = { ...signed, seal: createSeal(digest, seq, sealedAt, sealer) };
      head = nextLogHead(head, { seq, digest, sealed_at: sealedAt });

      ledger.envelopes.push(envelope);
      ledger.disclosures.push(
        { receiptId, field: 'instance', salt: instance.salt, value: instanceValue },
        { receiptId, field: 'consumption', salt: consumption.salt, value: consumptionValue },
      );
      lastByAgent.set(agentId, envelope);
      return envelope;
    },

    checkpoint() {
      if (head === null) throw new Error('Nothing sealed yet');
      const cp = signCheckpoint({ count: seq, head_digest: head, at: new Date(clock + 20).toISOString() }, sealer);
      ledger.checkpoints.push(cp);
      return cp;
    },
  };
  return ledger;
}
