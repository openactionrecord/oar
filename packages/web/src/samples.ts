import { createHash } from 'node:crypto';
import { createLocalSealer, createRecorder, type Bundle, type SigningKey } from '@openactionrecord/core';

// Sample bundles for the playground. Fixed keys and randomness, so the page builds the same every time.
// SAMPLE KEYS ONLY.

const ISSUER: SigningKey = { kid: 'example-store-agent', privateKey: '33'.repeat(32) };
const SEALER: SigningKey = { kid: 'example-sealing-service', privateKey: '44'.repeat(32) };

const DB_ISSUER: SigningKey = { kid: 'example-ops-agent', privateKey: '55'.repeat(32) };

export async function sampleBundles(): Promise<{ database: Bundle; valid: Bundle; issuerSigned: Bundle }> {
  return { database: await databaseStory(), valid: await story(true), issuerSigned: await story(false) };
}

/** The `oar demo --database` story: an AI operations agent on a production database. */
async function databaseStory(): Promise<Bundle> {
  let t = Date.parse('2026-11-02T09:00:00.000Z');
  let n = 0;
  const h = (s: string) => createHash('sha256').update(s).digest('hex');
  const now = () => new Date((t += 1_500));
  const sealer = createLocalSealer({ key: SEALER, now });
  const oar = createRecorder({
    issuer: DB_ISSUER,
    org: 'example-co',
    orgName: 'Example Co',
    agent: 'ops-agent',
    run: 'run:sample-database',
    policyId: 'database-rules-v2',
    policy: { destructiveChangesNeedApproval: true, backupDeletion: 'never' },
    sealer,
    now,
    randomId: () => {
      const x = h(`sample:db:id:${++n}`);
      return `${x.slice(0, 8)}-${x.slice(8, 12)}-4${x.slice(13, 16)}-8${x.slice(17, 20)}-${x.slice(20, 32)}`;
    },
    randomSalt: () => h(`sample:db:salt:${++n}`),
  });

  const sessions = { table: 'sessions', rows: 5_000, expired: 120 };
  await oar.run({
    type: 'delete_rows',
    target: 'database',
    params: { table: 'sessions', where: 'expired', rows: 120 },
    idempotencyKey: 'cleanup-sessions',
    check: () => ({ result: 'allowed', reasons: ['routine_cleanup'] }),
    readState: () => ({ ...sessions }),
    execute: () => {
      sessions.rows -= 120;
      sessions.expired = 0;
      return { deleted: 120 };
    },
    confirm: () => sessions.expired === 0,
  });
  await oar.run({
    type: 'drop_table',
    target: 'database',
    params: { table: 'customers' },
    idempotencyKey: 'drop-customers',
    check: () => ({ result: 'held', reasons: ['destructive_change'] }),
    approve: () => ({ approver: 'maya', approved: false }),
    readState: () => ({ table: 'customers', rows: 48_210 }),
    execute: () => 'never runs',
  });
  await oar.run({
    type: 'delete_backups',
    target: 'database',
    params: { scope: 'all' },
    idempotencyKey: 'delete-backups',
    check: () => ({ result: 'denied', reasons: ['no_rule_allows_backup_deletion'] }),
    execute: () => 'never runs',
  });
  const schema = { table: 'customers', columns: ['created_at', 'email', 'id'] };
  await oar.run({
    type: 'run_migration',
    target: 'database',
    params: { migration: '2026_11_add_loyalty_tier' },
    idempotencyKey: 'migration-loyalty-tier',
    check: () => ({ result: 'allowed', reasons: ['approved_migration'] }),
    readState: () => ({ ...schema, columns: [...schema.columns] }),
    execute: () => ({ migration: '2026_11_add_loyalty_tier', status: 'applied' }), // "applied", but the column never appears
    targetRef: (r) => r.migration,
    confirm: () => schema.columns.includes('loyalty_tier'),
  });
  return oar.bundle({ disclose: 'all', purpose: 'debugging' });
}

async function story(sealed: boolean): Promise<Bundle> {
  let t = Date.parse('2026-10-25T14:00:00.000Z');
  let n = 0;
  const h = (s: string) => createHash('sha256').update(s).digest('hex');
  const now = () => new Date((t += 1_500));
  const sealer = sealed ? createLocalSealer({ key: SEALER, now }) : undefined;
  const oar = createRecorder({
    issuer: ISSUER,
    org: 'example-store',
    orgName: 'Example Store',
    agent: 'support-agent',
    run: 'run:sample',
    policyId: 'store-rules-v3',
    policy: { refundApprovalAboveCents: 125_000, maxDiscountPercent: 20 },
    ...(sealer ? { sealer } : {}),
    now,
    randomId: () => {
      const x = h(`sample:${sealed}:id:${++n}`);
      return `${x.slice(0, 8)}-${x.slice(8, 12)}-4${x.slice(13, 16)}-8${x.slice(17, 20)}-${x.slice(20, 32)}`;
    },
    randomSalt: () => h(`sample:${sealed}:salt:${++n}`),
  });

  const orders: Record<string, { order: string; totalCents: number; refundedCents: number }> = {
    '1142': { order: '1142', totalCents: 190_000, refundedCents: 0 },
    '1187': { order: '1187', totalCents: 4_500, refundedCents: 0 },
  };
  await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1142', amountCents: 190_000 },
    idempotencyKey: 'refund-1142',
    check: () => ({ result: 'held', reasons: ['over_approval_limit'] }),
    approve: () => ({ approver: 'jordan', approved: true }),
    readState: () => ({ ...orders['1142']! }),
    execute: () => {
      orders['1142']!.refundedCents += 190_000;
      return { id: 're_0001' };
    },
    targetRef: (r) => r.id,
    confirm: () => true,
  });
  await oar.run({
    type: 'discount_code',
    target: 'store',
    params: { percent: 80 },
    idempotencyKey: 'discount-80',
    check: () => ({ result: 'denied', reasons: ['over_maximum_discount'] }),
    execute: () => 'never runs',
  });
  await oar.run({
    type: 'refund',
    target: 'payments',
    params: { order: '1187', amountCents: 4_500 },
    idempotencyKey: 'refund-1187',
    readState: () => ({ ...orders['1187']! }),
    execute: () => ({ id: 're_0002' }), // the payment API says "succeeded", but nothing was refunded
    targetRef: (r) => r.id,
    confirm: () => false,
  });
  return oar.bundle({ disclose: 'all', purpose: 'debugging' });
}
