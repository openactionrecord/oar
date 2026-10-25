import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createRecorder, generateSigningKey, summarize, verifyBundle } from '@openactionrecord/core';
import { ACTION_ID_META, withOar, type WithOarOptions } from './index.js';

async function setup(options: Omit<WithOarOptions, 'recorder' | 'target'> = {}) {
  const recorder = createRecorder({ issuer: generateSigningKey('mcp-test-1'), org: 'acme', agent: 'ops-bot' });
  const rows = new Map<string, number>([['orders', 8312]]);
  const calls: string[] = [];
  const server = withOar(new McpServer({ name: 'prod-db', version: '1.0.0' }), { recorder, target: 'prod-db', ...options });
  server.registerTool('run_sql', { inputSchema: { sql: z.string() } }, async ({ sql }) => {
    calls.push(sql);
    if (sql.startsWith('DROP')) rows.clear();
    return { content: [{ type: 'text', text: `ok: ${rows.size} tables` }] };
  });
  server.registerTool('list_tables', { description: 'No arguments' }, async () => {
    calls.push('list');
    return { content: [{ type: 'text', text: [...rows.keys()].join(',') }] };
  });
  server.registerTool('broken', { inputSchema: { x: z.number() } }, async () => ({ content: [{ type: 'text', text: 'no' }], isError: true }));

  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '1.0.0' });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  return { recorder, client, calls, rows };
}

const text = (result: unknown) => ((result as { content: { text: string }[] }).content[0]!.text);

describe('withOar', () => {
  it('records an allowed call with its outcome, and the bundle verifies', async () => {
    const { recorder, client, calls } = await setup();
    const result = await client.callTool({ name: 'run_sql', arguments: { sql: 'SELECT count(*) FROM orders' } });
    expect(text(result)).toBe('ok: 1 tables');
    expect(calls).toEqual(['SELECT count(*) FROM orders']);
    expect(result._meta?.[ACTION_ID_META]).toBe(recorder.records[0]!.payload.receipt_id);

    const bundle = await recorder.bundle();
    expect(verifyBundle(bundle).result).toBe('pass');
    expect(JSON.stringify(bundle)).not.toContain('SELECT');
    expect(summarize(bundle.records)[0]).toMatchObject({ type: 'run_sql', target: 'prod-db', outcome: 'executed_unconfirmed' });
  });

  it('records tools without arguments', async () => {
    const { recorder, client } = await setup();
    expect(text(await client.callTool({ name: 'list_tables', arguments: {} }))).toBe('orders');
    expect(recorder.records.map((r) => r.payload.phase)).toEqual(['decision', 'execution']);
  });

  it('a denied call never reaches the tool, and the client is told why', async () => {
    const { recorder, client, calls, rows } = await setup({
      tools: { run_sql: { check: (a) => (/^DROP/i.test(String(a.sql)) ? { result: 'denied', reasons: ['destructive_sql'] } : { result: 'allowed' }) } },
    });
    const result = await client.callTool({ name: 'run_sql', arguments: { sql: 'DROP TABLE orders' } });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/^DENIED/);
    expect(calls).toEqual([]);
    expect(rows.size).toBe(1);
    expect(recorder.records).toHaveLength(1);
    expect(recorder.records[0]!.payload).toMatchObject({ result: 'denied', reasons: ['destructive_sql'] });
  });

  it('a held call waits for a person: refused without an approver, run once approved', async () => {
    const held = { check: () => ({ result: 'held' as const }) };
    const first = await setup({ check: () => ({ result: 'allowed' }), tools: { run_sql: held } });
    const refused = await first.client.callTool({ name: 'run_sql', arguments: { sql: 'DROP TABLE orders' } });
    expect(text(refused)).toMatch(/^HELD/);
    expect(first.calls).toEqual([]);

    const second = await setup({ tools: { run_sql: held }, approve: () => ({ approver: 'jordan' }) });
    await second.client.callTool({ name: 'run_sql', arguments: { sql: 'VACUUM' } });
    expect(second.calls).toEqual(['VACUUM']);
    expect(summarize(second.recorder.records)[0]).toMatchObject({ approvedBy: 'jordan' });
  });

  it('a tool that reports an error is recorded as failed, and its result is returned unchanged', async () => {
    const { recorder, client } = await setup();
    const result = await client.callTool({ name: 'broken', arguments: { x: 1 } });
    expect(result.isError).toBe(true);
    expect(text(result)).toBe('no');
    expect(recorder.records.at(-1)!.payload.result).toBe('failed');
    expect(result._meta?.[ACTION_ID_META]).toBe(recorder.records[0]!.payload.receipt_id);
  });

  it('a confirmation that does not find the change shows NOT confirmed', async () => {
    const { recorder, client } = await setup({ tools: { run_sql: { confirm: () => false } } });
    await client.callTool({ name: 'run_sql', arguments: { sql: 'DELETE FROM orders WHERE id = 1' } });
    expect(summarize(recorder.records)[0]!.outcome).toBe('not_confirmed');
  });

  it('records only the listed tools when asked', async () => {
    const { recorder, client, calls } = await setup({ record: 'listed', tools: { run_sql: {} } });
    await client.callTool({ name: 'list_tables', arguments: {} });
    expect(calls).toEqual(['list']);
    expect(recorder.records).toHaveLength(0);
  });
});
