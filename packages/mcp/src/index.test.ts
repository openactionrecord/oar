import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createRecorder, generateSigningKey, summarize, verifyBundle } from '@openactionrecord/core';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { recordTools } from './index.js';

async function setup(options: Partial<Parameters<typeof recordTools>[2]> = {}) {
  const oar = createRecorder({ issuer: generateSigningKey('mcp-test'), org: 'acme', agent: 'billing-mcp' });
  const server = new McpServer({ name: 'billing', version: '1.0.0' });
  const balances = new Map<string, number>([['c-1', 0]]);
  recordTools(server, oar, {
    target: 'billing',
    tools: {
      issue_credit: {
        check: (a) => ((a.cents as number) > 10_000 ? { result: 'denied', reasons: ['over_maximum'] } : { result: 'allowed' }),
        readState: (a) => ({ balance: balances.get(a.customer as string) ?? 0 }),
        confirm: (a) => (balances.get(a.customer as string) ?? 0) > 0,
      },
      lookup: { record: false },
    },
    ...options,
  });
  server.registerTool('issue_credit', { inputSchema: { customer: z.string(), cents: z.number() } }, async ({ customer, cents }) => {
    balances.set(customer, (balances.get(customer) ?? 0) + cents);
    return { content: [{ type: 'text', text: 'ok' }] };
  });
  server.registerTool('lookup', { inputSchema: { customer: z.string() } }, async ({ customer }) => ({ content: [{ type: 'text', text: String(balances.get(customer)) }] }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'agent', version: '1.0.0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { oar, client, balances };
}

describe('recordTools', () => {
  it('records an allowed call with its outcome, and the bundle verifies', async () => {
    const { oar, client } = await setup();
    const res = await client.callTool({ name: 'issue_credit', arguments: { customer: 'c-1', cents: 2_500 } });
    expect(res.isError).toBeFalsy();
    const [action] = summarize(oar.records);
    expect(action?.outcome).toBe('confirmed');
    expect(verifyBundle(await oar.bundle()).result).toBe('pass');
  });

  it('blocks a denied call before the tool runs, and tells the agent why', async () => {
    const { oar, client, balances } = await setup();
    const res = await client.callTool({ name: 'issue_credit', arguments: { customer: 'c-1', cents: 50_000 } });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain('over_maximum');
    expect(balances.get('c-1')).toBe(0);
    expect(summarize(oar.records)[0]?.outcome).toBe('denied');
  });

  it('leaves tools marked record: false unrecorded', async () => {
    const { oar, client } = await setup();
    await client.callTool({ name: 'lookup', arguments: { customer: 'c-1' } });
    expect(oar.records).toHaveLength(0);
  });

  it('refuses a call whose authority was revoked before it committed', async () => {
    const { oar, client, balances } = await setup({
      authorities: () => [{ type: 'oauth-access-token', issuer: 'https://auth.example', artifact: 'token-123' }],
      recheck: () => ['revoked'],
    });
    const res = await client.callTool({ name: 'issue_credit', arguments: { customer: 'c-1', cents: 100 } });
    expect(res.isError).toBe(true);
    expect(balances.get('c-1')).toBe(0);
    expect(summarize(oar.records)[0]?.outcome).toBe('refused');
    expect(verifyBundle(await oar.bundle()).result).toBe('pass');
  });

  it('records the authority and the re-check when it is still valid', async () => {
    const { oar, client } = await setup({
      authorities: () => [{ type: 'oauth-access-token', issuer: 'https://auth.example', artifact: 'token-123', expiresAt: '2099-01-01T00:00:00Z' }],
    });
    await client.callTool({ name: 'issue_credit', arguments: { customer: 'c-1', cents: 100 } });
    const exec = oar.records.find((r) => r.payload.phase === 'execution');
    expect(exec?.payload.authority_check?.result).toBe('current');
    expect(verifyBundle(await oar.bundle()).result).toBe('pass');
  });
});
