// Wrap an MCP server in one line: every tool call is checked by your rules, then recorded.
// Run: npx tsx examples/mcp-server.ts
import { writeFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createRecorder, generateSigningKey, summarize, verifyBundle } from '@openactionrecord/core';
import { withOar } from '@openactionrecord/mcp';

// A stand-in for a production database.
const tables = new Map([['customers', 1204], ['orders', 8312]]);

const recorder = createRecorder({ issuer: generateSigningKey('prod-db-2026'), org: 'acme', agent: 'ops-bot' });
const server = withOar(new McpServer({ name: 'prod-db', version: '1.0.0' }), {
  recorder,
  target: 'prod-db',
  tools: {
    run_sql: {
      // Reads run; anything destructive needs a person.
      check: ({ sql }) => (/^\s*(drop|delete|truncate)\b/i.test(String(sql)) ? { result: 'held', reasons: ['destructive_sql'] } : { result: 'allowed' }),
    },
  },
});

server.registerTool('run_sql', { inputSchema: { sql: z.string() } }, async ({ sql }) => {
  const drop = /^\s*drop table (\w+)/i.exec(sql);
  if (drop) tables.delete(drop[1]!);
  return { content: [{ type: 'text', text: `ok (${[...tables.keys()].join(', ')})` }] };
});

// An agent connects and calls the tools.
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
const agent = new Client({ name: 'ops-bot', version: '1.0.0' });
await Promise.all([server.connect(serverSide), agent.connect(clientSide)]);

for (const sql of ['SELECT count(*) FROM orders', 'DROP TABLE customers']) {
  const result = await agent.callTool({ name: 'run_sql', arguments: { sql } });
  console.log(`${sql}\n  -> ${(result.content as { text: string }[])[0]!.text}`);
}
console.log(`Tables now: ${[...tables.keys()].join(', ')}\n`);

const bundle = await recorder.bundle();
await writeFile('mcp-bundle.json', JSON.stringify(bundle, null, 2));
for (const a of summarize(bundle.records)) console.log(`${a.type}: ${a.outcomeText}`);
console.log(`\nVerification: ${verifyBundle(bundle).result}. Wrote mcp-bundle.json; check it with: npx @openactionrecord/cli verify mcp-bundle.json`);
