# @openactionrecord/mcp

Record every tool call of an MCP server as [Open Action Records](../../README.md), with your rules checked **before**
the tool runs.

```bash
npm install @openactionrecord/core @openactionrecord/mcp @modelcontextprotocol/sdk
```

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createRecorder, generateSigningKey } from '@openactionrecord/core';
import { withOar } from '@openactionrecord/mcp';
import { z } from 'zod';

const recorder = createRecorder({ issuer: generateSigningKey('prod-db-2026'), org: 'acme', agent: 'ops-bot' });

// One line: every tool registered afterwards is recorded.
const server = withOar(new McpServer({ name: 'prod-db', version: '1.0.0' }), {
  recorder,
  target: 'prod-db',
  tools: {
    run_sql: {
      check: ({ sql }) => (/^\s*(drop|delete|truncate)/i.test(String(sql)) ? { result: 'held', reasons: ['destructive_sql'] } : { result: 'allowed' }),
    },
  },
});

server.registerTool('run_sql', { inputSchema: { sql: z.string() } }, async ({ sql }) => runSql(sql));

// Later: a bundle anyone can verify offline (npx @openactionrecord/cli verify bundle.json).
const bundle = await recorder.bundle();
```

What happens to a call:

| Your rules say | The tool | The client gets | Recorded |
|---|---|---|---|
| allowed (default) | runs | the tool's own result, with `_meta["oar/action_id"]` | decision, execution (and confirmation, with `confirm`) |
| denied | does not run | a tool error starting `DENIED:` | the decision |
| held | runs only if `approve` approves it | the result, or a tool error starting `HELD:` / `REJECTED:` | the decision and the approval |

A result with `isError: true` is recorded as a failed execution and returned unchanged.

## Options

`withOar(server, options)`:

- `recorder`: from `createRecorder` in `@openactionrecord/core`.
- `target`: the system the tools act on ("prod-db", "shop"). Never personal data.
- `tools`: per-tool `type`, `target`, `check`, `readState` (state before and after, committed), `targetRef` and
  `confirm` (read the system of record back; an action that didn't happen shows as NOT confirmed).
- `record`: `"all"` (default) or `"listed"` (only the tools in `tools`).
- `check(tool, args)`: rules applied to every recorded tool, before its own `check`.
- `approve(action, tool, args)`: asked when a call is held; return `{ approver: 'jordan' }`, or `approved: false`.

Arguments, state and results are never written in clear: each record carries salted commitments, and the recorder
keeps the salts (`recorder.disclosures`) so you can disclose a value later to the people who need it.

`withOar` wraps `registerTool`. Tools registered with the older `server.tool(...)` are not recorded.
