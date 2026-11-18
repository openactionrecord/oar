# @openactionrecord/mcp

Record every tool call on an [MCP](https://modelcontextprotocol.io) server as an [Open Action Record](https://github.com/openactionrecord/oar): the rule decision, the authorization the call relied on (checked again just before the tool runs), what it changed, and whether the system of record agrees. Records are signed, chained per agent, and verify offline.

```sh
npm install @openactionrecord/mcp @openactionrecord/core @modelcontextprotocol/sdk
```

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createRecorder, generateSigningKey } from '@openactionrecord/core';
import { recordTools } from '@openactionrecord/mcp';

const oar = createRecorder({ issuer: generateSigningKey('billing-mcp-2026'), org: 'acme', agent: 'billing-mcp' });
const server = new McpServer({ name: 'billing', version: '1.0.0' });

recordTools(server, oar, {
  target: 'billing',
  tools: {
    refund: { check: (a) => (a.cents > 125_000 ? { result: 'held', reasons: ['over_approval_limit'] } : { result: 'allowed' }) },
    lookup_order: { record: false }, // read-only, not recorded
  },
});

// Register tools as usual, after recordTools. The handlers don't change.
server.registerTool('refund', { inputSchema: { order: z.string(), cents: z.number() } }, refundHandler);

// Later: a bundle anyone can verify offline.
const bundle = await oar.bundle();
```

## What each call records

| Step | Record |
|---|---|
| Your rule allows, holds or denies the call | Decision, with reason codes. A denied or held call returns an error result to the agent, with the reason; the tool does not run. |
| The call relied on an access token | The token by digest (never in clear), with its expiry, as the decision's authority set. |
| Just before the tool runs | The authority set checked again. If the token was revoked or expired in between, the tool does not run and the action is recorded as **refused**. |
| The tool runs | Execution, with commitments to the state before and after if you give `readState`. A thrown error or an `isError` result is recorded as failed. |
| You give `confirm` | A confirmation read back from the system of record: **confirmed** or **not confirmed**. |

## Authorization

When the server uses MCP authorization, the caller's access token (`extra.authInfo`) is recorded by default. The default re-check only looks at the token's expiry. To detect revocation, pass `recheck` and call your authorization server's token introspection endpoint (RFC 7662):

```ts
recordTools(server, oar, {
  target: 'billing',
  issuer: 'https://auth.example.com',
  recheck: async (authorities, extra) => [(await introspect(extra.authInfo!.token)).active ? 'valid' : 'revoked'],
});
```

Pass `authorities` to record other artifacts the call relied on (a session, a payment mandate, an approval service's result), or return `[]` to record none. If the re-check throws, the call is refused (fail closed).

## Options

| Option | Meaning |
|---|---|
| `target` | The system the tools act on. |
| `tools` | Rules per tool name: `type`, `target`, `check`, `readState`, `targetRef`, `confirm`, `record: false`. |
| `defaults` | The rule for tools without an entry. |
| `authorities` | The artifacts a call relied on. Default: the caller's access token. |
| `recheck` | One status per authority, checked just before the tool runs. Default: expiry only. |
| `issuer` | The authorization server's identifier for the default authority. |

A held call stops at "held" and the agent is told it is waiting for a person. Approval flows for MCP tools are not built into this package yet.

Licensed Apache 2.0. Specification: [SPEC.md](https://github.com/openactionrecord/oar/blob/main/SPEC.md).
