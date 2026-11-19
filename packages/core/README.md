# @openactionrecord/core

Write and verify [Open Action Records](https://github.com/openactionrecord/oar): signed proof of what an AI agent's action actually changed, and who approved it.

```bash
npm install @openactionrecord/core
```

```ts
import { createRecorder, generateSigningKey, verifyBundle, summarize } from '@openactionrecord/core';

const oar = createRecorder({ issuer: generateSigningKey('my-agent-2026'), org: 'acme', agent: 'support-bot' });

await oar.run({
  type: 'refund',
  target: 'stripe',
  params: { order: '1142', amountCents: 190_000 },
  check: (p) => (Number(p.amountCents) > 125_000 ? { result: 'held' } : { result: 'allowed' }),
  approve: async () => ({ approver: 'jordan', approved: true }),
  readState: () => getOrderState('1142'),
  execute: () => refund('1142', 190_000),
  targetRef: (r) => r.id,
  confirm: async (r) => await refundExists(r.id),
});

const bundle = await oar.bundle();            // { disclose: 'all' } to include values, for your own debugging
const report = verifyBundle(bundle);          // report.result, report.level, per-record checks
summarize(bundle.records, bundle.disclosures, report);   // each action's story and outcome
```

## Authority re-checked at commit

If an action relies on something from outside your system (a delegated token, an OAuth grant, a session, an approval service's result), record it by digest on the decision, and check it again just before the action runs. If it was revoked or expired in between, the action doesn't run and is recorded as **refused**.

```ts
const action = await oar.decide({
  type: 'payout', target: 'payments', params: { payee: 'P-2077', amountCents: 980_000 }, result: 'allowed',
  authorities: [{ type: 'aauth', issuer: 'https://auth.example', artifact: token, expiresAt }],
});
// ... just before the money moves:
await oar.execute(action, { authorityCheck: { statuses: [await introspect(token)] } });   // 'valid' runs; 'revoked' → refused
```

Every action is also reported in one of three outcome classes: **committed** (the change happened and is confirmed), **refused** (it did not run, and the records say why) or **unresolved**.

## Approval bound to the exact action

`recorder.requestApproval(action, { display })` returns the value the approver's passkey signs, or that an outside service (a bank app, a SIM check) confirms. It is bound to this one action and to what the approver was shown, so it cannot be reused for another amount or payee. Pass the outside service's proof as `evidence` to `recorder.approve()`.

## API

| | |
|---|---|
| `createRecorder(options)` | One recorder per agent. Options: `issuer`, `org`, `agent`, optional `sealer`, `policy`, `policyId`, `run`. |
| `recorder.run(input)` | Check, optional approval, state before, execute, state after, confirm. Every step recorded. |
| `recorder.decide / approve / execute / confirm` | The same steps, one at a time. `decide` takes `authorities`; `execute` takes `authorityCheck`. |
| `recorder.requestApproval(action, { display })` | The approval binding for a passkey challenge or an outside approval service. |
| `recorder.bundle({ disclose, actionId, purpose })` | A self-contained evidence bundle. Discloses nothing by default. |
| `createLocalSealer({ key })` | An in-process sealing service: seals, checkpoints and `anchor()` for an RFC 3161 timestamp (DigiCert's free service by default). Run it as a separate service for real separation (see `examples/sealer-server.ts`). |
| `verifyBundle(bundle, { keys, requireSeal, tsaRoots })` | The reference verifier. |
| `summarize(records, disclosures, report)` | Plain-language story, outcome and outcome class (`committed`, `refused`, `unresolved`) of each action. |
| `checkApproval`, `checkAuthority` | The approval binding and authority checks (checks 7 and 8), on one record. |
| `@openactionrecord/core/standalone` | The independent WebCrypto verifier and an offline verification page generator. |
| `generateSigningKey(kid)`, `publicKeys(...)` | Keys, and the key set to publish at `/.well-known/aar-keys.json`. |

For MCP servers, [`@openactionrecord/mcp`](https://www.npmjs.com/package/@openactionrecord/mcp) records every tool call in one line.

The format is specified in [SPEC.md](https://github.com/openactionrecord/oar/blob/main/SPEC.md). Apache-2.0.
