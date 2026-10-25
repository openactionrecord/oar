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

## API

| | |
|---|---|
| `createRecorder(options)` | One recorder per agent. Options: `issuer`, `org`, `agent`, optional `sealer`, `policy`, `policyId`, `run`. |
| `recorder.run(input)` | Check, optional approval, state before, execute, state after, confirm. Every step recorded. |
| `recorder.decide / approve / execute / confirm` | The same steps, one at a time. |
| `recorder.bundle({ disclose, actionId, purpose })` | A self-contained evidence bundle. Discloses nothing by default. |
| `createLocalSealer({ key })` | An in-process sealing service: seals, checkpoints and `anchor()` for an RFC 3161 timestamp (DigiCert's free service by default). Run it as a separate service for real separation (see `examples/sealer-server.ts`). |
| `verifyBundle(bundle, { keys, requireSeal, tsaRoots })` | The reference verifier. |
| `summarize(records, disclosures, report)` | Plain-language story and outcome of each action. |
| `@openactionrecord/core/standalone` | The independent WebCrypto verifier and an offline verification page generator. |
| `generateSigningKey(kid)`, `publicKeys(...)` | Keys, and the key set to publish at `/.well-known/aar-keys.json`. |

The format is specified in [SPEC.md](https://github.com/openactionrecord/oar/blob/main/SPEC.md). Apache-2.0.
