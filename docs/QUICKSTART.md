# Quickstart: record your own agent in 5 minutes

Three ways in, from no setup to your own code:

| You want to | Do this | Needs |
|---|---|---|
| See it, no install | Open the [playground](https://openactionrecord.github.io/oar/), press a tamper button | A browser |
| See it run | `npx @openactionrecord/cli demo --database` | Node.js 20+ |
| Record your own agent | Steps 1–5 below | Node.js 22.13+ for the SQLite example (any Node.js 20+ for your own code) |

Nothing here needs an account or a server, and nothing is sent anywhere except one optional timestamp request (a hash only).

## 1. Install

```bash
mkdir oar-try && cd oar-try
npm init -y && npm pkg set type=module
npm install @openactionrecord/core
```

Python instead? `pip install open-action-record` gives the same recorder (`Recorder(...).run(...)`) and verifier; see [python/](../python).

## 2. Run the database example

Copy [`examples/quickstart-database.mjs`](../examples/quickstart-database.mjs) into the folder and run it:

```bash
node quickstart-database.mjs
```

It uses a real SQLite database (built into Node.js) and records four actions by an AI operations agent:

```text
A. cleanup: completed confirmed = true                  ← allowed, and the database confirms it
B. drop table: rejected | customers still there: 2       ← held for a person, who said no
C. delete all customers: denied                          ← blocked by the rules, never ran
D. update that never happened: confirmed = false         ← the tool said "done"; the read-back disagrees

PASS: All 9 records passed verification.
```

It writes `evidence.json`. Check it independently:

```bash
npx @openactionrecord/cli verify evidence.json --cross-check   # two verifiers
npx @openactionrecord/cli html evidence.json                    # a page that verifies it offline
```

## 3. Point it at your own system

Each action your agent takes goes through `oar.run()`. You supply five small functions; all can be async:

```js
await oar.run({
  type: 'delete_rows',                 // what kind of action
  target: 'postgres',                  // which system it changes
  params: { table: 'sessions' },       // its parameters (committed, never stored in clear)

  check: (params) => ({ result: 'allowed' }),     // your rules: 'allowed', 'held' (needs a person) or 'denied'
  approve: async (action) => ({ approver: 'maya', approved: true }),   // only asked when check says 'held'
  readState: () => readFromYourDatabase(),         // read before and after the change
  execute: () => doTheAction(),                    // the action itself; errors are recorded, then re-thrown
  confirm: () => readItBackAndCheck(),             // read the system of record again: did it really happen?
});
```

For Postgres, for example:

```js
readState: async () => (await db.query('select count(*)::int as expired from sessions where expires_at < now()')).rows[0],
execute:   () => db.query('delete from sessions where expires_at < now()'),
confirm:   async () => (await db.query('select count(*)::int as n from sessions where expires_at < now()')).rows[0].n === 0,
```

`approve` is where a person comes in: ask on Slack, by email or in your own dashboard, and return their answer. If you leave it out, a held action stops at `held` and never runs.

## 4. Wrap your agent's tools once

Wrap each tool that changes something (MCP tool handlers, OpenAI Agents SDK tools, LangChain tools), and every call is recorded. A denied or held call throws, so the agent sees the refusal. See [`examples/tool-wrapper.ts`](../examples/tool-wrapper.ts).

## 5. Keep and share the evidence

- `await oar.bundle()` discloses nothing in clear: it proves what happened without revealing parameters or state. Share it with an auditor, a customer or an insurer.
- `await oar.bundle({ disclose: 'all' })` includes the values, for your own debugging.
- Run a separate sealing service so the issuer can't rewrite its own history: [`examples/sealer-server.ts`](../examples/sealer-server.ts).
- `await sealer.anchor()` has an outside authority timestamp the records (DigiCert's free RFC 3161 service by default).
- Publish your public keys (`await oar.keys()`) and verify with `--keys` to rule out a substituted bundle.

## What it checks, and what it doesn't

A verified bundle proves the records weren't changed, removed or reordered after signing, who approved each held action, and whether the system of record confirmed the outcome. It can't prove that the functions you supplied tell the truth: `confirm` is only as good as the read-back you write. Make it read the real system of record, not the agent's own report.

Questions or something unclear? [Open an issue](https://github.com/openactionrecord/oar/issues/1).
