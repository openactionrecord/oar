// The pattern for any tool layer (an MCP server's tool handlers, OpenAI Agents SDK tools, LangChain tools):
// wrap each consequential tool once, and every call is recorded with its rule check and outcome.
// Run: npx tsx examples/tool-wrapper.ts
import { createRecorder, generateSigningKey, summarize, type Recorder, type RuleResult } from '@openactionrecord/core';

type Tool<A extends Record<string, unknown>, R> = (args: A) => Promise<R>;

interface Recorded<A, R> {
  type: string;
  target: string;
  check?: (args: A) => RuleResult;
  readState?: (args: A) => unknown | Promise<unknown>;
  targetRef?: (result: R) => string | undefined;
  confirm?: (args: A, result: R) => boolean | Promise<boolean>;
}

/** Returns the same tool, recorded. Denied calls throw, so the agent sees the refusal. */
export function recorded<A extends Record<string, unknown>, R>(oar: Recorder, tool: Tool<A, R>, how: Recorded<A, R>): Tool<A, R> {
  return async (args) => {
    const out = await oar.run({
      type: how.type,
      target: how.target,
      params: args,
      ...(how.check ? { check: () => how.check!(args) } : {}),
      ...(how.readState ? { readState: () => how.readState!(args) } : {}),
      execute: () => tool(args),
      ...(how.targetRef ? { targetRef: how.targetRef } : {}),
      ...(how.confirm ? { confirm: (r: R) => how.confirm!(args, r) } : {}),
    });
    if (out.status === 'denied') throw new Error(`${how.type} blocked by the rules.`);
    if (out.status === 'held') throw new Error(`${how.type} is waiting for a person to approve it.`);
    if (out.status === 'rejected') throw new Error(`${how.type} was rejected by a person.`);
    return out.result as R;
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const credits = new Map<string, number>();
  const oar = createRecorder({ issuer: generateSigningKey('my-agent-2026'), org: 'acme', agent: 'support-bot' });

  // Your existing tool, unchanged.
  const issueCredit = async ({ customer, cents }: { customer: string; cents: number }) => {
    credits.set(customer, (credits.get(customer) ?? 0) + cents);
    return { ok: true };
  };

  // Recorded, with a rule and a read-back.
  const tool = recorded(oar, issueCredit, {
    type: 'store_credit',
    target: 'store',
    check: (a) => (a.cents > 10_000 ? { result: 'denied', reasons: ['over_max_per_credit'] } : { result: 'allowed' }),
    readState: (a) => ({ balance: credits.get(a.customer) ?? 0 }),
    confirm: (a) => (credits.get(a.customer) ?? 0) > 0,
  });

  await tool({ customer: 'c-1', cents: 2_500 });
  await tool({ customer: 'c-1', cents: 50_000 }).catch((e: Error) => console.log(e.message));
  for (const a of summarize(oar.records)) console.log(`${a.type}: ${a.outcomeText}`);
}
