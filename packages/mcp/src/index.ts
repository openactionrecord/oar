// @openactionrecord/mcp: record every tool call of an MCP server as Open Action Records.
//
//   const server = withOar(new McpServer({ name: 'shop', version: '1.0.0' }), { recorder, target: 'shop' });
//   server.registerTool('refund', { inputSchema: { orderId: z.string(), cents: z.number() } }, handler);
//
// Each call is checked by your rules before the tool runs. Allowed calls run and are recorded with their outcome;
// denied or held calls never reach the handler, and the client gets a tool error that says why. Arguments are
// committed, never written in clear.
import type { ActionHandle, ApproveInput, Recorder, RuleResult } from '@openactionrecord/core';

/** The part of an MCP tool result this package reads and extends (`CallToolResult` in the MCP SDK). */
export interface ToolResult {
  content?: unknown[];
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

type Args = Record<string, unknown>;
type Handler = (...args: never[]) => ToolResult | Promise<ToolResult>;

/** Anything with the MCP SDK's `registerTool(name, config, handler)`, such as `McpServer`. */
export interface ToolRegistrar {
  registerTool(name: string, config: { inputSchema?: unknown; [key: string]: unknown }, handler: Handler): unknown;
}

export interface ToolOptions {
  /** The action type in the record. Default: the tool's name. */
  type?: string;
  /** The system the tool acts on. Default: the `target` given to `withOar`. */
  target?: string;
  /** Your rules for this tool. Return "held" to require a person's approval, "denied" to block. */
  check?: (args: Args) => RuleResult | Promise<RuleResult>;
  /** Reads the affected state; called before and after the tool runs. */
  readState?: (args: Args) => unknown | Promise<unknown>;
  /** The identifier of what changed, from the tool's result. */
  targetRef?: (result: ToolResult) => string | undefined;
  /** Reads the system of record again and says whether it shows the change. */
  confirm?: (args: Args, result: ToolResult) => boolean | Promise<boolean>;
}

export interface WithOarOptions {
  recorder: Recorder;
  /** The system the server's tools act on, for example "shop" or "prod-db". Never personal data. */
  target: string;
  /** Per-tool options, by tool name. */
  tools?: Record<string, ToolOptions>;
  /** "all" (default) records every tool; "listed" records only the tools in `tools`. */
  record?: 'all' | 'listed';
  /** Rules applied to every recorded tool, before its own `check`. */
  check?: (tool: string, args: Args) => RuleResult | Promise<RuleResult>;
  /** Asked when a call is held. Without it, a held call is refused with "needs approval". */
  approve?: (action: ActionHandle, tool: string, args: Args) => ApproveInput | Promise<ApproveInput>;
}

/** The `_meta` key that carries the action's identifier on every recorded tool result. */
export const ACTION_ID_META = 'oar/action_id';

/** Wraps `server.registerTool` so every tool registered afterwards is recorded. Returns the same server. */
export function withOar<S extends ToolRegistrar>(server: S, options: WithOarOptions): S {
  const register = server.registerTool.bind(server);
  server.registerTool = (name, config, handler) => {
    const how = options.tools?.[name];
    if (options.record === 'listed' && !how) return register(name, config, handler);
    const takesArgs = config.inputSchema !== undefined;
    const wrapped = (async (...callArgs: unknown[]) => {
      const args = (takesArgs ? callArgs[0] : {}) as Args;
      return recordCall(options, name, how ?? {}, args, () => (handler as (...a: unknown[]) => ToolResult | Promise<ToolResult>)(...callArgs));
    }) as Handler;
    return register(name, config, wrapped);
  };
  return server;
}

class ToolReportedError extends Error {
  constructor(readonly result: ToolResult) {
    super('The tool reported an error.');
  }
}

async function recordCall(options: WithOarOptions, tool: string, how: ToolOptions, args: Args, call: () => ToolResult | Promise<ToolResult>): Promise<ToolResult> {
  try {
    const out = await options.recorder.run<ToolResult>({
      type: how.type ?? tool,
      target: how.target ?? options.target,
      params: args,
      check: () => decide(options, tool, how, args),
      ...(options.approve ? { approve: (action: ActionHandle) => options.approve!(action, tool, args) } : {}),
      ...(how.readState ? { readState: () => how.readState!(args) } : {}),
      // A result with isError is recorded as a failed execution, then returned to the client unchanged.
      execute: async () => {
        const result = await call();
        if (result?.isError) throw new ToolReportedError(result);
        return result;
      },
      ...(how.targetRef ? { targetRef: how.targetRef } : {}),
      ...(how.confirm ? { confirm: (result: ToolResult) => how.confirm!(args, result) } : {}),
    });
    if (out.status !== 'completed') return refusal(out.status, out.action);
    return withActionId(out.result!, out.action.id);
  } catch (error) {
    if (error instanceof ToolReportedError) {
      const id = options.recorder.records.at(-1)?.payload.decision_ref;
      return withActionId(error.result, actionIdOf(options.recorder, id));
    }
    throw error;
  }
}

async function decide(options: WithOarOptions, tool: string, how: ToolOptions, args: Args): Promise<RuleResult> {
  const first = options.check ? await options.check(tool, args) : { result: 'allowed' as const };
  if (first.result !== 'allowed' || !how.check) return first;
  return how.check(args);
}

function refusal(status: 'denied' | 'held' | 'rejected', action: ActionHandle): ToolResult {
  const text = {
    denied: 'DENIED: the rules do not allow this call, so the tool did not run.',
    held: 'HELD: this call needs a person to approve it, so the tool did not run.',
    rejected: 'REJECTED: a person rejected this call, so the tool did not run.',
  }[status];
  return { content: [{ type: 'text', text }], isError: true, _meta: { [ACTION_ID_META]: action.id } };
}

function withActionId(result: ToolResult, id: string | undefined): ToolResult {
  if (!id) return result;
  return { ...result, _meta: { ...result._meta, [ACTION_ID_META]: id } };
}

/** The action a record belongs to: its decision record's id. */
function actionIdOf(recorder: Recorder, recordId: string | undefined): string | undefined {
  let id = recordId;
  for (let guard = 0; id && guard < 10; guard++) {
    const record = recorder.records.find((r) => r.payload.receipt_id === id);
    if (!record?.payload.decision_ref) return id;
    id = record.payload.decision_ref;
  }
  return id;
}
