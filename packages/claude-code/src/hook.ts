// The hook: one call per Claude Code PreToolUse / PostToolUse / PostToolUseFailure event.
//
// PreToolUse checks the call against `.oar/rules.json` and records the decision:
//   allow -> exit 0, the call runs;
//   hold  -> asks the person in Claude Code's permission prompt; if they allow it, the approval is recorded;
//   deny  -> exit 2 with the reason, which blocks the call and tells Claude why.
// PostToolUse records the execution, with a commitment to the tool's response (never the response itself).
//
// If the hook cannot check or record a call, it blocks it (exit 2) unless `failClosed` is false in `.oar/config.json`.
import { canonicalDigest, createRecorder, type ActionHandle, type Recorder } from '@openactionrecord/core';
import { check, parseRules } from './rules.js';
import { sessionFile, signingKey, Store, type Config } from './store.js';

export interface HookInput {
  hook_event_name?: string;
  session_id?: string;
  cwd?: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  tool_use_id?: string;
}

export interface HookOutcome {
  exitCode: 0 | 1 | 2;
  stdout?: string;
  stderr?: string;
}

export interface HookEnv {
  /** The project whose `.oar/` folder is used. Default: CLAUDE_PROJECT_DIR, then the input's `cwd`. */
  projectDir?: string;
  /** Where the signing key lives. Default: OAR_HOME, then ~/.oar. */
  oarHome?: string;
}

export async function runHook(input: HookInput, env: HookEnv = {}): Promise<HookOutcome> {
  const projectDir = env.projectDir ?? process.env.CLAUDE_PROJECT_DIR ?? input.cwd ?? process.cwd();
  const store = new Store(projectDir);
  let config: Config = {};
  try {
    config = store.config();
    const event = input.hook_event_name;
    if (typeof input.tool_name !== 'string' || !input.tool_name) throw new Error('the hook input has no tool_name');
    if (event === 'PreToolUse') return await pre(store, config, input, env);
    if (event === 'PostToolUse' || event === 'PostToolUseFailure') return await post(store, config, input, env);
    return { exitCode: 0 };
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    if (input.hook_event_name === 'PreToolUse' && config.failClosed !== false) {
      return { exitCode: 2, stderr: `OAR could not check or record this tool call, so it was blocked: ${why}. Fix .oar/ or set "failClosed": false in .oar/config.json.` };
    }
    return { exitCode: 1, stderr: `OAR could not record this tool call: ${why}.` };
  }
}

async function pre(store: Store, config: Config, input: HookInput, env: HookEnv): Promise<HookOutcome> {
  const rules = parseRules(store.rulesFile() ?? {});
  const tool = input.tool_name!;
  const verdict = check(rules, tool, input.tool_input);
  const session = sessionFile(input.session_id);
  return store.withLock(async () => {
    const oar = open(store, config, session, env);
    const action = await oar.decide({
      type: tool,
      target: targetOf(tool),
      params: { input: input.tool_input ?? null },
      ...(input.tool_use_id ? { idempotencyKey: input.tool_use_id } : {}),
      result: verdict.result,
      ...(verdict.reasons ? { reasons: verdict.reasons } : {}),
    });
    if (verdict.result !== 'denied') store.setPending(session, { ...store.pending(session), [callKey(input)]: action.id });
    save(store, session, oar);
    const reason = verdict.reasons?.join(', ') ?? '';
    if (verdict.result === 'denied') return { exitCode: 2, stderr: `Blocked by the OAR rules (${reason}). The call was recorded and did not run.` };
    if (verdict.result === 'held') {
      return {
        exitCode: 0,
        stdout: JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'ask',
            permissionDecisionReason: `The OAR rules say this call needs a person's approval (${reason}).`,
          },
        }),
      };
    }
    return { exitCode: 0 };
  });
}

async function post(store: Store, config: Config, input: HookInput, env: HookEnv): Promise<HookOutcome> {
  const tool = input.tool_name!;
  const session = sessionFile(input.session_id);
  return store.withLock(async () => {
    const oar = open(store, config, session, env);
    const pending = store.pending(session);
    const key = callKey(input);
    let action: ActionHandle | undefined = pending[key] ? oar.action(pending[key]) : undefined;
    // No PreToolUse record (the hook was added mid-session, or only PostToolUse is configured): record it now.
    action ??= await oar.decide({ type: tool, target: targetOf(tool), params: { input: input.tool_input ?? null }, result: 'allowed', reasons: ['recorded_after_the_call'] });
    // A held call that ran was allowed by the person in Claude Code's permission prompt.
    if (action.status === 'held') await oar.approve(action, { approver: config.approver ?? 'local-user', method: 'button' });
    if (action.status === 'allowed' || action.status === 'approved') {
      const ok = input.hook_event_name === 'PostToolUse' && (input.tool_response as { success?: unknown } | undefined)?.success !== false;
      await oar.execute(action, { ok, after: { response_digest: canonicalDigest(input.tool_response ?? null) } });
    }
    delete pending[key];
    store.setPending(session, pending);
    save(store, session, oar);
    return { exitCode: 0 };
  });
}

/** A recorder that continues the session's chain. */
function open(store: Store, config: Config, session: string, env: HookEnv): Recorder & { saved: number; savedSalts: number } {
  const records = store.records(session);
  const disclosures = store.disclosures(session);
  const oar = createRecorder({
    issuer: signingKey(env.oarHome),
    org: config.org ?? 'local',
    agent: config.agent ?? 'claude-code',
    run: `run:${session}`,
    policy: store.rulesFile() ?? { rules: [] },
    policyId: 'oar-rules',
    history: { records, disclosures },
  });
  return Object.assign(oar, { saved: records.length, savedSalts: disclosures.length });
}

function save(store: Store, session: string, oar: Recorder & { saved: number; savedSalts: number }): void {
  store.append(session, oar.records.slice(oar.saved), oar.disclosures.slice(oar.savedSalts));
}

/** MCP tools are named mcp__<server>__<tool>: the server is the target. Claude Code's own tools act locally. */
function targetOf(tool: string): string {
  const mcp = /^mcp__([^_]+(?:_[^_]+)*)__/.exec(tool);
  return mcp ? mcp[1]! : 'claude-code';
}

/** Links a PostToolUse to its PreToolUse: the tool_use_id, or the tool and its exact input. */
function callKey(input: HookInput): string {
  return input.tool_use_id ? `id:${input.tool_use_id}` : canonicalDigest({ tool: input.tool_name, input: input.tool_input ?? null });
}
