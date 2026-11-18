// Record every tool call on an MCP server as an Open Action Record (SPEC.md): the rule decision, the authorities
// the call relied on (re-checked just before the tool runs), what it changed, and whether the system agrees.
//
//   const oar = createRecorder({ issuer, org: 'acme', agent: 'billing-mcp' });
//   recordTools(server, oar, { target: 'billing', tools: { refund: { check: (a) => ... } } });
//   server.registerTool('refund', { inputSchema: {...} }, handler);   // recorded
//
// Call `recordTools` before registering tools. Tools registered afterwards are wrapped; the handlers themselves
// do not change.
import type { AuthorityInput, AuthorityStatus, Recorder, RuleResult as CheckResult } from '@openactionrecord/core';

/** The parts of the MCP SDK's McpServer this package uses. */
export interface McpServerLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registerTool: (name: string, config: any, cb: any) => any;
}

/** What the MCP SDK passes a handler as `extra`; only `authInfo` is read. */
export interface ToolExtra {
  authInfo?: { token: string; clientId?: string; scopes?: string[]; expiresAt?: number; extra?: Record<string, unknown> };
  [key: string]: unknown;
}

export interface ToolResultLike {
  content?: unknown[];
  isError?: boolean;
  [key: string]: unknown;
}

export interface ToolRule {
  /** The action type in the record. Default: the tool's name. */
  type?: string;
  /** The system the tool acts on. Default: the `target` given to `recordTools`. */
  target?: string;
  /** Your rules: "allowed", "held" (waits for a person) or "denied". Default: allowed. */
  check?: (args: Record<string, unknown>, extra: ToolExtra) => CheckResult | Promise<CheckResult>;
  /** Reads the affected state from the system of record, before and after the tool runs. */
  readState?: (args: Record<string, unknown>) => unknown | Promise<unknown>;
  /** The identifier of what changed, from the tool's result. */
  targetRef?: (result: ToolResultLike) => string | undefined;
  /** Reads the system of record again and says whether it shows the change. */
  confirm?: (args: Record<string, unknown>, result: ToolResultLike) => boolean | Promise<boolean>;
  /** Set false to leave this tool unrecorded (for example a read-only lookup). */
  record?: boolean;
}

export interface RecordToolsOptions {
  /** The system the tools act on, for example "billing". */
  target: string;
  /** Rules per tool name. Tools without an entry use `defaults`. */
  tools?: Record<string, ToolRule>;
  defaults?: ToolRule;
  /**
   * The authorities a call relied on (SPEC.md section 4.5). Default: the caller's OAuth access token from
   * `extra.authInfo`, by digest, when the server has authentication. Return [] to record none.
   */
  authorities?: (extra: ToolExtra, args: Record<string, unknown>) => AuthorityInput[] | Promise<AuthorityInput[]>;
  /**
   * Checks each authority again just before the tool runs, and returns one status per authority. Use your
   * authorization server's token introspection (RFC 7662) here. Default: "expired" once `expiresAt` has passed,
   * otherwise "valid"; that alone does not detect revocation.
   */
  recheck?: (authorities: AuthorityInput[], extra: ToolExtra) => AuthorityStatus[] | Promise<AuthorityStatus[]>;
  /** The authorization server's identifier, for the default authority. Default: "mcp-authorization-server". */
  issuer?: string;
}

const text = (t: string, isError = true): ToolResultLike => ({ content: [{ type: 'text', text: t }], isError });

function defaultAuthorities(issuer: string) {
  return (extra: ToolExtra): AuthorityInput[] => {
    const auth = extra?.authInfo;
    if (!auth?.token) return [];
    return [{ type: 'oauth-access-token', issuer, artifact: auth.token, ...(auth.expiresAt ? { expiresAt: new Date(auth.expiresAt * 1000).toISOString() } : {}) }];
  };
}

function defaultRecheck(authorities: AuthorityInput[]): AuthorityStatus[] {
  return authorities.map((a) => (a.expiresAt && Date.parse(a.expiresAt) <= Date.now() ? 'expired' : 'valid'));
}

/** Wraps `server.registerTool` so that every tool registered from now on is recorded. Returns the server. */
export function recordTools<S extends McpServerLike>(server: S, oar: Recorder, options: RecordToolsOptions): S {
  const original = server.registerTool.bind(server);
  const authoritiesFor = options.authorities ?? defaultAuthorities(options.issuer ?? 'mcp-authorization-server');
  const recheck = options.recheck ?? defaultRecheck;

  server.registerTool = (name, config, cb) => {
    const rule: ToolRule = { ...options.defaults, ...options.tools?.[name] };
    if (rule.record === false) return original(name, config, cb);
    const hasArgs = config?.inputSchema !== undefined;

    const wrapped = async (...callArgs: unknown[]) => {
      const args = (hasArgs ? callArgs[0] : {}) as Record<string, unknown>;
      const extra = ((hasArgs ? callArgs[1] : callArgs[0]) ?? {}) as ToolExtra;
      const type = rule.type ?? name;
      const target = rule.target ?? options.target;

      const verdict = rule.check ? await rule.check(args, extra) : ({ result: 'allowed' } as CheckResult);
      const authorities = await authoritiesFor(extra, args);
      const action = await oar.decide({
        type,
        target,
        params: args,
        result: verdict.result,
        ...(verdict.reasons ? { reasons: verdict.reasons } : {}),
        ...(authorities.length ? { authorities } : {}),
      });
      if (verdict.result === 'denied') return text(`${name} was blocked by the rules${verdict.reasons?.length ? ` (${verdict.reasons.join(', ')})` : ''}. Nothing ran.`);
      if (verdict.result === 'held') return text(`${name} is waiting for a person to approve it. Nothing has run yet.`);

      let statuses: AuthorityStatus[] | undefined;
      if (authorities.length) {
        try {
          statuses = await recheck(authorities, extra);
        } catch {
          statuses = authorities.map(() => 'unknown' as AuthorityStatus);
        }
        if (statuses.some((s) => s !== 'valid')) {
          await oar.execute(action, { authorityCheck: { statuses } });
          return text(`${name} did not run: the authorization it relied on is no longer valid.`);
        }
      }

      const before = rule.readState ? await rule.readState(args) : undefined;
      let result: ToolResultLike;
      try {
        result = (await (cb as (...a: unknown[]) => unknown)(...callArgs)) as ToolResultLike;
      } catch (error) {
        await oar.execute(action, { ok: false, ...(before !== undefined ? { before } : {}), ...(statuses ? { authorityCheck: { statuses } } : {}) });
        throw error;
      }
      const after = rule.readState ? await rule.readState(args) : undefined;
      const ok = !result?.isError;
      const ref = ok ? rule.targetRef?.(result) : undefined;
      await oar.execute(action, {
        ok,
        ...(before !== undefined ? { before } : {}),
        ...(after !== undefined ? { after } : {}),
        ...(ref !== undefined ? { targetRef: ref } : {}),
        ...(statuses ? { authorityCheck: { statuses } } : {}),
      });
      if (ok && rule.confirm) await oar.confirm(action, { confirmed: await rule.confirm(args, result) });
      return result;
    };

    return original(name, config, wrapped);
  };
  return server;
}
