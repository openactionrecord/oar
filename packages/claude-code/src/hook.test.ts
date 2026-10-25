import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { summarize, verifyBundle } from '@openactionrecord/core';
import { bundleSession, init } from './commands.js';
import { runHook, type HookInput } from './hook.js';

function project(rules?: unknown) {
  const projectDir = mkdtempSync(join(tmpdir(), 'oar-cc-'));
  const oarHome = mkdtempSync(join(tmpdir(), 'oar-home-'));
  init(projectDir);
  if (rules !== undefined) writeFileSync(join(projectDir, '.oar', 'rules.json'), JSON.stringify(rules));
  const env = { projectDir, oarHome };
  const call = (event: string, tool: string, toolInput: unknown, extra: Partial<HookInput> = {}) =>
    runHook({ hook_event_name: event, session_id: 'sess-1', tool_name: tool, tool_input: toolInput, ...extra }, env);
  return { projectDir, oarHome, env, call };
}

const DENY_RM = { rules: [{ tool: 'Bash', contains: ['rm -rf'], effect: 'deny', reason: 'destructive_command' }] };

describe('the Claude Code hook', () => {
  it('records an allowed call end to end, and the bundle verifies without revealing the command', async () => {
    const { projectDir, oarHome, call } = project(DENY_RM);
    expect(await call('PreToolUse', 'Bash', { command: 'ls -la' }, { tool_use_id: 't1' })).toEqual({ exitCode: 0 });
    expect(await call('PostToolUse', 'Bash', { command: 'ls -la' }, { tool_use_id: 't1', tool_response: { stdout: 'a.ts' } })).toEqual({ exitCode: 0 });

    const { bundle } = await bundleSession(projectDir, 'sess-1', oarHome);
    expect(bundle.records.map((r) => r.payload.phase)).toEqual(['decision', 'execution']);
    expect(verifyBundle(bundle).result).toBe('pass');
    expect(JSON.stringify(bundle)).not.toContain('ls -la');
    expect(summarize(bundle.records)[0]).toMatchObject({ type: 'Bash', target: 'claude-code', outcome: 'executed_unconfirmed' });
  });

  it('blocks a denied call with exit 2 and says why; it is recorded and never executed', async () => {
    const { projectDir, oarHome, call } = project(DENY_RM);
    const out = await call('PreToolUse', 'Bash', { command: 'rm -rf /' });
    expect(out.exitCode).toBe(2);
    expect(out.stderr).toContain('destructive_command');
    const { bundle } = await bundleSession(projectDir, undefined, oarHome);
    expect(bundle.records).toHaveLength(1);
    expect(bundle.records[0]!.payload).toMatchObject({ result: 'denied', reasons: ['destructive_command'] });
  });

  it("a held call asks the person in Claude Code's prompt; once it runs, the approval is recorded", async () => {
    const { projectDir, oarHome, call } = project({ rules: [{ tool: 'mcp__prod-db__*', contains: ['drop'], effect: 'hold' }] });
    const asked = await call('PreToolUse', 'mcp__prod-db__run_sql', { sql: 'DROP TABLE tmp' }, { tool_use_id: 't9' });
    expect(asked.exitCode).toBe(0);
    expect(JSON.parse(asked.stdout!).hookSpecificOutput.permissionDecision).toBe('ask');
    await call('PostToolUse', 'mcp__prod-db__run_sql', { sql: 'DROP TABLE tmp' }, { tool_use_id: 't9', tool_response: { ok: true } });

    const { bundle } = await bundleSession(projectDir, undefined, oarHome);
    expect(verifyBundle(bundle).result).toBe('pass');
    expect(summarize(bundle.records)[0]).toMatchObject({ target: 'prod-db', approvedBy: 'local-user', outcome: 'executed_unconfirmed' });
  });

  it('records a failed call as failed, and matches calls without a tool_use_id by their input', async () => {
    const { projectDir, oarHome, call } = project();
    await call('PreToolUse', 'Write', { file_path: 'a.ts' });
    await call('PostToolUseFailure', 'Write', { file_path: 'a.ts' });
    const { bundle } = await bundleSession(projectDir, undefined, oarHome);
    expect(bundle.records.map((r) => r.payload.result)).toEqual(['allowed', 'failed']);
  });

  it('keeps one chain across many calls, including calls that run at the same time', async () => {
    const { projectDir, oarHome, call } = project();
    await Promise.all(
      Array.from({ length: 6 }, async (_, i) => {
        await call('PreToolUse', 'Read', { file_path: `f${i}` }, { tool_use_id: `r${i}` });
        await call('PostToolUse', 'Read', { file_path: `f${i}` }, { tool_use_id: `r${i}`, tool_response: 'x' });
      }),
    );
    const { bundle } = await bundleSession(projectDir, undefined, oarHome);
    expect(bundle.records).toHaveLength(12);
    expect(verifyBundle(bundle).result).toBe('pass');
  });

  it('a record changed on disk fails verification', async () => {
    const { projectDir, oarHome, call } = project();
    await call('PreToolUse', 'Read', { file_path: 'a' });
    await call('PostToolUse', 'Read', { file_path: 'a' });
    const file = join(projectDir, '.oar', 'records', 'sess-1.jsonl');
    writeFileSync(file, readFileSync(file, 'utf8').replace('"Read"', '"Write"'));
    const { bundle } = await bundleSession(projectDir, undefined, oarHome);
    expect(verifyBundle(bundle).result).toBe('fail');
  });

  it('fails closed: a broken rules file blocks the call, unless failClosed is false', async () => {
    const { projectDir, call } = project();
    writeFileSync(join(projectDir, '.oar', 'rules.json'), '{ not json');
    const blocked = await call('PreToolUse', 'Bash', { command: 'ls' });
    expect(blocked.exitCode).toBe(2);
    expect(blocked.stderr).toContain('rules.json is not valid JSON');
    writeFileSync(join(projectDir, '.oar', 'config.json'), JSON.stringify({ failClosed: false }));
    expect((await call('PreToolUse', 'Bash', { command: 'ls' })).exitCode).toBe(1);
  });

  it('keeps the salts and the key readable only by you, and .oar/ out of git', async () => {
    const { projectDir, oarHome, call } = project();
    await call('PreToolUse', 'Read', { file_path: 'a' });
    expect(statSync(join(projectDir, '.oar', 'salts', 'sess-1.jsonl')).mode & 0o777).toBe(0o600);
    expect(statSync(join(oarHome, 'keys', 'claude-code.json')).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(projectDir, '.gitignore'), 'utf8')).toContain('.oar/');
  });

  it('works as a command: stdin in, exit code out', () => {
    const { projectDir, oarHome } = project(DENY_RM);
    const main = fileURLToPath(new URL('./main.ts', import.meta.url));
    const root = fileURLToPath(new URL('../../../', import.meta.url));
    const tsx = join(root, 'node_modules', '.bin', 'tsx');
    // Run from the repository root, so tsx resolves @openactionrecord/core to its source.
    const env = { ...process.env, CLAUDE_PROJECT_DIR: projectDir, OAR_HOME: oarHome };
    const run = (input: unknown) => spawnSync(tsx, [main], { cwd: root, input: JSON.stringify(input), env, encoding: 'utf8' });
    expect(run({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } }).status).toBe(0);
    const denied = run({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'rm -rf x' } });
    expect(denied.status).toBe(2);
    expect(denied.stderr).toContain('Blocked by the OAR rules');
    const out = execFileSync(tsx, [main, 'bundle', 's'], { cwd: root, env, encoding: 'utf8' });
    expect(out).toContain('Wrote 2 records');
    expect(statSync(join(projectDir, 'oar-bundle-s.json')).isFile()).toBe(true);
  });
});
