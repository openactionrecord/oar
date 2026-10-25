import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRecorder, type Bundle } from '@openactionrecord/core';
import { sessionFile, signingKey, Store } from './store.js';

/** The hooks block for `.claude/settings.json`. */
export const SETTINGS = {
  hooks: {
    PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y @openactionrecord/claude-code' }] }],
    PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y @openactionrecord/claude-code' }] }],
    PostToolUseFailure: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y @openactionrecord/claude-code' }] }],
  },
};

const EXAMPLE_RULES = {
  rules: [
    { tool: 'Bash', contains: ['rm -rf', 'git push --force', 'drop table'], effect: 'deny', reason: 'destructive_command' },
    { tool: 'mcp__*', contains: ['delete', 'drop', 'refund'], effect: 'hold', reason: 'needs_a_person' },
  ],
  default: 'allow',
};

/** Creates `.oar/` with example rules, keeps it out of git, and returns what to paste into settings. */
export function init(projectDir: string): string[] {
  const done: string[] = [];
  const dir = join(projectDir, '.oar');
  mkdirSync(dir, { recursive: true });
  const rules = join(dir, 'rules.json');
  if (!existsSync(rules)) {
    writeFileSync(rules, `${JSON.stringify(EXAMPLE_RULES, null, 2)}\n`);
    done.push('Wrote example rules to .oar/rules.json: edit them to suit your project.');
  }
  const gitignore = join(projectDir, '.gitignore');
  const ignored = existsSync(gitignore) && readFileSync(gitignore, 'utf8').split('\n').some((l) => l.trim() === '.oar/' || l.trim() === '.oar');
  if (!ignored) {
    appendFileSync(gitignore, `${existsSync(gitignore) && !readFileSync(gitignore, 'utf8').endsWith('\n') ? '\n' : ''}.oar/\n`);
    done.push('Added .oar/ to .gitignore: it holds the salts behind your records.');
  }
  return done;
}

/** A bundle of one session's records, without disclosing any values. Default: the latest session. */
export async function bundleSession(projectDir: string, session?: string, oarHome?: string): Promise<{ session: string; bundle: Bundle }> {
  const store = new Store(projectDir);
  const name = session ? sessionFile(session) : store.sessions().at(-1);
  if (!name) throw new Error('No records yet: run Claude Code with the hook first.');
  const records = store.records(name);
  if (records.length === 0) throw new Error(`No records for session ${name}.`);
  const first = records[0]!.payload;
  const oar = createRecorder({
    issuer: signingKey(oarHome),
    org: first.org_id,
    agent: first.agent_id,
    run: first.run_id,
    history: { records, disclosures: store.disclosures(name) },
  });
  return { session: name, bundle: await oar.bundle() };
}
