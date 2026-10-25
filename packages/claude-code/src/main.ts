#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { bundleSession, init, SETTINGS } from './commands.js';
import { runHook, type HookInput } from './hook.js';

const HELP = `oar-claude-hook: record Claude Code's tool calls as Open Action Records

  oar-claude-hook                    Run as a hook (reads the hook's JSON on stdin)
  oar-claude-hook init               Create .oar/ with example rules, and print the settings to add
  oar-claude-hook bundle [session]   Write the latest (or named) session's records as a bundle
                                     to check with: npx @openactionrecord/cli verify <bundle.json>

Docs: https://github.com/openactionrecord/oar/tree/main/packages/claude-code`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

async function main(argv: string[]): Promise<number> {
  const [command, arg] = argv;
  const projectDir = process.env.CLAUDE_PROJECT_DIR ?? process.cwd();
  if (command === '--help' || command === '-h') {
    console.log(HELP);
    return 0;
  }
  if (command === 'init') {
    for (const line of init(projectDir)) console.log(line);
    console.log('\nAdd this to .claude/settings.json (merge with any hooks you already have):\n');
    console.log(JSON.stringify(SETTINGS, null, 2));
    return 0;
  }
  if (command === 'bundle') {
    const { session, bundle } = await bundleSession(projectDir, arg);
    const out = `oar-bundle-${session}.json`;
    writeFileSync(join(projectDir, out), `${JSON.stringify(bundle, null, 2)}\n`);
    console.log(`Wrote ${bundle.records.length} records to ${out}. Check it with: npx @openactionrecord/cli verify ${out}`);
    return 0;
  }
  if (command !== undefined) {
    console.error(HELP);
    return 1;
  }

  let input: HookInput;
  try {
    input = JSON.parse(await readStdin()) as HookInput;
  } catch {
    console.error('OAR could not read the hook input, so the call was blocked.');
    return 2;
  }
  const outcome = await runHook(input);
  if (outcome.stdout) process.stdout.write(outcome.stdout);
  if (outcome.stderr) process.stderr.write(`${outcome.stderr}\n`);
  return outcome.exitCode;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  },
);
