import { execFile } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// The examples in the README must keep working.
const run = promisify(execFile);
const root = fileURLToPath(new URL('..', import.meta.url));

async function example(name: string): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'oar-example-'));
  const { stdout } = await run(join(root, 'node_modules/.bin/tsx'), ['--tsconfig', join(root, 'tsconfig.json'), join(root, 'examples', `${name}.ts`)], { cwd });
  return stdout;
}

describe('examples', () => {
  it('quickstart', async () => expect(await example('quickstart')).toContain('Done, and confirmed in the system of record'), 30_000);
  it('sealer-server', async () => expect(await example('sealer-server')).toContain('Sealed by a separate service'), 30_000);
  it('tool-wrapper', async () => expect(await example('tool-wrapper')).toContain('store_credit blocked by the rules'), 30_000);
  it('mcp-server', async () => expect(await example('mcp-server')).toContain('Tables now: customers, orders'), 30_000);
  it('add-to-another-receipt', async () => expect(await example('add-to-another-receipt')).toContain('not_confirmed'), 30_000);
});
