import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

const run = promisify(execFile);
const root = fileURLToPath(new URL('../../..', import.meta.url));
const main = fileURLToPath(new URL('./main.ts', import.meta.url));
const tsx = join(root, 'node_modules', '.bin', 'tsx');

async function oar(args: string[]): Promise<{ code: number; out: string; err: string }> {
  try {
    const { stdout, stderr } = await run(tsx, [main, ...args], { cwd: root, env: { ...process.env, NO_COLOR: '1' } });
    return { code: 0, out: stdout, err: stderr };
  } catch (e) {
    const error = e as { code: number; stdout: string; stderr: string };
    return { code: error.code, out: error.stdout, err: error.stderr };
  }
}

describe('oar CLI', () => {
  it('demo writes a bundle that verifies, a tampered copy that does not, and an offline page', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'oar-demo-'));
    const demo = await oar(['demo', dir, '--offline']);
    expect(demo.code).toBe(0);
    expect(demo.out).toContain('Done, and confirmed in the system of record');
    expect(demo.out).toContain('Executed, but the system of record does NOT show it');
    expect(demo.out).toContain('Verification failed');

    const ok = await oar(['verify', join(dir, 'evidence.json'), '--cross-check']);
    expect(ok.code).toBe(0);
    expect(ok.out).toContain('Independent WebCrypto verifier agrees');
    expect(ok.out).toContain('All 8 records passed verification.');

    const bad = await oar(['verify', join(dir, 'evidence-tampered.json')]);
    expect(bad.code).toBe(1);
    expect(bad.out).toContain('signature FAILED');

    const sealRequired = await oar(['verify', join(dir, 'evidence.json'), '--require-seal', '--json']);
    expect(JSON.parse(sealRequired.out).report.result).toBe('pass');

    const html = await readFile(join(dir, 'verify.html'), 'utf8');
    expect(html).toContain('oarVerifyBundle');
    expect(html).not.toMatch(/<script[^>]+src=/);
  }, 60_000);

  it('verify against substituted keys fails', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'oar-keys-'));
    await oar(['demo', dir, '--offline']);
    const other = await oar(['keygen', 'someone-else']);
    const jwks = JSON.parse(other.out.slice(other.out.indexOf('{\n')));
    await writeFile(join(dir, 'wrong-keys.json'), JSON.stringify({ issuer: jwks }));
    const res = await oar(['verify', join(dir, 'evidence.json'), '--keys', join(dir, 'wrong-keys.json')]);
    expect(res.code).toBe(1);
  }, 60_000);

  it('explains bad input instead of crashing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'oar-bad-'));
    await writeFile(join(dir, 'x.json'), '{"format":"nope"}');
    const res = await oar(['verify', join(dir, 'x.json')]);
    expect(res.code).toBe(2);
    expect(res.err).toContain('Not a valid bundle');
    expect((await oar(['frobnicate'])).err).toContain('Unknown command');
  }, 30_000);
});
