import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { summarize, verifyBundle, parseBundle } from '@openactionrecord/core';
import { loadStandaloneVerifier } from '@openactionrecord/core/standalone';

// Every verifier must reach the expected result on every vector. The Python verifier runs the same manifests.

interface Case {
  file: string;
  description: string;
  options: { tsa_roots?: 'test'; require_seal?: boolean };
  expect: { result: 'pass' | 'fail'; level?: string; failedChecks?: string[]; outcomes?: string[] };
}

for (const folder of ['vectors/', 'vectors/compat/']) {
  const base = fileURLToPath(new URL(`../${folder}`, import.meta.url));
  const manifest = JSON.parse(readFileSync(`${base}manifest.json`, 'utf8')) as { tsa_roots_file: string; cases: Case[] };
  const roots = JSON.parse(readFileSync(`${base}${manifest.tsa_roots_file}`, 'utf8'));

  describe(`test vectors: ${folder}`, () => {
    for (const c of manifest.cases) {
      const options = { ...(c.options.tsa_roots === 'test' ? { tsaRoots: roots } : {}), requireSeal: Boolean(c.options.require_seal) };
      const raw = JSON.parse(readFileSync(`${base}${c.file}`, 'utf8'));

      it(`${c.file}${c.options.require_seal ? ' (seals required)' : ''}: reference verifier`, () => {
        const report = verifyBundle(raw, options);
        expect(report.result).toBe(c.expect.result);
        if (c.expect.level) expect(report.level).toBe(c.expect.level);
        if (c.expect.failedChecks) expect([...report.failedChecks].sort()).toEqual([...c.expect.failedChecks].sort());
        if (c.expect.outcomes) expect(summarize(parseBundle(raw).records).map((s) => s.outcome)).toEqual(c.expect.outcomes);
      });

      it(`${c.file}${c.options.require_seal ? ' (seals required)' : ''}: standalone verifier agrees`, async () => {
        const report = await loadStandaloneVerifier()(raw, webcrypto.subtle as never, options);
        expect(report.result).toBe(c.expect.result);
        if (c.expect.level) expect(report.level).toBe(c.expect.level);
        if (c.expect.failedChecks) expect([...report.failedChecks].sort()).toEqual([...c.expect.failedChecks].sort());
      });
    }
  });
}
