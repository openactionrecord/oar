// Builds the playground into dist/index.html (one self-contained file, ready for any static host).
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { verifyBundle } from '@openactionrecord/core';
import { playgroundHtml } from './page.js';
import { sampleBundles } from './samples.js';

const out = fileURLToPath(new URL('../dist/', import.meta.url));
const samples = await sampleBundles();
for (const [name, bundle] of Object.entries(samples)) {
  if (verifyBundle(bundle).result !== 'pass') throw new Error(`Sample ${name} does not verify`);
}
await mkdir(out, { recursive: true });
await writeFile(`${out}index.html`, playgroundHtml(samples));
console.log(`Wrote ${out}index.html`);
