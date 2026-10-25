// Checks that every published package has the version of the release tag (v0.1.0 -> 0.1.0).
// Usage: node scripts/check-versions.mjs v0.1.0
import { readdirSync, readFileSync } from 'node:fs';

const tag = process.argv[2] ?? '';
const want = tag.replace(/^v/, '');
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(want)) {
  console.error(`The release tag must look like v0.1.0 (got "${tag}").`);
  process.exit(1);
}

const found = [];
for (const dir of readdirSync('packages')) {
  const pkg = JSON.parse(readFileSync(`packages/${dir}/package.json`, 'utf8'));
  if (!pkg.private) found.push([pkg.name, pkg.version]);
}
const py = /^version\s*=\s*"([^"]+)"/m.exec(readFileSync('python/pyproject.toml', 'utf8'));
found.push(['open-action-record (Python)', py?.[1]]);

const wrong = found.filter(([, version]) => version !== want);
for (const [name, version] of found) console.log(`${version === want ? 'ok ' : 'NO '} ${name} ${version}`);
if (wrong.length) {
  console.error(`\nSet every version to ${want} before releasing ${tag}.`);
  process.exit(1);
}
