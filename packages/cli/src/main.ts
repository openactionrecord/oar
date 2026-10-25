#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  BundleError,
  generateSigningKey,
  keyFingerprints,
  parseBundle,
  publicKeys,
  summarize,
  verifyBundle,
  type Jwks,
  type TsaRoot,
  type VerificationKeys,
} from '@openactionrecord/core';
import { loadStandaloneVerifier, standaloneVerifierHtml } from '@openactionrecord/core/standalone';
import { demo } from './demo.js';
import { c, line, printActions, printReport, FAIL, PASS } from './print.js';

const HELP = `${c.bold('oar')}: Open Action Record, from the command line

${c.bold('Usage')}
  oar demo [dir] [--offline]         See what OAR proves, in one minute (writes files to ./oar-demo)
  oar verify <bundle.json>           Verify a bundle and show what each action did
      --keys <keys.json>             Check against keys you trust ({ "issuer": JWKS, "sealer": JWKS })
      --require-seal                 Fail records not countersigned by a separate sealing service
      --tsa-roots <roots.json>       Accept these timestamp-authority roots instead of the bundled DigiCert roots
      --cross-check                  Also run the independent WebCrypto verifier; fail if they disagree
      --json                         Print the report as JSON
      --verbose                      Show every check on every record
  oar inspect <bundle.json>          Show the actions in a bundle without verifying
  oar html <bundle.json> [out.html]  Write a self-contained page that verifies the bundle offline
  oar keygen <kid> [out.json]        Make an Ed25519 signing key (keep it secret) and print its public key set
  oar --version

Docs and source: https://github.com/openactionrecord/oar`;

interface Flags {
  _: string[];
  [flag: string]: string | boolean | string[];
}

function parseArgs(argv: string[]): Flags {
  const flags: Flags = { _: [] };
  const takesValue = new Set(['keys', 'tsa-roots']);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith('--')) {
      const name = arg.slice(2);
      if (takesValue.has(name)) {
        const value = argv[++i];
        if (value === undefined) throw new UsageError(`--${name} needs a file`);
        flags[name] = value;
      } else flags[name] = true;
    } else if (arg === '-h') flags.help = true;
    else if (arg === '-v') flags.version = true;
    else flags._.push(arg);
  }
  return flags;
}

class UsageError extends Error {}

async function readJson(path: string, what: string): Promise<unknown> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new UsageError(`Cannot read ${what} ${path}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${path} is not valid JSON`);
  }
}

async function main(argv: string[]): Promise<number> {
  const flags = parseArgs(argv);
  const [command, ...args] = flags._;
  if (flags.version) {
    const pkg = createRequire(import.meta.url)('../package.json') as { version: string };
    line(pkg.version);
    return 0;
  }
  if (!command || flags.help || command === 'help') {
    line(HELP);
    return command || flags.help ? 0 : 1;
  }

  switch (command) {
    case 'demo':
      return demo(args[0] ?? 'oar-demo', { offline: Boolean(flags.offline) });

    case 'verify': {
      const file = need(args[0], 'oar verify <bundle.json>');
      const raw = await readJson(file, 'bundle');
      const keys = flags.keys ? ((await readJson(String(flags.keys), 'key file')) as VerificationKeys) : undefined;
      const tsaRoots = flags['tsa-roots'] ? ((await readJson(String(flags['tsa-roots']), 'roots file')) as TsaRoot[]) : undefined;
      const options = { ...(keys ? { keys } : {}), ...(tsaRoots ? { tsaRoots } : {}), requireSeal: Boolean(flags['require-seal']) };
      const bundle = parseBundle(raw);
      const report = verifyBundle(raw, options);
      let agree = true;
      if (flags['cross-check']) {
        const alt = await loadStandaloneVerifier()(keys ? { ...(raw as object), keys } : raw, webcrypto.subtle as never, { ...(tsaRoots ? { tsaRoots } : {}), requireSeal: Boolean(flags['require-seal']) });
        agree = alt.result === report.result && alt.level === report.level;
        if (!flags.json) line(`${agree ? PASS : FAIL} Independent WebCrypto verifier ${agree ? 'agrees' : `DISAGREES (${alt.result}, ${alt.level})`}`);
      }
      if (flags.json) {
        line(JSON.stringify({ report, actions: summarize(bundle.records, bundle.disclosures, report), crossCheck: flags['cross-check'] ? agree : undefined }, null, 2));
      } else {
        printReport(report, { verbose: Boolean(flags.verbose) });
        printActions(summarize(bundle.records, bundle.disclosures, report));
        line();
        line(c.dim(`Keys from ${keys ? String(flags.keys) : 'the bundle'}: issuer ${fp((keys ?? bundle.keys).issuer)}${(keys ?? bundle.keys).sealer ? `; sealer ${fp((keys ?? bundle.keys).sealer!)}` : ''}`));
        if (!keys) line(c.dim('To rule out a substituted bundle, pass --keys with the key sets the issuer and sealing service publish.'));
      }
      return report.result === 'pass' && agree ? 0 : 1;
    }

    case 'inspect': {
      const bundle = parseBundle(await readJson(need(args[0], 'oar inspect <bundle.json>'), 'bundle'));
      line(c.bold(`${bundle.org.name}: ${bundle.records.length} records${bundle.purpose ? `, for ${bundle.purpose}` : ''}${bundle.generated_at ? `, ${bundle.generated_at}` : ''}`));
      line(c.dim('Not verified. Run `oar verify` to check signatures, seals and the chain.'));
      printActions(summarize(bundle.records, bundle.disclosures));
      return 0;
    }

    case 'html': {
      const file = need(args[0], 'oar html <bundle.json> [out.html]');
      const raw = await readJson(file, 'bundle');
      parseBundle(raw);
      const out = args[1] ?? file.replace(/\.json$/i, '') + '.verify.html';
      await writeFile(out, standaloneVerifierHtml(JSON.stringify(raw)));
      line(`${PASS} Wrote ${out}: open it in any browser, offline, to verify the bundle.`);
      return 0;
    }

    case 'keygen': {
      const kid = need(args[0], 'oar keygen <kid> [out.json]');
      const key = generateSigningKey(kid);
      if (args[1]) {
        await writeFile(args[1], JSON.stringify(key, null, 2), { mode: 0o600 });
        line(`${PASS} Private key written to ${args[1]} (mode 600). Keep it secret; never commit it.`);
      } else {
        line(c.yellow('Private key (keep it secret; store it in a secret manager or an environment variable):'));
        line(JSON.stringify(key));
      }
      line();
      line(c.bold('Public key set to publish, for example at /.well-known/aar-keys.json:'));
      line(JSON.stringify(publicKeys(key), null, 2));
      return 0;
    }

    default:
      throw new UsageError(`Unknown command "${command}". Run \`oar help\`.`);
  }
}

function need(value: string | undefined, usage: string): string {
  if (!value) throw new UsageError(`Usage: ${usage}`);
  return value;
}

function fp(jwks: Jwks): string {
  return keyFingerprints(jwks).join(', ');
}

// Piping into `head` closes stdout early; that is not an error.
process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(process.exitCode ?? 0);
  throw error;
});

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    if (error instanceof UsageError || error instanceof BundleError) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 2;
    } else {
      process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
      process.exitCode = 1;
    }
  },
);
