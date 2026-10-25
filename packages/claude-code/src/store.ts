// Where the hook keeps things. Each tool call runs the hook as a new process, so everything lives in files:
//
//   <project>/.oar/records/<session>.jsonl   the records, append-only (safe to share; values are committed)
//   <project>/.oar/salts/<session>.jsonl     the salts and values behind the commitments (secret; never commit)
//   <project>/.oar/pending/<session>.json    tool calls checked but not finished yet
//   <project>/.oar/config.json, rules.json   your settings and rules (optional)
//   ~/.oar/keys/claude-code.json             the signing key (secret), made on first use
import { appendFileSync, chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { generateSigningKey, type DisclosureInput, type OarRecord, type SigningKey } from '@openactionrecord/core';

export interface Config {
  /** Your organisation or app identifier in the records. Default "local". */
  org?: string;
  /** The agent's identifier in the records. Default "claude-code". */
  agent?: string;
  /** Who approves held calls in Claude Code's permission prompt: a stable reference, not an email. Default "local-user". */
  approver?: string;
  /** When the hook cannot check or record a call, block it (default) instead of letting it run unrecorded. */
  failClosed?: boolean;
}

export class Store {
  readonly dir: string;

  constructor(projectDir: string) {
    this.dir = join(projectDir, '.oar');
  }

  config(): Config {
    return this.json<Config>('config.json') ?? {};
  }

  rulesFile(): unknown {
    return this.json('rules.json');
  }

  records(session: string): OarRecord[] {
    return this.lines<OarRecord>(join('records', `${session}.jsonl`));
  }

  disclosures(session: string): DisclosureInput[] {
    return this.lines<DisclosureInput>(join('salts', `${session}.jsonl`));
  }

  append(session: string, records: readonly OarRecord[], disclosures: readonly DisclosureInput[]): void {
    this.appendLines(join('records', `${session}.jsonl`), records, 0o644);
    this.appendLines(join('salts', `${session}.jsonl`), disclosures, 0o600);
  }

  pending(session: string): Record<string, string> {
    return this.json<Record<string, string>>(join('pending', `${session}.json`)) ?? {};
  }

  setPending(session: string, pending: Record<string, string>): void {
    const file = join(this.dir, 'pending', `${session}.json`);
    mkdirSync(join(this.dir, 'pending'), { recursive: true });
    writeFileSync(`${file}.tmp`, JSON.stringify(pending), { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
  }

  /** Sessions with records, most recently changed last. */
  sessions(): string[] {
    const dir = join(this.dir, 'records');
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => ({ name: f.slice(0, -'.jsonl'.length), at: statSync(join(dir, f)).mtimeMs }))
      .sort((a, b) => a.at - b.at)
      .map((s) => s.name);
  }

  /** Runs `fn` while holding the project's lock, so tool calls that run in parallel keep one chain. */
  async withLock<T>(fn: () => Promise<T>): Promise<T> {
    mkdirSync(this.dir, { recursive: true });
    const lock = join(this.dir, 'lock');
    const deadline = Date.now() + 10_000;
    for (;;) {
      try {
        mkdirSync(lock);
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        if (Date.now() - statSafe(lock) > 30_000) rmSync(lock, { recursive: true, force: true });
        else if (Date.now() > deadline) throw new Error('another OAR hook has held .oar/lock for too long');
        else await new Promise((resolve) => setTimeout(resolve, 15));
      }
    }
    try {
      return await fn();
    } finally {
      rmSync(lock, { recursive: true, force: true });
    }
  }

  private json<T>(file: string): T | undefined {
    const path = join(this.dir, file);
    if (!existsSync(path)) return undefined;
    try {
      return JSON.parse(readFileSync(path, 'utf8')) as T;
    } catch {
      throw new Error(`.oar/${file} is not valid JSON`);
    }
  }

  private lines<T>(file: string): T[] {
    const path = join(this.dir, file);
    if (!existsSync(path)) return [];
    return readFileSync(path, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line, i) => {
        try {
          return JSON.parse(line) as T;
        } catch {
          throw new Error(`.oar/${file}: line ${i + 1} is not valid JSON`);
        }
      });
  }

  private appendLines(file: string, items: readonly unknown[], mode: number): void {
    if (items.length === 0) return;
    const path = join(this.dir, file);
    mkdirSync(join(path, '..'), { recursive: true });
    appendFileSync(path, items.map((item) => `${JSON.stringify(item)}\n`).join(''), { mode });
    chmodSync(path, mode);
  }
}

/** The hook's signing key: `$OAR_HOME/keys/claude-code.json` (default `~/.oar`), made on first use, readable only by you. */
export function signingKey(home = process.env.OAR_HOME ?? join(homedir(), '.oar')): SigningKey {
  const dir = join(home, 'keys');
  const file = join(dir, 'claude-code.json');
  if (existsSync(file)) {
    const key = JSON.parse(readFileSync(file, 'utf8')) as SigningKey;
    if (typeof key?.kid !== 'string' || !/^[0-9a-f]{64}$/.test(key.privateKey ?? '')) throw new Error(`${file} is not a signing key`);
    return key;
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const key = generateSigningKey(`claude-code-${new Date().toISOString().slice(0, 10)}`);
  try {
    writeFileSync(file, JSON.stringify(key), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    // Another hook (in another project) made the key first: use that one.
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return signingKey(home);
    throw error;
  }
  return key;
}

/** Session ids become file names: keep them to safe characters. */
export function sessionFile(session: unknown): string {
  const name = typeof session === 'string' ? session.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 100) : '';
  return name || 'default';
}

function statSafe(path: string): number {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return Date.now();
  }
}

