import { LEVEL_LABELS, OUTCOME_LABELS, type ActionSummary, type VerificationReport } from '@openactionrecord/core';

// Terminal output: plain words, colour only when the terminal supports it (NO_COLOR and FORCE_COLOR respected).

const useColor = process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== '0' : !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
const paint = (code: string) => (s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);

export const c = {
  bold: paint('1'),
  dim: paint('2'),
  green: paint('32'),
  red: paint('31'),
  yellow: paint('33'),
  cyan: paint('36'),
};

export const PASS = c.green('✔');
export const FAIL = c.red('✘');
export const WAIT = c.yellow('●');

export function line(text = ''): void {
  process.stdout.write(`${text}\n`);
}

const CHECK_ORDER = ['issuer_signature', 'seal', 'chain', 'checkpoint', 'timestamp', 'disclosures'] as const;
const CHECK_SHORT: Record<(typeof CHECK_ORDER)[number], string> = {
  issuer_signature: 'signature',
  seal: 'seal',
  chain: 'chain',
  checkpoint: 'checkpoint',
  timestamp: 'timestamp',
  disclosures: 'disclosures',
};

/** The verification headline and, per record, which checks passed. */
export function printReport(report: VerificationReport, options: { verbose?: boolean } = {}): void {
  const ok = report.result === 'pass';
  const headline = (report.messages[0] ?? '').replace(/ Evidence level: .*$/, '');
  line(`${ok ? PASS : FAIL} ${c.bold(headline)}${ok ? `  ${levelText(report.level)}` : ''}`);
  for (const message of report.messages.slice(1)) line(`  ${c.dim(message)}`);

  const showRecords = options.verbose || !ok;
  if (!showRecords) return;
  line();
  for (const r of report.receipts) {
    if (!options.verbose && r.result === 'pass') continue;
    const checks = CHECK_ORDER.filter((k) => r.checks[k] !== 'not_checked')
      .map((k) => (r.checks[k] === 'pass' ? c.green(CHECK_SHORT[k]) : c.red(`${CHECK_SHORT[k]} FAILED`)))
      .join(' · ');
    line(`  ${r.result === 'pass' ? PASS : FAIL} ${c.dim(r.receiptId.replace('urn:uuid:', '').slice(0, 8))}  ${checks}`);
    for (const m of r.messages) if (r.result === 'fail' || options.verbose) line(`      ${c.dim(m)}`);
  }
}

export function levelText(level: VerificationReport['level']): string {
  const text = `[${LEVEL_LABELS[level]}]`;
  return level === 'timestamped' ? c.green(text) : level === 'sealed' ? c.cyan(text) : c.yellow(`${text} (no separate sealing service)`);
}

/** One block per action: what was asked, who approved it, what changed, whether it is confirmed. */
export function printActions(actions: readonly ActionSummary[]): void {
  for (const a of actions) {
    const mark = a.outcome === 'confirmed' ? PASS : ['not_confirmed', 'failed', 'denied', 'rejected'].includes(a.outcome) ? FAIL : WAIT;
    line();
    line(`${mark} ${c.bold(`${a.type} → ${a.target}`)}  ${OUTCOME_LABELS[a.outcome]}${a.verified === false ? c.red('  (records did not verify)') : ''}`);
    for (const s of a.steps) {
      const label = s.phase.padEnd(12);
      line(`    ${c.dim(label)} ${s.text}`);
    }
    if (a.before !== undefined || a.after !== undefined) {
      line(`    ${c.dim('state before'.padEnd(12))} ${compact(a.before)}`);
      line(`    ${c.dim('state after'.padEnd(12))} ${compact(a.after)}`);
    }
    if (a.external) line(`    ${c.dim('adds to'.padEnd(12))} ${a.external.format} receipt ${a.external.id ?? ''} ${c.dim(a.external.digest.slice(0, 20) + '…')}`);
  }
}

function compact(value: unknown): string {
  return value === undefined ? c.dim('(not disclosed)') : JSON.stringify(value);
}
