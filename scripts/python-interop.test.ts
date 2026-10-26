import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { summarize, verifyBundle, parseBundle } from '@openactionrecord/core';
import { loadStandaloneVerifier } from '@openactionrecord/core/standalone';

// Records written by the Python writer must verify with the TypeScript and browser verifiers.
// Needs the Python package installed: pip install -e ./python

const root = fileURLToPath(new URL('..', import.meta.url));
const python = process.env.PYTHON ?? 'python3';

const script = `
import json, sys
from open_action_record import LocalSealer, Recorder, generate_signing_key
sealed = sys.argv[1] == "sealed"
oar = Recorder(issuer=generate_signing_key("py-issuer"), org="acme", agent="py-agent",
               sealer=LocalSealer(generate_signing_key("py-sealer")) if sealed else None)
order = {"order": "1142", "refundedCents": 0}
def refund():
    order["refundedCents"] += 190000
    return {"id": "re_py"}
oar.run(type="refund", target="stripe", params={"order": "1142", "amountCents": 190000, "note": "café ✓", "ratio": 0.1},
        check=lambda p: {"result": "held", "reasons": ["over_approval_limit"]},
        approve=lambda a: {"approver": "jordan", "approved": True},
        read_state=lambda: dict(order), execute=refund, target_ref=lambda r: r["id"], confirm=lambda r: True)
oar.run(type="discount", target="shop", params={"pct": 80}, check=lambda p: {"result": "denied"}, execute=lambda: 1)
print(json.dumps(oar.bundle(disclose="all")))
`;

function pythonBundle(sealed: boolean): unknown {
  return JSON.parse(execFileSync(python, ['-c', script, sealed ? 'sealed' : 'plain'], { cwd: root, encoding: 'utf8' }));
}

describe('records written in Python', () => {
  for (const sealed of [true, false]) {
    it(`verify in TypeScript and in the browser verifier (${sealed ? 'sealed' : 'issuer-signed'})`, async () => {
      const bundle = pythonBundle(sealed);
      const report = verifyBundle(bundle);
      expect(report.messages[0]).toMatch(/passed/);
      expect(report.result).toBe('pass');
      expect(report.level).toBe(sealed ? 'sealed' : 'issuer-signed');
      expect(report.receipts.every((r) => r.checks.disclosures !== 'fail')).toBe(true);
      const parsed = parseBundle(bundle);
      expect(summarize(parsed.records, parsed.disclosures, report).map((a) => a.outcome)).toEqual(['confirmed', 'denied']);
      const alt = await loadStandaloneVerifier()(bundle, webcrypto.subtle as never);
      expect(alt.result).toBe('pass');
      expect(alt.level).toBe(report.level);
    }, 30_000);
  }
});
