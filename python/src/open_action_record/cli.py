"""oar-verify: verify an Open Action Record bundle from the command line."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__
from .verify import BundleError, outcomes, verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oar-verify", description="Verify an Open Action Record bundle.")
    parser.add_argument("bundle", help="path to the bundle (.json)")
    parser.add_argument("--keys", help='keys you trust: { "issuer": JWKS, "sealer": JWKS }')
    parser.add_argument("--tsa-roots", help="timestamp-authority roots to accept instead of the bundled DigiCert roots")
    parser.add_argument("--require-seal", action="store_true", help="fail records not countersigned by a separate sealing service")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        with open(args.bundle, encoding="utf-8") as f:
            bundle = json.load(f)
        keys = json.load(open(args.keys, encoding="utf-8")) if args.keys else None
        roots = json.load(open(args.tsa_roots, encoding="utf-8")) if args.tsa_roots else None
        report = verify_bundle(bundle, keys=keys, tsa_roots=roots, require_seal=args.require_seal)
    except (OSError, json.JSONDecodeError, BundleError) as e:
        print(str(e), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"report": asdict(report), "outcomes": outcomes(bundle)}, indent=2))
    else:
        mark = "✔" if report.result == "pass" else "✘"
        print(f"{mark} {report.messages[0]}")
        for m in report.messages[1:]:
            print(f"  {m}")
        for r in report.records:
            if r.result == "fail":
                failed = ", ".join(k for k, v in r.checks.items() if v == "fail")
                print(f"  ✘ {r.receipt_id[9:17]} {r.phase} {r.outcome}: {failed} failed")
        print("  Outcomes: " + ", ".join(outcomes(bundle)))
    return 0 if report.result == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
