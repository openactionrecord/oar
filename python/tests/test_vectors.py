"""The Python verifier must reach the expected result on every shared test vector."""

import json
from pathlib import Path

import pytest

from open_action_record import outcomes, verify_bundle

ROOT = Path(__file__).resolve().parents[2] / "vectors"
CASES = []
for folder in (ROOT, ROOT / "compat"):
    manifest = json.loads((folder / "manifest.json").read_text())
    roots = json.loads((folder / manifest["tsa_roots_file"]).read_text())
    for case in manifest["cases"]:
        CASES.append(pytest.param(folder, roots, case, id=f"{folder.name}/{case['file']}{'+require_seal' if case['options'].get('require_seal') else ''}"))


@pytest.mark.parametrize("folder,roots,case", CASES)
def test_vector(folder, roots, case):
    bundle = json.loads((folder / case["file"]).read_text())
    report = verify_bundle(
        bundle,
        tsa_roots=roots if case["options"].get("tsa_roots") == "test" else None,
        require_seal=bool(case["options"].get("require_seal")),
    )
    expect = case["expect"]
    assert report.result == expect["result"], report.messages
    if "level" in expect:
        assert report.level == expect["level"]
    if "failedChecks" in expect:
        assert sorted(report.failed_checks) == sorted(expect["failedChecks"])
    if "outcomes" in expect:
        assert outcomes(bundle) == expect["outcomes"]


def test_untrusted_timestamp_root_fails():
    bundle = json.loads((ROOT / "refund-lifecycle.json").read_text())
    report = verify_bundle(bundle)  # bundled DigiCert roots: the test authority is not trusted
    assert report.result == "fail"
    assert "timestamp" in report.failed_checks


def test_substituted_keys_fail():
    bundle = json.loads((ROOT / "issuer-signed.json").read_text())
    other = {"issuer": {"keys": [{**bundle["keys"]["issuer"]["keys"][0], "x": "A" * 43}]}}
    assert verify_bundle(bundle, keys=other).result == "fail"
