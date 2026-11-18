"""Authority set and the re-check at commit (SPEC.md section 4.5), written in Python and checked by the Python verifier."""

import pytest

from open_action_record import LocalSealer, Recorder, generate_signing_key, verify_bundle

TOKEN = {"type": "aauth", "issuer": "https://auth.example", "artifact": "eyJhbGciOiJFZERTQSJ9.payload.sig", "expires_at": "2099-01-01T00:00:00Z"}


def _recorder() -> Recorder:
    return Recorder(issuer=generate_signing_key("py-issuer"), org="demo-bank", agent="payments-agent", sealer=LocalSealer(generate_signing_key("py-sealer")))


def test_current_authority_runs_and_verifies() -> None:
    oar = _recorder()
    action = oar.decide(type="payout", target="payments", params={"amountCents": 50_000}, result="allowed", authorities=[TOKEN])
    record = oar.execute(action, authority_check=["valid"])
    assert record["payload"]["result"] == "executed" and record["payload"]["authority_check"]["result"] == "current"
    oar.confirm(action, confirmed=True)
    report = verify_bundle(oar.bundle(disclose="all"))
    assert report.result == "pass"
    assert {r.checks["authority"] for r in report.records} == {"pass", "not_checked"}


def test_revoked_authority_is_refused_and_verifies() -> None:
    oar = _recorder()
    action = oar.decide(type="payout", target="payments", params={"amountCents": 50_000}, result="allowed", authorities=[TOKEN])
    record = oar.execute(action, authority_check=["revoked"])
    assert record["payload"]["result"] == "refused" and record["payload"]["reasons"] == ["authority_revoked"]
    assert verify_bundle(oar.bundle()).result == "pass"


def test_execute_needs_the_recheck() -> None:
    oar = _recorder()
    action = oar.decide(type="payout", target="payments", params={"amountCents": 1}, result="allowed", authorities=[TOKEN])
    with pytest.raises(ValueError, match="authority_check"):
        oar.execute(action)
