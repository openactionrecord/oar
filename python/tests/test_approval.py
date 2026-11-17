"""Approval binding (SPEC.md section 4.3) written in Python and checked by the Python verifier."""

from open_action_record import LocalSealer, Recorder, check_approval, generate_signing_key, verify_bundle


def _recorder() -> Recorder:
    return Recorder(issuer=generate_signing_key("py-issuer"), org="demo-bank", agent="payments-agent", sealer=LocalSealer(generate_signing_key("py-sealer")))


def test_outside_approval_is_bound_and_verifies() -> None:
    oar = _recorder()
    action = oar.decide(type="wire_transfer", target="core-banking", params={"payee": "P-1002", "amountCents": 4_800_000}, result="held")
    request = oar.request_approval(action, display={"text": "Pay $48,000.00 to payee P-1002"})
    record = oar.approve(action, approver="treasury-lead", evidence={"provider": "sim-check", "format": "provider-json", "proof": '{"ok":true}'})
    approval = record["payload"]["approval"]
    assert approval["method"] == "external" and approval["binding"]["digest"] == request["binding"]
    assert check_approval(record["payload"]) == []
    report = verify_bundle(oar.bundle(disclose="all"))
    assert report.result == "pass"
    assert {r.checks["approval"] for r in report.records} == {"pass", "not_checked"}


def test_signed_rejection_recorded_as_approved_fails() -> None:
    oar = _recorder()
    action = oar.decide(type="payout", target="payments", params={"amountCents": 100}, result="held")
    oar.request_approval(action, decision="reject")
    record = oar.approve(action, approver="ops", approved=False)
    payload = dict(record["payload"], result="approved")
    assert "The approver signed a rejection, but the record says otherwise." in (check_approval(payload) or [])


def test_outside_approval_needs_a_request() -> None:
    oar = _recorder()
    action = oar.decide(type="payout", target="payments", params={"amountCents": 100}, result="held")
    try:
        oar.approve(action, approver="ops", evidence={"provider": "sim-check", "format": "provider-json", "proof": "{}"})
    except ValueError as e:
        assert "request_approval" in str(e)
    else:
        raise AssertionError("expected a ValueError")
