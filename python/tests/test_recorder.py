"""The Python writer: every path is recorded, records verify, and nothing sensitive is written in clear."""

import asyncio
import json

import pytest

from open_action_record import LocalSealer, Recorder, build_bundle, generate_signing_key, outcomes, verify_bundle


def store():
    order = {"order": "1142", "totalCents": 190000, "refundedCents": 0}

    def refund(cents):
        order["refundedCents"] += cents
        return {"id": "re_123", "status": "succeeded"}

    return order, refund


def recorder(sealed=True, **kw):
    sealer = LocalSealer(generate_signing_key("shop-sealer-1")) if sealed else None
    return Recorder(issuer=generate_signing_key("shop-issuer-1"), org="maple-and-pine", agent="rex", sealer=sealer, **kw)


def test_refund_end_to_end_verifies_and_hides_values():
    oar = recorder()
    order, refund = store()
    out = oar.run(
        type="refund", target="stripe", params={"order": "1142", "amountCents": 190000},
        check=lambda p: {"result": "held", "reasons": ["over_approval_limit"]} if p["amountCents"] > 125000 else {"result": "allowed"},
        approve=lambda a: {"approver": "jordan", "approved": True},
        read_state=lambda: dict(order), execute=lambda: refund(190000),
        target_ref=lambda r: r["id"], confirm=lambda r: r["status"] == "succeeded",
    )
    assert out.status == "completed" and out.confirmed is True
    assert [f"{r['payload']['phase']}:{r['payload']['result']}" for r in oar.records] == [
        "decision:held", "decision:approved", "execution:executed", "confirmation:confirmed"]
    text = json.dumps(oar.records)
    assert '"re_123"' not in text and '"1142"' not in text and ":190000" not in text
    bundle = oar.bundle()
    report = verify_bundle(bundle)
    assert report.result == "pass", report.messages
    assert report.level == "sealed"
    assert outcomes(bundle) == ["confirmed"]


def test_disclosures_open_the_commitments_and_edits_fail():
    oar = recorder()
    order, refund = store()
    oar.run(type="refund", target="stripe", params={"amountCents": 5000}, read_state=lambda: dict(order), execute=lambda: refund(5000))
    bundle = oar.bundle(disclose="all")
    assert verify_bundle(bundle).result == "pass"
    after = next(d for d in bundle["disclosures"] if d["field"] == "state_after")
    after["value"]["refundedCents"] = 1
    report = verify_bundle(bundle)
    assert report.result == "fail" and "disclosures" in report.failed_checks


def test_every_path_is_recorded():
    oar = recorder(sealed=False)
    assert oar.run(type="discount", target="shop", params={"pct": 80}, check=lambda p: {"result": "denied"}, execute=lambda: 1).status == "denied"
    assert oar.run(type="refund", target="stripe", params={}, check=lambda p: {"result": "held"},
                   approve=lambda a: {"approver": "jordan", "approved": False}, execute=lambda: 1).status == "rejected"
    held = oar.run(type="refund", target="stripe", params={"n": 2}, check=lambda p: {"result": "held"}, execute=lambda: 1)
    assert held.status == "held"
    with pytest.raises(RuntimeError):
        oar.run(type="refund", target="stripe", params={"n": 3}, execute=lambda: (_ for _ in ()).throw(RuntimeError("declined")))
    ghost = oar.run(type="refund", target="stripe", params={"n": 4}, execute=lambda: {"id": "re_x"}, confirm=lambda r: False)
    assert ghost.confirmed is False
    bundle = oar.bundle()
    report = verify_bundle(bundle)
    assert report.result == "pass" and report.level == "issuer-signed"
    assert outcomes(bundle) == ["denied", "rejected", "awaiting_approval", "failed", "not_confirmed"]


def test_steps_out_of_order_and_email_approvers_are_refused():
    oar = recorder()
    a = oar.decide(type="refund", target="stripe", params={}, result="denied")
    with pytest.raises(ValueError, match="allowed or approved"):
        oar.execute(a)
    b = oar.decide(type="refund", target="stripe", params={}, result="held")
    with pytest.raises(ValueError, match="not an email"):
        oar.approve(b, approver="jordan@example.com")


def test_automated_approver_is_recorded_as_standing_mandate():
    oar = recorder()
    a = oar.decide(type="shell", target="cli", params={"cmd": "rm -rf /tmp/x"}, result="held")
    rec = oar.approve(a, approver="aux_llm", method="standing_mandate", reasons=["approved_by_llm"])
    assert rec["payload"]["approval"]["method"] == "standing_mandate"
    assert verify_bundle(oar.bundle()).result == "pass"


def test_async_run():
    oar = recorder()

    async def execute():
        return {"id": "re_async"}

    async def confirm(r):
        return True

    out = asyncio.run(oar.run_async(type="refund", target="stripe", params={"a": 1}, execute=execute, target_ref=lambda r: r["id"], confirm=confirm))
    assert out.confirmed is True
    assert verify_bundle(oar.bundle()).result == "pass"


def test_chain_continues_across_restarts_and_a_removed_record_breaks_it(tmp_path):
    issuer = generate_signing_key("k")
    stored: list[dict] = []
    first = Recorder(issuer=issuer, org="o", agent="a", on_record=lambda r, d: stored.append(r))
    first.run(type="x", target="y", params={"i": 1}, execute=lambda: 1)
    second = Recorder(issuer=issuer, org="o", agent="a", last_record=stored[-1], on_record=lambda r, d: stored.append(r))
    second.run(type="x", target="y", params={"i": 2}, execute=lambda: 2)
    keys = {"issuer": {"keys": first.keys()["issuer"]["keys"]}}
    bundle = build_bundle(records=stored, keys=keys, complete=True)
    assert verify_bundle(bundle).result == "pass"
    broken = build_bundle(records=stored[:1] + stored[2:], keys=keys, complete=True)
    report = verify_bundle(broken)
    assert report.result == "fail" and "chain" in report.failed_checks


def test_external_ref():
    oar = recorder()
    oar.run(type="refund", target="stripe", params={}, external={"format": "acta", "digest": "sha256:" + "a" * 64, "id": "r-1"}, execute=lambda: 1)
    assert oar.records[0]["payload"]["external_ref"] == {"format": "acta", "digest": "sha256:" + "a" * 64, "id": "r-1"}
    with pytest.raises(ValueError):
        oar.decide(type="x", target="y", params={}, result="allowed", external={"format": "acta", "digest": "nope"})


def test_private_key_is_never_printed():
    key = generate_signing_key("k")
    assert key.private_key not in repr(key)
