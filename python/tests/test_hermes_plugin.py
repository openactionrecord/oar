"""The Hermes plugin, without Hermes: hooks in, verifiable records out. (tests/hermes_integration.py runs it
against a real Hermes install.)"""

import json
import os
import subprocess
import sys

from open_action_record import outcomes, verify_bundle
from open_action_record import hermes as plugin


class FakeCtx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def common(**kw):
    base = dict(command="rm -rf /srv/data --token=s3cr3t", description="recursive delete", pattern_key="rm_rf",
                pattern_keys=["rm_rf"], session_key="slack:U123:C456", surface="gateway", turn_id="t", tool_call_id="c1")
    base.update(kw)
    return base


def test_register_and_record_every_outcome(tmp_path, monkeypatch):
    monkeypatch.setenv("OAR_HERMES_DIR", str(tmp_path))
    ctx = FakeCtx()
    plugin.register(ctx)
    assert set(ctx.hooks) == {"pre_approval_request", "post_approval_response", "post_tool_call"}
    pre, post, tool = ctx.hooks["pre_approval_request"], ctx.hooks["post_approval_response"], ctx.hooks["post_tool_call"]

    pre(**common())
    post(**common(), choice="session")
    tool(tool_name="terminal", args={"command": "x"}, result={"exit": 0}, session_id="s", tool_call_id="c1", status="success")
    pre(**common(tool_call_id="c2"))
    post(**common(tool_call_id="c2"), choice="smart_deny", decided_by="aux_llm")
    post(**common(tool_call_id="c3"), choice="notify_failed")  # no request seen first: still recorded
    tool(tool_name="terminal", args={}, result="boom", tool_call_id="c9", status="error")  # unrelated, not recorded by default

    text = (tmp_path / "records.jsonl").read_text()
    for secret in ("s3cr3t", "U123", "rm -rf"):
        assert secret not in text
    bundle = plugin.export(tmp_path)
    report = verify_bundle(bundle)
    assert report.result == "pass", report.messages
    assert outcomes(bundle) == ["executed_unconfirmed", "rejected", "expired"]
    approvals = [r["payload"] for r in bundle["records"] if r["payload"]["result"] in ("approved", "rejected", "expired")]
    assert [a["approval"]["approver"] for a in approvals] == ["gateway-user", "aux_llm", "gateway-user"]
    assert approvals[1]["approval"]["method"] == "standing_mandate"
    full = plugin.export(tmp_path, disclose=True)
    assert verify_bundle(full).result == "pass"
    assert any(d["value"]["params"]["command"].startswith("rm -rf") for d in full["disclosures"] if d["field"] == "instance")


def test_all_tools_mode_and_a_crash_never_reaches_hermes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OAR_HERMES_ALL_TOOLS", "1")
    rec = plugin.HermesRecorder(tmp_path)
    rec.on_tool_result(tool_name="read_file", args={"path": "/etc/hosts"}, result="...", tool_call_id="c1", status="success")
    rec.on_approval_response(**common(tool_call_id="cX"), choice="once")
    rec.on_approval_response(**common(tool_call_id="cX"), choice="once")  # duplicate: warned, not raised
    assert "could not record" in capsys.readouterr().err
    assert verify_bundle(plugin.export(tmp_path)).result == "pass"


def test_two_processes_keep_one_chain(tmp_path):
    script = (
        "import os, sys\n"
        "os.environ['OAR_HERMES_DIR'] = sys.argv[1]\n"
        "from open_action_record.hermes import HermesRecorder\n"
        "r = HermesRecorder()\n"
        "for i in range(15):\n"
        "    kw = dict(command=f'cmd {sys.argv[2]} {i}', description='d', pattern_key='p', pattern_keys=['p'],\n"
        "              session_key='s', surface='cli', turn_id='t', tool_call_id=f'{sys.argv[2]}-{i}')\n"
        "    r.on_approval_request(**kw)\n"
        "    r.on_approval_response(**kw, choice='deny')\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", script, str(tmp_path), name]) for name in ("a", "b", "c")]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    lines = (tmp_path / "records.jsonl").read_text().splitlines()
    assert len(lines) == 90
    report = verify_bundle(plugin.export(tmp_path))
    assert report.result == "pass", report.messages


def test_cli_where_and_export(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OAR_HERMES_DIR", str(tmp_path))
    assert plugin.main(["export"]) == 1
    rec = plugin.HermesRecorder()
    rec.on_approval_request(**common())
    rec.on_approval_response(**common(), choice="deny")
    capsys.readouterr()
    assert plugin.main(["export"]) == 0
    assert verify_bundle(json.loads(capsys.readouterr().out)).result == "pass"
