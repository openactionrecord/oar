"""End-to-end check against a real Hermes Agent install (not part of the default test run).

    pip install -e ./python   # into the environment Hermes is installed in
    python python/tests/hermes_integration.py

It enables the plugin the way a user would (plugins.enabled in config.yaml), lets Hermes discover and load it,
drives Hermes's real approval code (approve once, deny, time out, smart approval), sends a tool result, then
exports a bundle and verifies it.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

home = Path(tempfile.mkdtemp(prefix="hermes-home-"))
os.environ["HERMES_HOME"] = str(home)
os.environ.pop("OAR_HERMES_DIR", None)
(home / "config.yaml").write_text("plugins:\n  enabled:\n    - oar\n", encoding="utf-8")
if os.environ.get("OAR_PLUGIN_MODE") == "directory":  # as `hermes plugins install .../integrations/hermes` lays it out
    import shutil

    shutil.copytree(Path(__file__).resolve().parents[2] / "integrations" / "hermes", home / "plugins" / "oar")

import hermes_cli.plugins as plugins  # noqa: E402
from tools import approval_context  # noqa: E402
from tools.approval import check_all_command_guards  # noqa: E402
from tools.approval_context import set_current_session_key  # noqa: E402

plugins.discover_plugins(force=True)
info = [p for p in plugins.get_plugin_manager().list_plugins() if p["name"] == "oar"]
assert info, "Hermes did not discover the oar plugin"
print("plugin:", {k: info[0][k] for k in ("name", "source", "enabled", "hooks", "error")})
if os.environ.get("OAR_PLUGIN_MODE") == "directory":
    assert info[0]["source"] == "user", info[0]
assert info[0]["enabled"] and not info[0]["error"], info[0]
assert info[0]["hooks"] == 3, info[0]

set_current_session_key("telegram:123456789")  # contains a chat id: must not appear in records
os.environ["HERMES_SESSION_KEY"] = "telegram:123456789"
os.environ["HERMES_INTERACTIVE"] = "1"
os.environ.pop("HERMES_GATEWAY_SESSION", None)
os.environ.pop("HERMES_YOLO_MODE", None)
approval_context._get_approval_mode = lambda: "manual"  # always ask

answers = iter(["once", "deny", "timeout"])
cb = lambda command, description, *, allow_permanent=True: next(answers)  # noqa: E731
r1 = check_all_command_guards("rm -rf /tmp/oar-hermes-test --secret-token=abc123", "local", approval_callback=cb)
r2 = check_all_command_guards("rm -rf /tmp/oar-denied", "local", approval_callback=cb)
r3 = check_all_command_guards("rm -rf /tmp/oar-timeout", "local", approval_callback=cb)
print("hermes results:", r1.get("approved"), r2.get("approved"), r3.get("approved"))

# A smart (LLM) approval with a tool call id, then that tool call finishing.
common = dict(command="git push --force", description="force push", pattern_key="force_push", pattern_keys=["force_push"],
              session_key="telegram:123456789", surface="smart", turn_id="t1", tool_call_id="call_42")
plugins.invoke_hook("pre_approval_request", **common)
plugins.invoke_hook("post_approval_response", **common, choice="smart_approve", decided_by="aux_llm")
plugins.invoke_hook("post_tool_call", tool_name="terminal", args={"command": "git push --force"}, result="Everything up-to-date",
                    session_id="s1", tool_call_id="call_42", status="success", duration_ms=12)

from open_action_record import outcomes, verify_bundle  # noqa: E402
from open_action_record.hermes import export  # noqa: E402

oar_dir = home / "oar"
lines = (oar_dir / "records.jsonl").read_text().splitlines()
print("records written:", len(lines))
text = "\n".join(lines)
for secret in ("abc123", "123456789", "rm -rf", "git push"):
    assert secret not in text, f"{secret!r} leaked into records"
assert oct(os.stat(oar_dir / "disclosures.jsonl").st_mode & 0o777) == "0o600"
assert oct(os.stat(oar_dir / "issuer-key.json").st_mode & 0o777) == "0o600"

bundle = export(oar_dir)
report = verify_bundle(bundle)
print("verify:", report.result, report.level, report.messages[0])
print("outcomes:", outcomes(bundle))
assert report.result == "pass", report.messages
summary = [(r["payload"]["phase"], r["payload"]["result"], r["payload"]["reasons"]) for r in bundle["records"]]
for row in summary:
    print("  ", row)
assert outcomes(bundle) == ["approved_not_executed", "rejected", "expired", "executed_unconfirmed"], outcomes(bundle)

full = export(oar_dir, disclose=True)
assert verify_bundle(full).result == "pass"
(Path(tempfile.gettempdir()) / "hermes-oar-bundle.json").write_text(json.dumps(bundle))
print("OK: Hermes approvals recorded as verifiable Open Action Records")
sys.exit(0)
