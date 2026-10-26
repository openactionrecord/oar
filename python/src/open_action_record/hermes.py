"""Hermes Agent plugin: a signed, tamper-evident Open Action Record for every approval decision.

Hermes asks for approval before dangerous commands, protected file writes, MCP elicitations and payments, on the
CLI, in messaging gateways, or through "smart" approval by an auxiliary LLM. This plugin records each one:

- a decision record when approval is requested ("held", with the matched pattern keys as reasons);
- an approval record with the outcome: approved (once, for the session, always), rejected, or expired
  (timeout, cancelled, notification failed), and whether a person or the LLM decided;
- an execution record when the approved tool call finishes, with its status.

Commands, descriptions and session keys are never written in clear: records carry salted commitments. The salts
and values stay in a separate local file (mode 600) so you can disclose them later, to the people who need them.

Install and enable:

    pip install open-action-record        # in the Python environment Hermes runs in
    hermes plugins enable oar

Files (in $HERMES_HOME/oar, default ~/.hermes/oar):

    records.jsonl        one signed record per line (safe to share)
    disclosures.jsonl    salts and values that open the commitments (private; mode 600)
    issuer-key.json      this installation's signing key (private; mode 600)

Export a bundle anyone can verify offline:

    python -m open_action_record.hermes export > approvals.json
    oar-verify approvals.json                          # or: npx @openactionrecord/cli verify approvals.json

Settings (environment variables):

    OAR_HERMES_DIR            where the files go (default $HERMES_HOME/oar)
    OAR_HERMES_ALL_TOOLS=1    also record every tool call that needed no approval (allowed + executed)
    OAR_HERMES_DISCLOSURES=0  do not keep salts and values (records still verify; values can never be disclosed)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

from .canonical import digest
from .keys import load_or_create_key

try:  # file lock, so several Hermes processes keep one chain
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
from .recorder import ActionHandle, Recorder, build_bundle

APPROVED = {"once": "approved_once", "session": "approved_for_session", "always": "approved_always", "smart_approve": "approved_by_llm"}
REJECTED = {"deny": "rejected_by_person", "smart_deny": "rejected_by_llm"}
EXPIRED = {"timeout": "approval_timeout", "cancelled": "approval_cancelled", "notify_failed": "approval_notify_failed"}


def _home() -> Path:
    explicit = os.environ.get("OAR_HERMES_DIR")
    if explicit:
        return Path(explicit).expanduser()
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home()) / "oar"
    except Exception:  # noqa: BLE001
        return Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser() / "oar"


def _pseudonym(value: str | None) -> str:
    """A stable, non-reversible label for a session key (which may contain chat or user identifiers)."""
    return "session:" + hashlib.sha256((value or "none").encode()).hexdigest()[:16]


def _action_type(surface: str) -> str:
    if surface.startswith("mcp-elicitation"):
        return "mcp.elicitation"
    if surface.startswith("mcp-trust"):
        return "mcp.trust"
    if surface == "vault-payment":
        return "payment"
    return "command"


class HermesRecorder:
    """Turns Hermes approval and tool hooks into Open Action Records, appended to local JSONL files."""

    def __init__(self, directory: Path | None = None):
        self.dir = directory or _home()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.records_path = self.dir / "records.jsonl"
        self.disclosures_path = self.dir / "disclosures.jsonl"
        self.keep_disclosures = os.environ.get("OAR_HERMES_DISCLOSURES", "1") != "0"
        self.all_tools = os.environ.get("OAR_HERMES_ALL_TOOLS", "0") == "1"
        self.key = load_or_create_key(str(self.dir / "issuer-key.json"), kid=f"hermes-{os.urandom(4).hex()}")
        self._lock = threading.Lock()
        self._pending: dict[str, ActionHandle] = {}
        self.recorder = Recorder(issuer=self.key, org="hermes", agent="hermes", last_record=_last_record(self.records_path),
                                 on_record=self._persist, policy={"approvals": "hermes"}, policy_id="hermes-approvals")

    def _locked(self):
        """Thread and process lock; continues the chain from the file's last record, which another process may have written."""
        recorder = self

        class _Guard:
            def __enter__(self_inner):
                recorder._lock.acquire()
                self_inner.fd = os.open(recorder.dir / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
                if fcntl is not None:
                    fcntl.flock(self_inner.fd, fcntl.LOCK_EX)
                recorder.recorder.continue_from(_last_record(recorder.records_path))

            def __exit__(self_inner, *exc):
                try:
                    if fcntl is not None:
                        fcntl.flock(self_inner.fd, fcntl.LOCK_UN)
                    os.close(self_inner.fd)
                finally:
                    recorder._lock.release()

        return _Guard()

    # ---- Hermes hooks (observers: they never raise into Hermes) ----

    def on_approval_request(self, command: str = "", description: str = "", pattern_key: str = "", pattern_keys: list | None = None,
                            session_key: str = "", surface: str = "cli", turn_id: Any = None, tool_call_id: Any = None, **_: Any) -> None:
        try:
            with self._locked():
                self._held(command, description, pattern_key, pattern_keys, session_key, surface, tool_call_id)
        except Exception as e:  # noqa: BLE001
            _warn(f"could not record an approval request: {e}")

    def on_approval_response(self, command: str = "", description: str = "", pattern_key: str = "", pattern_keys: list | None = None,
                             session_key: str = "", surface: str = "cli", turn_id: Any = None, tool_call_id: Any = None,
                             choice: str = "", decided_by: str | None = None, **_: Any) -> None:
        try:
            with self._locked():
                key = self._key(session_key, tool_call_id, command)
                handle = self._pending.get(key) or self._held(command, description, pattern_key, pattern_keys, session_key, surface, tool_call_id)
                run = _pseudonym(session_key)
                llm = decided_by == "aux_llm" or choice.startswith("smart_")
                approver = "aux_llm" if llm else f"{surface.split('/')[0]}-user"
                method = "standing_mandate" if llm else "button"
                if choice in APPROVED:
                    self.recorder.approve(handle, approver=approver, method=method, reasons=[APPROVED[choice]], run=run)
                    if tool_call_id is None:
                        self._pending.pop(key, None)  # nothing to match an execution to
                elif choice in REJECTED:
                    self.recorder.approve(handle, approver=approver, method=method, approved=False, reasons=[REJECTED[choice]], run=run)
                    self._pending.pop(key, None)
                else:
                    self.recorder.approve(handle, approver=approver, method=method, expired=True, reasons=[EXPIRED.get(choice, "approval_" + (choice or "unknown"))], run=run)
                    self._pending.pop(key, None)
        except Exception as e:  # noqa: BLE001
            _warn(f"could not record an approval decision: {e}")

    def on_tool_result(self, tool_name: str = "", args: Any = None, result: Any = None, session_id: Any = None, tool_call_id: Any = None,
                       status: str | None = None, error_type: str | None = None, duration_ms: Any = None, **kw: Any) -> None:
        try:
            with self._locked():
                handle = None
                if tool_call_id is not None:
                    for key, h in list(self._pending.items()):
                        if key.endswith(f"|{tool_call_id}") and h.status == "approved":
                            handle = self._pending.pop(key)
                            break
                ok = (status or "success") in ("success", "ok", "completed")
                outcome = {"status": status or "unknown", "error_type": error_type, "result_sha256": digest(result if _jsonable(result) else str(result))}
                run = _pseudonym(kw.get("session_key") or session_id)
                if handle is not None:
                    self.recorder.execute(handle, after=outcome, target_ref=str(tool_call_id), ok=ok, run=run)
                elif self.all_tools:
                    action = self.recorder.decide(type="tool", target=f"hermes.{tool_name or 'tool'}", params={"tool": tool_name, "args": args if _jsonable(args) else str(args)},
                                                  result="allowed", reasons=["no_approval_needed"], run=run)
                    self.recorder.execute(action, after=outcome, target_ref=str(tool_call_id) if tool_call_id is not None else None, ok=ok, run=run)
        except Exception as e:  # noqa: BLE001
            _warn(f"could not record a tool result: {e}")

    # ---- internals ----

    @staticmethod
    def _key(session_key: str, tool_call_id: Any, command: str) -> str:
        return f"{session_key}|{tool_call_id}" if tool_call_id is not None else f"{session_key}|cmd:{hashlib.sha256(command.encode()).hexdigest()}"

    def _held(self, command, description, pattern_key, pattern_keys, session_key, surface, tool_call_id) -> ActionHandle:
        keys = [k for k in (pattern_keys or ([pattern_key] if pattern_key else [])) if isinstance(k, str)]
        handle = self.recorder.decide(
            type=_action_type(surface or "cli"),
            target=f"hermes.{(surface or 'cli').split('/')[0]}",
            params={"command": command, "description": description, "pattern_keys": keys, "surface": surface, "tool_call_id": tool_call_id},
            result="held",
            reasons=["needs_approval", *[f"pattern:{k}" for k in keys]],
            run=_pseudonym(session_key),
        )
        self._pending[self._key(session_key, tool_call_id, command)] = handle
        return handle

    def _persist(self, record: dict, disclosures: list[dict]) -> None:
        with open(self.records_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
        if self.keep_disclosures and disclosures:
            new = not self.disclosures_path.exists()
            fd = os.open(self.disclosures_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                for d in disclosures:
                    f.write(json.dumps(d, separators=(",", ":"), ensure_ascii=False) + "\n")
            if new:
                os.chmod(self.disclosures_path, 0o600)


def _last_record(path: Path) -> dict | None:
    """The last record in a JSONL file, read from the end (files grow long)."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        chunk = b""
        pos = size
        while pos > 0:
            step = min(65536, pos)
            pos -= step
            f.seek(pos)
            chunk = f.read(step) + chunk
            lines = [line for line in chunk.split(b"\n") if line.strip()]
            if len(lines) >= 2 or pos == 0:
                return json.loads(lines[-1]) if lines else None
    return None


def _jsonable(value: Any) -> bool:
    try:
        json.dumps(value)
        return True
    except (TypeError, ValueError):
        return False


def _warn(message: str) -> None:
    print(f"[oar] {message}", file=sys.stderr)


_instance: HermesRecorder | None = None


def register(ctx: Any) -> None:
    """Hermes plugin entry point."""
    global _instance
    _instance = HermesRecorder()
    ctx.register_hook("pre_approval_request", _instance.on_approval_request)
    ctx.register_hook("post_approval_response", _instance.on_approval_response)
    ctx.register_hook("post_tool_call", _instance.on_tool_result)


def export(directory: Path | None = None, disclose: bool = False) -> dict:
    """A bundle of every recorded approval, ready to share and verify."""
    home = directory or _home()
    records = [json.loads(line) for line in (home / "records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    disclosures: list[dict] = []
    if disclose and (home / "disclosures.jsonl").exists():
        disclosures = [json.loads(line) for line in (home / "disclosures.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    from .keys import public_keys

    key = load_or_create_key(str(home / "issuer-key.json"), kid="unused")
    return build_bundle(records=records, keys={"issuer": public_keys(key)}, disclosures=disclosures, org="hermes",
                        org_name="Hermes Agent approvals", purpose="audit", complete=True)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m open_action_record.hermes", description="Open Action Records for Hermes approvals.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export", help="print a bundle of all recorded approvals")
    ex.add_argument("--disclose", action="store_true", help="include the commands and other values (private!)")
    sub.add_parser("where", help="print where the records are kept")
    args = parser.parse_args(argv)
    if args.cmd == "where":
        print(_home())
        return 0
    if not (_home() / "records.jsonl").exists():
        print(f"No records yet in {_home()}. Enable the plugin with: hermes plugins enable oar", file=sys.stderr)
        return 1
    print(json.dumps(export(disclose=args.disclose), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
