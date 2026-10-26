"""Write Open Action Records from Python: record what an agent's action did, step by step or around a function.

    oar = Recorder(issuer=generate_signing_key("my-agent"), org="acme", agent="support-bot")
    out = oar.run(type="refund", target="stripe", params={...}, read_state=..., execute=..., confirm=...)
    bundle = oar.bundle()

Values passed as params, usage, state and target references are never written in clear: each record carries a
salted commitment, and the recorder keeps the salts so you can disclose a value later. Records written here
verify with every OAR verifier (TypeScript, browser and Python).
"""

from __future__ import annotations

import inspect
import os
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Literal, TypeVar

from .canonical import digest
from .keys import SigningKey, public_keys, sign_canonical
from .sealer import SealingService
from .times import iso, iso_now, parse

OAR_VERSION = "0.3"
BUNDLE_FORMAT = "oar-bundle/0.1"
PAYLOAD_ORDER = (
    "aar_version", "receipt_id", "phase", "org_id", "agent_id", "run_id", "action", "instance_commitment",
    "authorization_ref", "principal", "approval", "consumption_commitment", "result", "reasons", "enforced",
    "decision_ref", "target_ref_commitment", "state_before_commitment", "state_after_commitment", "external_ref",
    "issued_at", "prev_receipt_hash",
)

T = TypeVar("T")
Decision = Literal["allowed", "held", "denied"]


def commitment_for(value: Any, salt: str) -> str:
    return digest({"salt": salt, "value": value})


def is_sha256_digest(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(c in "0123456789abcdef" for c in value[7:])


@dataclass
class ActionHandle:
    """One action. `id` is its decision record's id."""

    id: str
    type: str
    target: str
    instance_commitment: str
    last_record_id: str
    status: str
    principal: str = ""
    target_ref: str | None = None


@dataclass
class RunResult:
    status: Literal["completed", "denied", "held", "rejected"]
    action: ActionHandle
    result: Any = None
    confirmed: bool | None = None


@dataclass
class _Secret:
    receiptId: str
    field: str
    salt: str
    value: Any


class Recorder:
    """Writes signed records for one agent. Thread-safe: hooks may call it from several threads."""

    def __init__(
        self,
        *,
        issuer: SigningKey,
        org: str,
        agent: str,
        run: str | None = None,
        org_name: str | None = None,
        sealer: SealingService | None = None,
        policy: Any = None,
        policy_id: str = "default",
        last_record: dict | None = None,
        on_record: Callable[[dict, list[dict]], None] | None = None,
        now: Callable[[], str] | None = None,
        random_id: Callable[[], str] | None = None,
        random_salt: Callable[[], str] | None = None,
    ):
        """
        last_record: the agent's previous record, to continue its chain across restarts.
        on_record: called with (record, disclosures) after each record is written, to persist both.
        """
        if not issuer or not issuer.kid or not issuer.private_key:
            raise ValueError("issuer: expected a SigningKey")
        if not org or not agent:
            raise ValueError("org and agent are required")
        self._issuer = issuer
        self._org = org
        self._org_name = org_name or org
        self._agent = agent
        self._sealer = sealer
        self._now = now or iso_now
        self._random_id = random_id or (lambda: str(uuid.uuid4()))
        self._random_salt = random_salt or (lambda: os.urandom(32).hex())
        self._run = run or f"run:{self._random_id()}"
        self._authorization_ref = policy if is_sha256_digest(policy) else digest(policy if policy is not None else {"policy": "none"})
        self._policy_principal = f"policy:{policy_id}"
        self._on_record = on_record
        self._records: list[dict] = []
        self._secrets: list[_Secret] = []
        self._actions: dict[str, ActionHandle] = {}
        self._prev_hash: str | None = digest(last_record) if last_record else None
        self._last_issued = parse(last_record["payload"]["issued_at"]) if last_record else None
        self._lock = threading.RLock()

    # ---- public API ----

    def continue_from(self, last_record: dict | None) -> None:
        """Continue the agent's chain from `last_record` (for example, when another process wrote records too)."""
        with self._lock:
            self._prev_hash = digest(last_record) if last_record else None
            if last_record:
                t = parse(last_record["payload"]["issued_at"])
                if self._last_issued is None or t > self._last_issued:
                    self._last_issued = t

    @property
    def records(self) -> list[dict]:
        with self._lock:
            return list(self._records)

    def decide(
        self,
        *,
        type: str,
        target: str,
        params: dict,
        result: Decision,
        reasons: list[str] | None = None,
        idempotency_key: str | None = None,
        usage: Any = None,
        enforced: bool = True,
        external: dict | None = None,
        run: str | None = None,
    ) -> ActionHandle:
        """Records the decision on an action: "allowed", "held" (waits for a person) or "denied"."""
        if not type or not target:
            raise ValueError('type and target are required, for example type="refund", target="stripe"')
        if not isinstance(params, dict):
            raise ValueError("params: expected a dict")
        if result not in ("allowed", "held", "denied"):
            raise ValueError('result: "allowed", "held" or "denied"')
        with self._lock:
            rid = self._new_id()
            instance = self._commit(rid, "instance", {"type": type, "params": params, "idempotency_key": idempotency_key or rid})
            fields: dict[str, Any] = {
                "receipt_id": rid,
                "phase": "decision",
                "action": {"type": type, "target": target},
                "instance_commitment": instance,
                "principal": self._policy_principal,
                "result": result,
                "reasons": reasons or [{"allowed": "within_limits", "held": "needs_approval", "denied": "over_limit"}[result]],
                "enforced": enforced,
            }
            if result == "allowed":
                fields["approval"] = {"method": "standing_mandate", "at": self._stamp()}
            if usage is not None:
                fields["consumption_commitment"] = self._commit(rid, "consumption", usage)
            if external is not None:
                if not external.get("format") or not is_sha256_digest(external.get("digest")):
                    raise ValueError('external: expected {"format": ..., "digest": "sha256:<hex>"}')
                fields["external_ref"] = {k: external[k] for k in ("format", "digest", "id") if external.get(k)}
            self._write(fields, run)
            handle = ActionHandle(rid, type, target, instance, rid, result, self._policy_principal)
            self._actions[rid] = handle
            return handle

    def approve(
        self,
        action: ActionHandle,
        *,
        approver: str,
        approved: bool = True,
        method: Literal["button", "passkey", "standing_mandate"] | None = None,
        assertion: Any = None,
        reasons: list[str] | None = None,
        expired: bool = False,
        run: str | None = None,
    ) -> dict:
        """Records a decision on a held action. `approver` is a stable reference ("jordan"), never an email.
        Use method="standing_mandate" when software decided (for example an LLM classifier), not a person."""
        with self._lock:
            handle = self._handle(action)
            if handle.status != "held":
                raise ValueError(f"Only a held action can be approved or rejected (this one is {handle.status}).")
            if not approver or "@" in approver:
                raise ValueError('approver: a stable reference such as "jordan", not an email address')
            method = method or ("passkey" if assertion is not None else "button")
            rid = self._new_id()
            result = "expired" if expired else ("approved" if approved else "rejected")
            approval: dict[str, Any] = {"method": method, "approver": approver, "at": self._stamp()}
            if assertion is not None:
                approval["assertion_digest"] = digest(assertion)
            principal = f"approver:{approver}"
            record = self._write({
                "receipt_id": rid,
                "phase": "decision",
                "action": {"type": handle.type, "target": handle.target},
                "instance_commitment": handle.instance_commitment,
                "principal": principal,
                "approval": approval,
                "result": result,
                "reasons": reasons or [{"approved": "approved_by_person", "rejected": "rejected_by_person", "expired": "approval_expired"}[result]],
                "enforced": True,
                "decision_ref": handle.last_record_id,
            }, run)
            handle.principal = principal
            handle.last_record_id = rid
            handle.status = result
            return record

    def execute(
        self,
        action: ActionHandle,
        *,
        before: Any = None,
        after: Any = None,
        target_ref: str | None = None,
        ok: bool = True,
        reasons: list[str] | None = None,
        run: str | None = None,
    ) -> dict:
        """Records the execution, with commitments to the affected state before and after."""
        with self._lock:
            handle = self._handle(action)
            if handle.status not in ("allowed", "approved"):
                raise ValueError(f"Only an allowed or approved action can be executed (this one is {handle.status}).")
            rid = self._new_id()
            fields: dict[str, Any] = {
                "receipt_id": rid,
                "phase": "execution",
                "action": {"type": handle.type, "target": handle.target},
                "instance_commitment": handle.instance_commitment,
                "principal": handle.principal,
                "result": "executed" if ok else "failed",
                "reasons": reasons or ["executed" if ok else "execution_failed"],
                "enforced": True,
                "decision_ref": handle.last_record_id,
            }
            if target_ref is not None:
                fields["target_ref_commitment"] = self._commit(rid, "target_ref", target_ref)
                handle.target_ref = target_ref
            if before is not None:
                fields["state_before_commitment"] = self._commit(rid, "state_before", before)
            if after is not None:
                fields["state_after_commitment"] = self._commit(rid, "state_after", after)
            record = self._write(fields, run)
            handle.last_record_id = rid
            handle.status = "executed" if ok else "failed"
            return record

    def confirm(
        self,
        action: ActionHandle,
        *,
        confirmed: bool,
        reason: Literal["outcome_confirmed", "outcome_missing", "outcome_mismatch"] | None = None,
        target_ref: str | None = None,
        run: str | None = None,
    ) -> dict:
        """Records whether the system of record, read back after the change, shows it."""
        with self._lock:
            handle = self._handle(action)
            if handle.status != "executed":
                raise ValueError(f"Only an executed action can be confirmed (this one is {handle.status}).")
            rid = self._new_id()
            fields: dict[str, Any] = {
                "receipt_id": rid,
                "phase": "confirmation",
                "action": {"type": handle.type, "target": handle.target},
                "instance_commitment": handle.instance_commitment,
                "principal": handle.principal,
                "result": "confirmed" if confirmed else "not_confirmed",
                "reasons": [reason or ("outcome_confirmed" if confirmed else "outcome_missing")],
                "enforced": True,
                "decision_ref": handle.last_record_id,
            }
            ref = target_ref if target_ref is not None else handle.target_ref
            if ref is not None:
                fields["target_ref_commitment"] = self._commit(rid, "target_ref", ref)
            record = self._write(fields, run)
            handle.last_record_id = rid
            handle.status = "confirmed" if confirmed else "not_confirmed"
            return record

    def run(
        self,
        *,
        type: str,
        target: str,
        params: dict,
        execute: Callable[[], T],
        check: Callable[[dict], dict] | None = None,
        approve: Callable[[ActionHandle], dict] | None = None,
        read_state: Callable[[], Any] | None = None,
        target_ref: Callable[[T], str | None] | None = None,
        confirm: Callable[[T], bool] | None = None,
        idempotency_key: str | None = None,
        usage: Any = None,
        external: dict | None = None,
    ) -> RunResult:
        """Wraps one action: check, optional approval, state before, execute, state after, confirmation.
        Every step is recorded. Errors from `execute` are recorded as a failed execution, then re-raised."""
        verdict = check(params) if check else {"result": "allowed"}
        action = self.decide(type=type, target=target, params=params, result=verdict["result"], reasons=verdict.get("reasons"),
                             idempotency_key=idempotency_key, usage=usage, external=external)
        if verdict["result"] == "denied":
            return RunResult("denied", action)
        if verdict["result"] == "held":
            if approve is None:
                return RunResult("held", action)
            answer = approve(action)
            self.approve(action, **answer)
            if answer.get("approved") is False:
                return RunResult("rejected", action)
        before = read_state() if read_state else None
        try:
            result = execute()
        except Exception:
            after = _safely(read_state) if read_state else None
            self.execute(action, before=before, after=after, ok=False)
            raise
        after = read_state() if read_state else None
        ref = target_ref(result) if target_ref else None
        self.execute(action, before=before, after=after, target_ref=ref)
        if confirm is None:
            return RunResult("completed", action, result)
        confirmed = bool(confirm(result))
        self.confirm(action, confirmed=confirmed)
        return RunResult("completed", action, result, confirmed)

    async def run_async(
        self,
        *,
        type: str,
        target: str,
        params: dict,
        execute: Callable[[], Awaitable[T] | T],
        check: Callable[[dict], Any] | None = None,
        approve: Callable[[ActionHandle], Any] | None = None,
        read_state: Callable[[], Any] | None = None,
        target_ref: Callable[[T], str | None] | None = None,
        confirm: Callable[[T], Any] | None = None,
        idempotency_key: str | None = None,
        usage: Any = None,
        external: dict | None = None,
    ) -> RunResult:
        """The same as `run`, for async agents: any callback may be async."""
        verdict = await _maybe(check(params)) if check else {"result": "allowed"}
        action = self.decide(type=type, target=target, params=params, result=verdict["result"], reasons=verdict.get("reasons"),
                             idempotency_key=idempotency_key, usage=usage, external=external)
        if verdict["result"] == "denied":
            return RunResult("denied", action)
        if verdict["result"] == "held":
            if approve is None:
                return RunResult("held", action)
            answer = await _maybe(approve(action))
            self.approve(action, **answer)
            if answer.get("approved") is False:
                return RunResult("rejected", action)
        before = await _maybe(read_state()) if read_state else None
        try:
            result = await _maybe(execute())
        except Exception:
            after = None
            if read_state:
                try:
                    after = await _maybe(read_state())
                except Exception:  # noqa: BLE001
                    after = None
            self.execute(action, before=before, after=after, ok=False)
            raise
        after = await _maybe(read_state()) if read_state else None
        ref = target_ref(result) if target_ref else None
        self.execute(action, before=before, after=after, target_ref=ref)
        if confirm is None:
            return RunResult("completed", action, result)
        confirmed = bool(await _maybe(confirm(result)))
        self.confirm(action, confirmed=confirmed)
        return RunResult("completed", action, result, confirmed)

    def keys(self) -> dict:
        out: dict[str, Any] = {"issuer": public_keys(self._issuer)}
        if self._sealer is not None:
            out["sealer"] = self._sealer.keys()
        return out

    def bundle(self, *, disclose: str | Iterable[str] = "none", purpose: str | None = None) -> dict:
        """A self-contained evidence bundle. Discloses nothing by default; disclose="all" for your own debugging."""
        with self._lock:
            records = [dict(r) for r in self._records]
            ids = {r["payload"]["receipt_id"] for r in records}
            if disclose == "none":
                secrets: list[_Secret] = []
            elif disclose == "all":
                secrets = [s for s in self._secrets if s.receiptId in ids]
            else:
                wanted = set(disclose)
                secrets = [s for s in self._secrets if s.receiptId in ids and s.field in wanted]
            return build_bundle(
                records=records,
                disclosures=[s.__dict__ for s in secrets],
                keys=self.keys(),
                checkpoints=self._sealer.checkpoints() if self._sealer else [],
                org=self._org,
                org_name=self._org_name,
                purpose=purpose,
                complete=self._prev_hash_at_start_is_none() and _covers_all(records, self._sealer.checkpoints() if self._sealer else []),
                generated_at=self._now(),
            )

    # ---- internals ----

    def _prev_hash_at_start_is_none(self) -> bool:
        return not self._records or "prev_receipt_hash" not in self._records[0]["payload"]

    def _handle(self, action: ActionHandle) -> ActionHandle:
        handle = self._actions.get(action.id)
        if handle is None:
            raise ValueError(f"Unknown action {action.id}: it was not recorded by this recorder.")
        return handle

    def _new_id(self) -> str:
        return f"urn:uuid:{self._random_id()}"

    def _stamp(self) -> str:
        """Strictly increasing timestamps, so records sort in the order they were written."""
        t = parse(self._now())
        if self._last_issued is not None and t <= self._last_issued:
            from datetime import timedelta

            t = self._last_issued + timedelta(milliseconds=1)
        self._last_issued = t
        return iso(t)

    def _commit(self, receipt_id: str, field_name: str, value: Any) -> str:
        salt = self._random_salt()
        self._secrets.append(_Secret(receipt_id, field_name, salt, value))
        return commitment_for(value, salt)

    def _write(self, fields: dict[str, Any], run: str | None) -> dict:
        payload: dict[str, Any] = {
            "aar_version": OAR_VERSION,
            **fields,
            "org_id": self._org,
            "agent_id": self._agent,
            "run_id": run or self._run,
            "authorization_ref": self._authorization_ref,
            "issued_at": fields.get("approval", {}).get("at") or self._stamp(),
        }
        if self._prev_hash:
            payload["prev_receipt_hash"] = self._prev_hash
        payload = {k: payload[k] for k in PAYLOAD_ORDER if k in payload}
        record: dict[str, Any] = {"payload": payload, "issuer_sig": {"alg": "EdDSA", "kid": self._issuer.kid, "sig": sign_canonical(payload, self._issuer)}}
        if self._sealer is not None:
            record["seal"] = self._sealer.seal(digest(payload))
        self._records.append(record)
        self._prev_hash = digest(record)
        if self._on_record is not None:
            mine = [s.__dict__ for s in self._secrets if s.receiptId == payload["receipt_id"]]
            self._on_record(record, mine)
        return record


def build_bundle(
    *,
    records: list[dict],
    keys: dict,
    disclosures: list[dict] | None = None,
    checkpoints: list[dict] | None = None,
    org: str = "unknown",
    org_name: str | None = None,
    purpose: str | None = None,
    complete: bool = False,
    generated_at: str | None = None,
) -> dict:
    """Assembles a bundle from records you stored (for example, read back from a JSONL file)."""
    times = sorted(r["payload"]["issued_at"] for r in records)
    scope: dict[str, Any] = {"complete": complete}
    if times:
        scope["from"], scope["to"] = times[0], times[-1]
    bundle: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "generated_at": generated_at or iso_now(),
        "org": {"id": org, "name": org_name or org},
        "scope": scope,
        "records": records,
        "disclosures": disclosures or [],
        "checkpoints": checkpoints or [],
        "keys": keys,
    }
    if purpose:
        bundle["purpose"] = purpose
    return bundle


def _covers_all(records: list[dict], checkpoints: list[dict]) -> bool:
    latest = max((c["count"] for c in checkpoints), default=0)
    sealed = {r["seal"]["seq"] for r in records if r.get("seal")}
    return all(s in sealed for s in range(1, latest + 1))


def _safely(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return None


async def _maybe(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value
