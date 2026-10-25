"""Verifies an Open Action Record bundle: issuer signatures, seals, chains, checkpoint coverage, outside
timestamps and disclosures. Mirrors the TypeScript reference verifier and reaches the same result on the
shared test vectors (vectors/ in the repository)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .canonical import digest, signature_ok
from .timestamp import TimestampResult, anchor_digest, verify_timestamp_token

CHECKS = ("issuer_signature", "seal", "chain", "checkpoint", "disclosures", "timestamp")
LABELS = {
    "issuer_signature": "Issuer signature",
    "seal": "Seal",
    "chain": "Chain",
    "checkpoint": "Checkpoint coverage",
    "disclosures": "Disclosures",
    "timestamp": "Outside timestamp",
}
LEVELS = ("issuer-signed", "sealed", "timestamped")
LEVEL_LABELS = {
    "issuer-signed": "Issuer-signed",
    "sealed": "Sealed by a separate service",
    "timestamped": "Sealed and timestamped by an outside authority",
}
FIELDS = {
    "instance": "instance_commitment",
    "consumption": "consumption_commitment",
    "target_ref": "target_ref_commitment",
    "state_before": "state_before_commitment",
    "state_after": "state_after_commitment",
}
FORMATS = ("oar-bundle/0.1", "aar-evidence/0.1")


class BundleError(ValueError):
    """The input is not a bundle this verifier can read."""


@dataclass
class RecordReport:
    receipt_id: str
    agent_id: str
    phase: str
    outcome: str
    checks: dict[str, str]
    result: str = "pass"
    level: str = "issuer-signed"
    messages: list[str] = field(default_factory=list)


@dataclass
class Report:
    result: str
    level: str
    records: list[RecordReport]
    failed_checks: list[str]
    messages: list[str]
    checkpoint: dict | None = None
    timestamp: dict | None = None


@dataclass
class _Entry:
    record: dict
    report: RecordReport
    seal_valid: bool


def parse_bundle(bundle: Any) -> dict:
    if not isinstance(bundle, dict):
        raise BundleError("Not a bundle: expected a JSON object.")
    problems = []
    if bundle.get("format") not in FORMATS:
        problems.append(f'format: expected "oar-bundle/0.1", got {bundle.get("format")!r}')
    records = bundle.get("records", bundle.get("receipts"))
    if not isinstance(records, list) or not all(isinstance(r, dict) and "payload" in r and "issuer_sig" in r for r in records):
        problems.append("records: expected an array of { payload, issuer_sig, seal? }")
    keys = bundle.get("keys") or {}
    if not isinstance(keys.get("issuer"), dict) or not isinstance(keys["issuer"].get("keys"), list):
        problems.append('keys.issuer: expected a JWK set ({ "keys": [...] })')
    if problems:
        raise BundleError("Not a valid bundle:\n- " + "\n- ".join(problems))
    return {
        **bundle,
        "records": records,
        "disclosures": bundle.get("disclosures") or [],
        "checkpoints": bundle.get("checkpoints") or [],
        "scope": bundle.get("scope") or {"complete": False},
    }


def verify_bundle(bundle: Any, *, keys: dict | None = None, tsa_roots: list[dict] | None = None, require_seal: bool = False) -> Report:
    """Verifies a bundle. Pass `keys` you obtained independently to rule out a substituted bundle."""
    b = parse_bundle(bundle)
    use_keys = keys or b["keys"]
    issuer_keys = use_keys.get("issuer")
    sealer_keys = use_keys.get("sealer") or {"keys": []}
    partial = not bool(b["scope"].get("complete"))
    messages: list[str] = []

    entries: list[_Entry] = []
    for record in b["records"]:
        p = record.get("payload") or {}
        report = RecordReport(
            receipt_id=str(p.get("receipt_id", "unknown")),
            agent_id=str(p.get("agent_id", "unknown")),
            phase=str(p.get("phase", "")),
            outcome=str(p.get("result", "")),
            checks={"issuer_signature": "fail", "seal": "fail", "chain": "not_checked", "checkpoint": "not_checked", "disclosures": "not_checked", "timestamp": "not_checked"},
        )
        sig = record.get("issuer_sig") or {}
        if sig.get("alg") == "EdDSA" and signature_ok(issuer_keys, sig.get("kid", ""), p, sig.get("sig", "")):
            report.checks["issuer_signature"] = "pass"
        else:
            report.messages.append("The issuer signature does not match this record. It was changed after signing or signed with an unknown key.")

        seal = record.get("seal")
        seal_valid = False
        if seal:
            seal_valid = signature_ok(sealer_keys, seal.get("sealer_kid", ""), {"digest": digest(p), "seq": seal.get("seq"), "sealed_at": seal.get("sealed_at")}, seal.get("sig", ""))
            if seal_valid:
                report.checks["seal"] = "pass"
            else:
                report.messages.append("The seal does not match this record. It was changed after sealing or sealed with an unknown key.")
        elif require_seal:
            report.messages.append("This record has not been sealed.")
        else:
            report.checks["seal"] = "not_checked"
            report.messages.append("Issuer-signed only: not countersigned by a separate sealing service.")
        entries.append(_Entry(record, report, seal_valid))

    _check_chains(entries, partial)
    cov_failed, cov_messages, checkpoint = _check_checkpoints(entries, b["checkpoints"], sealer_keys, partial)
    messages += cov_messages
    ts_failed, ts_messages, stamp = _check_timestamps(entries, b["checkpoints"], sealer_keys, partial, tsa_roots)
    messages += ts_messages
    messages += _check_disclosures(entries, b["disclosures"])

    failed_checks: list[str] = []
    lowest = 2
    for e in entries:
        for name in CHECKS:
            if e.report.checks[name] == "fail" and name not in failed_checks:
                failed_checks.append(name)
        e.report.result = "fail" if "fail" in e.report.checks.values() else "pass"
        e.report.level = "timestamped" if e.report.checks["timestamp"] == "pass" else "sealed" if e.report.checks["seal"] == "pass" else "issuer-signed"
        lowest = min(lowest, LEVELS.index(e.report.level))
    if cov_failed and "checkpoint" not in failed_checks:
        failed_checks.append("checkpoint")
    if ts_failed and "timestamp" not in failed_checks:
        failed_checks.append("timestamp")
    level = LEVELS[lowest] if entries else "issuer-signed"
    failed = cov_failed or ts_failed or any(e.report.result == "fail" for e in entries)
    messages.insert(
        0,
        f"Verification failed: {', '.join(LABELS[c] for c in failed_checks)} check failed."
        if failed
        else f"All {len(entries)} records passed verification. Evidence level: {LEVEL_LABELS[level]}.",
    )
    return Report("fail" if failed else "pass", level, [e.report for e in entries], failed_checks, messages, checkpoint, stamp)


def _seq(e: _Entry) -> float:
    seal = e.record.get("seal")
    return seal["seq"] if seal and isinstance(seal.get("seq"), int) else math.inf


def _check_chains(entries: list[_Entry], partial: bool) -> None:
    by_agent: dict[str, list[_Entry]] = {}
    for e in entries:
        by_agent.setdefault(e.report.agent_id, []).append(e)
    for items in by_agent.values():
        ordered = sorted(items, key=lambda e: (_seq(e), str(e.record["payload"].get("issued_at"))))
        for i, e in enumerate(ordered):
            prev = e.record["payload"].get("prev_receipt_hash")
            if i == 0:
                if prev is None:
                    e.report.checks["chain"] = "pass"
                elif partial:
                    e.report.messages.append("The earlier record in the chain is not included, so this link was not checked.")
                else:
                    e.report.checks["chain"] = "fail"
                    e.report.messages.append("The record before this one in the agent's chain is missing.")
            elif prev is not None and prev == digest(ordered[i - 1].record):
                e.report.checks["chain"] = "pass"
            elif partial and prev is not None:
                e.report.messages.append("The earlier record in the chain is not included, so this link was not checked.")
            else:
                e.report.checks["chain"] = "fail"
                e.report.messages.append("This record does not link to the previous record in the agent's chain. A record was changed, removed or inserted.")


def _checkpoint_ok(cp: dict, sealer_keys: dict) -> bool:
    return signature_ok(sealer_keys, cp.get("sealer_kid", ""), {"count": cp.get("count"), "head_digest": cp.get("head_digest"), "at": cp.get("at")}, cp.get("sig", ""))


def _next_head(prev: str | None, seq: int, payload_digest: str, sealed_at: str) -> str:
    return digest({"prev": prev, "digest": payload_digest, "seq": seq, "sealed_at": sealed_at})


def _check_checkpoints(entries, checkpoints, sealer_keys, partial):
    messages: list[str] = []
    failed = False
    valid = [cp for cp in checkpoints if _checkpoint_ok(cp, sealer_keys)]
    if len(valid) < len(checkpoints):
        failed = True
        messages.append(f"{len(checkpoints) - len(valid)} checkpoint(s) have an invalid sealer signature.")
    if not valid:
        for e in entries:
            if e.record.get("seal"):
                e.report.messages.append("No checkpoint is available yet, so coverage was not checked.")
        return failed, messages, None
    latest = max(valid, key=lambda cp: cp["count"])
    summary = {"count": latest["count"], "at": latest["at"]}
    covered = [e for e in entries if e.record.get("seal") and _seq(e) <= latest["count"]]

    if partial:
        for e in covered:
            e.report.checks["checkpoint"] = "pass" if e.seal_valid else "fail"
        return failed, messages, summary

    by_seq: dict[int, _Entry] = {}
    duplicates = set()
    for e in covered:
        s = int(_seq(e))
        if s in by_seq:
            duplicates.add(s)
        by_seq[s] = e
    missing = [s for s in range(1, latest["count"] + 1) if s not in by_seq]
    ok = False
    if not missing and not duplicates:
        head = None
        for s in range(1, latest["count"] + 1):
            rec = by_seq[s].record
            head = _next_head(head, s, digest(rec["payload"]), rec["seal"]["sealed_at"])
        ok = head == latest["head_digest"]
    if not ok:
        failed = True
        if missing:
            messages.append(f"{len(missing)} record(s) covered by the latest checkpoint are missing.")
        elif duplicates:
            messages.append("More than one record uses the same seal number.")
        else:
            messages.append("The records do not match the sealer's latest checkpoint.")
    culprits = [e for e in covered if not e.seal_valid] if (not ok and not missing and not duplicates) else []
    for e in covered:
        if ok or (culprits and e.seal_valid):
            e.report.checks["checkpoint"] = "pass"
        else:
            e.report.checks["checkpoint"] = "fail"
    return failed, messages, summary


def _check_timestamps(entries, checkpoints, sealer_keys, partial, tsa_roots):
    messages: list[str] = []
    anchored = sorted((cp for cp in checkpoints if cp.get("anchors") and _checkpoint_ok(cp, sealer_keys)), key=lambda cp: cp["count"])
    heads: dict[int, str] = {}
    if not partial:
        by_seq = {int(_seq(e)): e for e in entries if e.record.get("seal")}
        head = None
        s = 1
        while s in by_seq:
            rec = by_seq[s].record
            head = _next_head(head, s, digest(rec["payload"]), rec["seal"]["sealed_at"])
            heads[s] = head
            s += 1
    results: list[tuple[dict, TimestampResult]] = []
    for cp in anchored:
        anchor = next((a for a in cp["anchors"] if a.get("type") == "rfc3161"), None)
        res = verify_timestamp_token(anchor["token"], anchor_digest(cp), tsa_roots) if anchor else TimestampResult(False, "The timestamp is of an unsupported type.")
        if res.ok and cp["count"] in heads and heads[cp["count"]] != cp["head_digest"]:
            res = TimestampResult(False, "The records do not match the timestamped checkpoint.")
        results.append((cp, res))
        if not res.ok:
            messages.append(f"The outside timestamp on checkpoint {cp['count']} does not verify: {res.reason}")

    pending = 0
    for e in entries:
        if not e.record.get("seal") or not e.seal_valid:
            continue
        hit = next(((cp, r) for cp, r in results if cp["count"] >= _seq(e)), None)
        if hit is None:
            pending += 1
            e.report.messages.append("Sealed; outside timestamp pending.")
            continue
        e.report.checks["timestamp"] = "pass" if hit[1].ok else "fail"
        if not hit[1].ok:
            e.report.messages.append(f"The outside timestamp covering this record does not verify: {hit[1].reason}")
    good = [(cp, r) for cp, r in results if r.ok]
    stamp = None
    if good:
        cp, r = good[-1]
        stamp = {"tsa": r.tsa, "at": r.gen_time, "count": cp["count"]}
        messages.append(f"Timestamped by {r.tsa} at {r.gen_time}: the records up to seal {cp['count']} existed then and have not changed since.")
    if pending:
        messages.append(f"{pending} record(s) not yet covered by an outside timestamp." if stamp else "No outside timestamp covers these records yet.")
    return any(not r.ok for _cp, r in results), messages, stamp


def _check_disclosures(entries, disclosures) -> list[str]:
    messages: list[str] = []
    by_id = {e.report.receipt_id: e for e in entries}
    for d in disclosures:
        e = by_id.get(d.get("receiptId"))
        if e is None:
            messages.append(f"A disclosure refers to a record that is not included ({d.get('receiptId')}).")
            continue
        commitment = e.record["payload"].get(FIELDS.get(d.get("field"), ""), None)
        salt = d.get("salt", "")
        ok = (
            isinstance(commitment, str)
            and isinstance(salt, str)
            and len(salt) == 64
            and all(c in "0123456789abcdef" for c in salt)
            and commitment == digest({"salt": salt, "value": d.get("value")})
        )
        if ok:
            if e.report.checks["disclosures"] != "fail":
                e.report.checks["disclosures"] = "pass"
        else:
            e.report.checks["disclosures"] = "fail"
            e.report.messages.append(f"The disclosed {str(d.get('field', '')).replace('_', ' ')} details do not match the record.")
    return messages


def outcomes(bundle: Any) -> list[str]:
    """The outcome of each action in the bundle, in order: "confirmed", "not_confirmed", "denied", ..."""
    b = parse_bundle(bundle)
    groups: dict[str, list[dict]] = {}
    for r in b["records"]:
        p = r["payload"]
        groups.setdefault(p.get("instance_commitment") or p.get("receipt_id"), []).append(p)
    result = []
    for items in groups.values():
        def last(pred):
            return next((p for p in reversed(items) if pred(p)), None)

        dec = last(lambda p: p["phase"] == "decision" and p["result"] in ("allowed", "held", "denied"))
        appr = last(lambda p: p["phase"] == "decision" and p["result"] in ("approved", "rejected", "expired"))
        exe = last(lambda p: p["phase"] == "execution")
        conf = last(lambda p: p["phase"] == "confirmation")
        if conf:
            result.append("confirmed" if conf["result"] == "confirmed" else "not_confirmed")
        elif exe:
            result.append("executed_unconfirmed" if exe["result"] == "executed" else "failed")
        elif appr:
            result.append({"rejected": "rejected", "expired": "expired"}.get(appr["result"], "allowed_not_executed"))
        elif dec and dec["result"] == "denied":
            result.append("denied")
        elif dec and dec["result"] == "held":
            result.append("awaiting_approval")
        else:
            result.append("allowed_not_executed")
    return result
