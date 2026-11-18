"""Verifies an Open Action Record bundle: issuer signatures, seals, chains, checkpoint coverage, outside
timestamps and disclosures. Mirrors the TypeScript reference verifier and reaches the same result on the
shared test vectors (vectors/ in the repository)."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .canonical import digest, signature_ok
from .timestamp import TimestampResult, anchor_digest, verify_timestamp_token

CHECKS = ("issuer_signature", "seal", "chain", "checkpoint", "disclosures", "timestamp", "approval", "authority")
LABELS = {
    "issuer_signature": "Issuer signature",
    "seal": "Seal",
    "chain": "Chain",
    "checkpoint": "Checkpoint coverage",
    "disclosures": "Disclosures",
    "timestamp": "Outside timestamp",
    "approval": "Approval binding",
    "authority": "Authority",
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
            checks={"issuer_signature": "fail", "seal": "fail", "chain": "not_checked", "checkpoint": "not_checked", "disclosures": "not_checked", "timestamp": "not_checked", "approval": "not_checked", "authority": "not_checked"},
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
        problems = check_approval(p)
        if problems is not None:
            report.checks["approval"] = "fail" if problems else "pass"
            report.messages += problems
        entries.append(_Entry(record, report, seal_valid))

    _check_chains(entries, partial)
    cov_failed, cov_messages, checkpoint = _check_checkpoints(entries, b["checkpoints"], sealer_keys, partial)
    messages += cov_messages
    ts_failed, ts_messages, stamp = _check_timestamps(entries, b["checkpoints"], sealer_keys, partial, tsa_roots)
    messages += ts_messages
    messages += _check_disclosures(entries, b["disclosures"])

    payloads = {e.record["payload"].get("receipt_id"): e.record["payload"] for e in entries if isinstance(e.record.get("payload"), dict)}
    for e in entries:
        problems = check_authority(e.record["payload"], payloads) if isinstance(e.record.get("payload"), dict) else None
        if problems is not None:
            e.report.checks["authority"] = "fail" if problems else "pass"
            e.report.messages += problems

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


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(c in "0123456789abcdef" for c in value[7:])


def binding_digest(action_id: str, instance_commitment: str, nonce: str, display_commitment: str | None = None, decision: str | None = None) -> str:
    """The approval binding (SPEC.md section 4.3): what the approver's device or the outside service confirms."""
    value: dict[str, Any] = {
        "v": 2,
        "purpose": "oar.approval",
        "action_id": action_id,
        "instance_commitment": instance_commitment,
        "display_commitment": display_commitment,
        "nonce": nonce,
    }
    if decision:
        value["decision"] = decision
    return digest(value)


def check_approval(p: dict) -> list[str] | None:
    """Problems with one record's approval binding and outside evidence; None when there is nothing to check."""
    a = p.get("approval")
    if not isinstance(a, dict) or (a.get("binding") is None and a.get("method") != "external"):
        return None
    problems: list[str] = []
    if a.get("method") == "external":
        ev = a.get("evidence")
        if not isinstance(ev, dict) or not isinstance(ev.get("provider"), str) or not ev.get("provider") or not isinstance(ev.get("format"), str) or not ev.get("format") or not _is_digest(ev.get("digest")):
            problems.append("An approval by an outside service must name the provider and format and carry the digest of its proof.")
        if not a.get("binding"):
            problems.append("An approval by an outside service must carry the binding it was asked to confirm.")
    b = a.get("binding")
    if b:
        nonce = b.get("nonce") if isinstance(b, dict) else None
        if not isinstance(b, dict) or b.get("v") != 2 or not isinstance(nonce, str) or len(nonce) != 64 or not all(c in "0123456789abcdef" for c in nonce) or not _is_digest(b.get("digest")):
            problems.append("The approval binding is malformed.")
        elif not isinstance(p.get("decision_ref"), str):
            problems.append("The approval binding names no held action (decision_ref is missing).")
        else:
            expected = binding_digest(p["decision_ref"], p.get("instance_commitment"), nonce, a.get("display_commitment") or None, b.get("decision"))
            if expected != b.get("digest"):
                problems.append("The approval binding does not match this action, what the approver was shown, or its nonce.")
            if b.get("decision") == "approve" and p.get("result") != "approved":
                problems.append("The approver signed an approval, but the record says otherwise.")
            if b.get("decision") == "reject" and p.get("result") != "rejected":
                problems.append("The approver signed a rejection, but the record says otherwise.")
    return problems


AUTHORITY_STATUSES = ("valid", "expired", "revoked", "invalid", "unknown")


def _time(value: Any) -> float | None:
    from datetime import datetime

    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def check_authority_evidence(evidence: Any, set_size: int) -> list[str]:
    """Problems with an authority check's evidence (SPEC.md section 4.5), given the size of the set it covers."""
    if evidence is None:
        return []
    if not isinstance(evidence, list) or not evidence:
        return ["The authority check evidence is malformed: it must be a non-empty list."]
    problems = []
    for i, e in enumerate(evidence, 1):
        idx = e.get("index") if isinstance(e, dict) else None
        if not isinstance(e, dict) or not isinstance(idx, int) or isinstance(idx, bool) or not 0 <= idx < set_size or not isinstance(e.get("format"), str) or not e.get("format") or not _is_digest(e.get("digest")):
            problems.append(f"Authority check evidence {i} is malformed: it needs the index of an authority in the set, a format and a sha256 digest.")
    return problems


def authority_set_digest(authorities: list) -> str:
    """SPEC.md section 4.5: the digest an execution record's authority_check names."""
    return digest({"v": 1, "purpose": "oar.authorities", "authorities": authorities})


def _with_authorities(p: dict | None, by_id: dict) -> dict | None:
    for _ in range(16):
        if p is None:
            return None
        if p.get("authorities") is not None:
            return p
        p = by_id.get(p.get("decision_ref"))
    return None


def check_authority(p: dict, by_id: dict) -> list[str] | None:
    """Check 8: problems with a record's authority set or its re-check at commitment; None when nothing to check."""
    problems: list[str] = []
    checked = False
    auths = p.get("authorities")
    if auths is not None:
        checked = True
        set_problems: list[str] = []
        if not isinstance(auths, list) or not auths:
            set_problems.append("The authority set is malformed: it must be a non-empty list.")
        else:
            for i, a in enumerate(auths, 1):
                if not isinstance(a, dict) or not isinstance(a.get("type"), str) or not a.get("type") or not isinstance(a.get("issuer"), str) or not a.get("issuer") or not _is_digest(a.get("digest")) or _time(a.get("checked_at")) is None or a.get("status") not in AUTHORITY_STATUSES:
                    set_problems.append(f"Authority {i} is malformed: it needs type, issuer, a sha256 digest, checked_at and a status.")
                    continue
                nb, ex, at = a.get("not_before"), a.get("expires_at"), _time(a["checked_at"])
                if (nb is not None and _time(nb) is None) or (ex is not None and _time(ex) is None):
                    set_problems.append(f"Authority {i} has an invalid validity window.")
                elif a["status"] == "valid" and ex is not None and _time(ex) <= at:
                    set_problems.append(f"Authority {i} is recorded as valid, but it had expired when it was checked.")
                elif a["status"] == "valid" and nb is not None and _time(nb) > at:
                    set_problems.append(f"Authority {i} is recorded as valid, but it was not yet valid when it was checked.")
        problems += set_problems
        if not set_problems and p.get("result") in ("allowed", "approved") and any(a.get("status") != "valid" for a in auths):
            problems.append(f"The action was {p['result']}, but not every authority it relied on was valid.")
    if p.get("phase") == "execution":
        src = _with_authorities(by_id.get(p.get("decision_ref")), by_id) if p.get("decision_ref") else None
        c = p.get("authority_check")
        if c is not None:
            checked = True
            if not isinstance(c, dict) or _time(c.get("checked_at")) is None or not _is_digest(c.get("set_digest")) or c.get("result") not in ("current", "changed"):
                problems.append("The authority check is malformed.")
            elif not src:
                problems.append("The authority check names no authority set: no earlier record of this action carries one.")
            else:
                if authority_set_digest(src["authorities"]) != c["set_digest"]:
                    problems.append("The authority check covers a different authority set than the decision relied on.")
                problems.extend(check_authority_evidence(c.get("evidence"), len(src["authorities"])))
                if c["result"] == "current":
                    at = _time(c["checked_at"])
                    stale = next((i for i, a in enumerate(src["authorities"], 1) if a.get("expires_at") is not None and (_time(a["expires_at"]) or 0) <= at), None)
                    if stale:
                        problems.append(f"The authority check says every authority was current, but authority {stale} had expired by then.")
                    if p.get("result") == "refused":
                        problems.append("The authority check says every authority was current, but the action was recorded as refused.")
                elif p.get("result") != "refused":
                    problems.append("An authority changed before the action committed, but the action was not recorded as refused.")
        elif src and p.get("result") == "executed":
            checked = True
            problems.append("The action ran without its authority set being checked again at the moment it committed.")
    return problems if checked else None


def _check_disclosures(entries, disclosures) -> list[str]:
    messages: list[str] = []
    by_id = {e.report.receipt_id: e for e in entries}
    for d in disclosures:
        e = by_id.get(d.get("receiptId"))
        if e is None:
            messages.append(f"A disclosure refers to a record that is not included ({d.get('receiptId')}).")
            continue
        payload = e.record["payload"]
        if d.get("field") == "display":
            commitment = (payload.get("approval") or {}).get("display_commitment")
        else:
            commitment = payload.get(FIELDS.get(d.get("field"), ""), None)
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


def outcome_class(outcome: str) -> str:
    """committed, refused or unresolved (SPEC.md section 6)."""
    if outcome == "confirmed":
        return "committed"
    if outcome in ("denied", "rejected", "expired", "refused"):
        return "refused"
    return "unresolved"


def outcomes(bundle: Any) -> list[str]:
    """The outcome of each action in the bundle, in order: "confirmed", "not_confirmed", "denied", ..."""
    b = parse_bundle(bundle)
    by_id = {r["payload"].get("receipt_id"): r["payload"] for r in b["records"]}

    def action_key(p: dict) -> str:
        # Follow decision_ref back to the action's first record (instance commitments may be re-salted per record).
        current = p
        for _ in range(16):
            parent = by_id.get(current.get("decision_ref"))
            if parent is None:
                break
            current = parent
        return current.get("decision_ref") or current.get("receipt_id")

    groups: dict[str, list[dict]] = {}
    for r in b["records"]:
        groups.setdefault(action_key(r["payload"]), []).append(r["payload"])
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
            result.append({"executed": "executed_unconfirmed", "refused": "refused"}.get(exe["result"], "failed"))
        elif appr:
            result.append({"rejected": "rejected", "expired": "expired"}.get(appr["result"], "approved_not_executed"))
        elif dec and dec["result"] == "denied":
            result.append("denied")
        elif dec and dec["result"] == "held":
            result.append("awaiting_approval")
        else:
            result.append("allowed_not_executed")
    return result
