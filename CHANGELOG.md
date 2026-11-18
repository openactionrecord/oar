# Changelog

## Unreleased (0.5.0)

- **Authority set and the re-check at commit** (SPEC section 4.5): a decision record can carry `authorities`, the
  outside artifacts it relied on (an AAuth or x401 token, an OAuth grant, a session, a mandate, an approval
  service's result), each by digest with its validity window and status. The execution record carries
  `authority_check`, the same set checked again just before the action committed. If an authority changed, the
  action does not run and is recorded with the new execution result `refused` and reason `authority_revoked`,
  `authority_expired` or `authority_invalid`. `decide({ authorities })` and `execute({ authorityCheck })` in the
  TypeScript and Python recorders.
- **Eighth verifier check, authority**, in all three verifiers. It fails an action allowed on an authority that was
  not valid, a re-check that covers a different set, a re-check that calls an expired authority current, and an
  action executed without its authority set being checked again. Test vectors `authority-current.json`,
  `authority-revoked.json`, `authority-not-rechecked.json` and `authority-stale.json`.
- **Outcome classes** (SPEC section 6): every action is also reported as `committed`, `refused` or `unresolved`,
  so a relying party can tell what is known to have happened. `outcomeClass()` and `outcome_class()`.
- **Specification:** reason code `authority_conflict`; composing with other protocols (section 12.1) and relying
  on an OAR record (section 12.2).

## 0.4.0 (17 November 2026)

- **Approval binding, version 2** (SPEC section 4.3.1): the approval record carries the value the approver
  confirmed, built from the held action, the exact action instance, what the approver was shown and a nonce.
  `requestApproval()` (TypeScript) and `request_approval()` (Python) prepare it; a passkey uses it as its challenge.
- **Approvals by an outside service** (`method: "external"`): a bank app, a SIM check or a digital identity wallet
  confirms the approver; the record carries the binding and the digest of the service's proof.
- **Seventh verifier check, approval binding**, in all three verifiers. It fails a binding made for another
  action, a changed display, or a signed rejection recorded as approved. Test vectors `approval-external.json`
  and `approval-flipped.json`.
- **Rules mapping.** `docs/REGULATORY-MAPPING.md`: how OAR records line up with rules in the EU (AI Act, payment
  rules, GDPR), the US (New York DFS, NIST) and Canada (OSFI E-23), with what is not covered yet and the proposals
  that would cover it.
- **Specification (no change to records):** common reason codes such as `new_payee` and `payee_details_changed`
  (section 7); an optional `retention` field on bundles, and verifiers ignore bundle fields they do not know
  (section 8); retention and erasure (section 11.1).
- Test vectors `retention.json` and `erased-values.json`.

## 0.3.0 (2 November 2026)

- **Database demo.** `npx @openactionrecord/cli demo --database`: an AI operations agent on a production database.
  A routine cleanup runs and is confirmed, deleting a table is held and rejected by a person, deleting the backups is
  blocked, and a migration the tool reports as "applied" but that never added its column is recorded as NOT confirmed.
- README: the one-minute demo as an animated GIF.
- Versions of the TypeScript and Python packages move together; no change to the record format or the Python package.

## 0.2.0 (26 October 2026)

- **Python writer.** `open-action-record` now writes records too: `Recorder` with `run()` and `run_async()`,
  step-by-step `decide`/`approve`/`execute`/`confirm`, `LocalSealer`, bundles, and chain continuation across
  restarts. Records written in Python verify with the TypeScript and browser verifiers (tested in CI).
- **Hermes Agent plugin.** `pip install open-action-record && hermes plugins enable oar`: every approval decision
  becomes a signed, chained record, with commands and session keys committed rather than stored. Safe with
  several Hermes processes. Tested against the latest Hermes weekly.
- Summaries report "approved; no execution recorded" separately from "allowed".

## 0.1.1 (26 October 2026)

- The demo's closing hints now give the `npx` commands that work from npm.
- First release of the Python package to PyPI.

## 0.1.0 (26 October 2026, npm)

First public release.

- **Specification** OAR 0.3: decision, approval, execution and confirmation records; salted commitments with
  selective disclosure; per-agent hash chains; optional sealing service with checkpoints and outside RFC 3161
  timestamps; `external_ref` to add evidence to receipts in other formats; evidence levels; bundles
  (`oar-bundle/0.1`). Reads records and packages written as AAR 0.3 / `aar-evidence/0.1`.
- **`@openactionrecord/core`**: `createRecorder` (with `run()` to wrap an action end to end), a local sealing
  service with RFC 3161 timestamping, the reference verifier, action summaries, and a standalone WebCrypto verifier.
- **`@openactionrecord/cli`**: `oar demo`, `oar verify` (with `--cross-check`), `oar inspect`, `oar html`, `oar keygen`.
- **`open-action-record`** (Python): verifier and `oar-verify`.
- **Playground**: a static page that verifies bundles in the browser, with tamper buttons.
- **Test vectors** shared by all verifiers, including compatibility cases and real evidence packages exported by Tridris.
