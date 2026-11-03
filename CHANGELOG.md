# Changelog

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
