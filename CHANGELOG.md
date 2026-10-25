# Changelog

## 0.1.0 (unreleased)

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
