# Working in this repository (for coding agents)

- Read `SPEC.md` before changing anything that touches records, bundles or verification.
- Three verifiers must always agree: `packages/core/src/verify.ts` (reference), `packages/core/src/standalone.ts`
  (plain JavaScript on WebCrypto, kept as source text so it can be embedded in HTML) and `python/`. Change them
  together and add a case to `vectors/` via `scripts/vectors.ts`.
- Commands: `pnpm install`, `pnpm test`, `pnpm typecheck`, `pnpm build`, `pnpm vectors`, `pnpm demo`;
  Python: `cd python && pip install -e ".[test]" && pytest`.
- Records must never contain personal data in clear: values go behind commitments.
- Wire identifiers keep the `aar_` prefix (`aar_version`, `/.well-known/aar-keys.json`) for compatibility.
- Never commit real keys. Test keys in `vectors/` are public on purpose.
- Releases: every published package (`packages/*`, `python/`) has the same version; `scripts/check-versions.mjs`
  checks it against the release tag. Publishing runs only from `.github/workflows/release.yml`.
