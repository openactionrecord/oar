# Contributing to Open Action Record

Thank you for helping. OAR is useful only if many tools can write and check it, so contributions of every size
matter: a bug report, a clearer sentence in the spec, an adapter for your framework, a verifier in a new language.

## Ways to help

- **Try it and tell us what confused you.** Run `npx @openactionrecord/cli demo` or the quickstart and open an issue
  with what was unclear. That is the most useful contribution right now.
- **Add OAR to the tool you use.** Adapters for agent frameworks and MCP servers, readers that confirm outcomes in
  real systems (payments, stores, databases). Open an issue first so we can agree the shape.
- **Write a verifier in another language.** It conforms when it passes every case in `vectors/`.
- **Improve the specification.** Open a discussion for anything that changes what is on the wire; small
  clarifications can go straight to a pull request.

## Development

Requirements: Node.js 20.12 or later, pnpm 10, Python 3.10 or later.

```bash
pnpm install
pnpm test          # TypeScript tests, test vectors (both JavaScript verifiers) and examples
pnpm typecheck
pnpm build         # packages and the playground page (packages/web/dist/index.html)
pnpm demo          # the CLI demo, from source

cd python && pip install -e ".[test]" && pytest    # the Python verifier against the same vectors
```

`pnpm vectors` regenerates `vectors/`. The output is deterministic; a change to the vectors in a pull request
must be explained.

## Rules for changes

- **Every verifier must agree.** A change to verification logic lands in the reference verifier
  (`packages/core/src/verify.ts`), the standalone verifier (`packages/core/src/standalone.ts`) and the Python
  verifier (`python/`) together, with a test vector that shows it.
- **Wire changes need a spec change.** Anything that changes records, bundles or verification results updates
  `SPEC.md` and its "Changes" section in the same pull request.
- **Never weaken privacy.** Records must not carry personal data in clear.
- **No new runtime dependencies** in `@openactionrecord/core` without discussion. Cryptography stays on
  well-reviewed libraries (`@noble/curves`, WebCrypto, `cryptography`).
- Keep messages and docs plain: say what happened and what to do.

## Licensing of contributions

Code contributions are licensed under Apache-2.0 and specification text under CC BY 4.0, the same as the
project (inbound = outbound). By opening a pull request you confirm you have the right to contribute it. Add a
`Signed-off-by` line to your commits (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/).
