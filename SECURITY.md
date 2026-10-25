# Security policy

OAR is used to prove what AI agents did. A flaw that lets a changed, removed or forged record pass verification,
or that leaks committed values, is a security issue. Please report it privately.

## Reporting

- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository.
- Or email **info@tridris.com** with "OAR security" in the subject.

Please include the affected package and version, a minimal bundle or test case, and what you expected. We aim to
acknowledge reports within 3 working days and to agree a disclosure date with you. Please do not open public
issues for vulnerabilities.

## Scope

In scope: the verifiers (TypeScript, standalone WebCrypto, Python), record writing and sealing in
`@openactionrecord/core`, the CLI, the playground page, and the specification itself.

Known limits, documented in SPEC.md section 10 and not vulnerabilities on their own: a sealing service run by the
same organisation as the issuer; certificate revocation for timestamp authorities is not checked; times are claims
until an outside timestamp bounds them.

## Supported versions

Until 1.0, security fixes go into the latest 0.x release.
