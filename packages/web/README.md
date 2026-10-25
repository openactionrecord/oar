# Playground

A single static page (`dist/index.html`) that verifies Open Action Record bundles in the browser with the
standalone WebCrypto verifier. No external requests; bundles never leave the page. Includes sample bundles and
buttons that tamper with them, so you can watch verification fail.

```bash
pnpm --filter @openactionrecord/web build   # writes packages/web/dist/index.html
```

Deployed to GitHub Pages by `.github/workflows/pages.yml`.
