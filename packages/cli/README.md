# @openactionrecord/cli

`oar`: verify [Open Action Records](https://github.com/openactionrecord/oar) from the command line, and see what they prove.

```bash
npx @openactionrecord/cli demo                          # a one-minute demo; writes ./oar-demo
npx @openactionrecord/cli verify evidence.json          # verify, and show what each action did
npx @openactionrecord/cli verify evidence.json --cross-check --keys published-keys.json
npx @openactionrecord/cli html evidence.json            # a page that verifies the bundle offline
npx @openactionrecord/cli keygen my-agent-2026          # a signing key and its public key set
```

Exit codes: `0` verified, `1` verification failed, `2` the input could not be read. Set `NO_COLOR=1` for plain output.

Apache-2.0.
