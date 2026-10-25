# open-action-record (Python)

Verify [Open Action Records](https://github.com/openactionrecord/oar): signed proof of what an AI agent's action actually changed, and who approved it.

```bash
pip install open-action-record
oar-verify evidence.json
```

```python
import json
from open_action_record import verify_bundle, outcomes

bundle = json.load(open("evidence.json"))
report = verify_bundle(bundle)          # pass keys=... to check against keys you trust
print(report.result, report.level)      # "pass", "sealed"
print(outcomes(bundle))                 # ["confirmed", "denied", "not_confirmed"]
```

It checks every record's issuer signature, the separate sealing service's seal, each agent's hash chain, checkpoint coverage, outside RFC 3161 timestamps (against the bundled DigiCert roots) and any disclosed values. It reaches the same result as the TypeScript and browser verifiers on every shared test vector.

Writing records from Python is planned; today, write them with [`@openactionrecord/core`](https://www.npmjs.com/package/@openactionrecord/core).

Apache-2.0.
