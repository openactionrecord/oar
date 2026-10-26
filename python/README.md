# open-action-record (Python)

Write and verify [Open Action Records](https://github.com/openactionrecord/oar): signed proof of what an AI agent's action actually changed, and who approved it. Records written here verify with every OAR verifier (Python, TypeScript and the browser).

```bash
pip install open-action-record
```

## Record an action

```python
from open_action_record import Recorder, generate_signing_key, verify_bundle

oar = Recorder(issuer=generate_signing_key("my-agent-2026"), org="acme", agent="support-bot")

out = oar.run(
    type="refund", target="stripe", params={"order": "1142", "amount_cents": 190000},   # committed, never in clear
    check=lambda p: {"result": "held", "reasons": ["over_approval_limit"]} if p["amount_cents"] > 125000 else {"result": "allowed"},
    approve=lambda action: {"approver": "jordan", "approved": ask_on_slack(action)},
    read_state=lambda: order_state("1142"),               # read before and after
    execute=lambda: stripe.Refund.create(payment_intent=pi, amount=190000),
    target_ref=lambda refund: refund.id,
    confirm=lambda refund: stripe.Refund.retrieve(refund.id).status == "succeeded",
)

bundle = oar.bundle()                 # discloses nothing by default; disclose="all" for your own debugging
verify_bundle(bundle).result          # "pass"
```

Every path is recorded: allowed, held, approved, rejected, denied, failed, confirmed and not confirmed. Async agents use `await oar.run_async(...)` (any callback may be async). Prefer explicit steps? Use `oar.decide()`, `oar.approve()`, `oar.execute()` and `oar.confirm()`. Pass `on_record=` to persist each record as it is written, and `last_record=` to continue an agent's chain after a restart. `LocalSealer` adds a separate sealing service.

## Hermes Agent plugin

Every approval decision in [Hermes Agent](https://github.com/NousResearch/hermes-agent) (dangerous commands, protected writes, MCP elicitations, payments; on the CLI, in messaging gateways, or by smart approval) becomes a signed, chained record: who or what decided, on which surface, and whether the approved call then succeeded. Commands, descriptions and session keys are committed, never written in clear.

```bash
hermes plugins install openactionrecord/oar/integrations/hermes --enable
# or, if you manage Hermes's Python environment yourself:
#   pip install open-action-record && hermes plugins enable oar
# ... use Hermes ...
python -m open_action_record.hermes export > approvals.json
oar-verify approvals.json
```

Records are in `~/.hermes/oar/records.jsonl` (safe to share). The values that open the commitments are in `disclosures.jsonl` and the signing key in `issuer-key.json`, both private (mode 600). Set `OAR_HERMES_ALL_TOOLS=1` to also record tool calls that needed no approval. Several Hermes processes can write at once; the chain stays intact.

## Verify

```bash
oar-verify evidence.json                 # --keys trusted-keys.json --require-seal --json
```

```python
import json
from open_action_record import verify_bundle, outcomes

bundle = json.load(open("evidence.json"))
report = verify_bundle(bundle)           # pass keys=... to check against keys you trust
print(report.result, report.level)       # "pass", "sealed"
print(outcomes(bundle))                  # ["confirmed", "denied", "not_confirmed"]
```

The verifier checks every record's issuer signature, the separate sealing service's seal, each agent's hash chain, checkpoint coverage, outside RFC 3161 timestamps (against the bundled DigiCert roots) and any disclosed values. It reaches the same result as the TypeScript and browser verifiers on every shared test vector.

Apache-2.0.
