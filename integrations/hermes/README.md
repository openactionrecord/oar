# Open Action Record for Hermes Agent

Every approval decision in Hermes becomes a signed, chained [Open Action Record](https://github.com/openactionrecord/oar): dangerous commands, protected file writes, MCP elicitations and payments, whether a person decided (CLI, Telegram, Slack...) or smart approval did. When the approved tool call finishes, its status is recorded too.

Commands, descriptions and session keys are **never written in clear**: each record carries salted commitments. Anyone can verify the records offline, and any edit, deletion or reordering shows.

## Install

```bash
hermes plugins install openactionrecord/oar/integrations/hermes --enable
```

Or, if you manage Hermes's Python environment yourself: `pip install open-action-record`, then `hermes plugins enable oar`.

## Use

Use Hermes as usual. Then:

```bash
python -m open_action_record.hermes export > approvals.json      # share this: no commands in clear
npx @openactionrecord/cli verify approvals.json                    # or: oar-verify approvals.json
```

```text
✔ All 9 records passed verification.
● command → hermes.cli   Approved; no execution recorded
    decision     Held for approval by policy:hermes-approvals (needs_approval, pattern:delete in root path)
    approval     Approved by approver:cli-user (button)
✘ command → hermes.cli   Rejected by a person
● command → hermes.smart  Executed; no confirmation recorded
    approval     Approved by approver:aux_llm (standing_mandate)
```

`python -m open_action_record.hermes export --disclose` includes the commands, for your own review. Keep that file private.

## Files

In `~/.hermes/oar/` (or `$HERMES_HOME/oar`):

| File | |
|---|---|
| `records.jsonl` | One signed record per line. Safe to share. |
| `disclosures.jsonl` | Salts and values that open the commitments. Private (mode 600). |
| `issuer-key.json` | This installation's signing key. Private (mode 600). |

## Settings

| Variable | |
|---|---|
| `OAR_HERMES_ALL_TOOLS=1` | Also record tool calls that needed no approval. |
| `OAR_HERMES_DISCLOSURES=0` | Don't keep salts and values (records still verify; values can never be disclosed). |
| `OAR_HERMES_DIR` | Where the files go. |

Several Hermes processes can write at once; the chain stays intact.
