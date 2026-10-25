# @openactionrecord/claude-code

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook that checks each tool call against your rules,
then records it as an [Open Action Record](../../README.md): what was asked, what your rules decided, who approved it
and whether it ran. Anyone can verify the records offline.

## Set up (2 minutes)

```bash
npx -y @openactionrecord/claude-code init
```

This creates `.oar/` with example rules, adds `.oar/` to `.gitignore`, and prints the hooks block to add to
`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "npx -y @openactionrecord/claude-code" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "npx -y @openactionrecord/claude-code" }] }],
    "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "npx -y @openactionrecord/claude-code" }] }]
  }
}
```

For faster hooks, install it once (`npm install -g @openactionrecord/claude-code`) and use `oar-claude-hook` as the
command.

## Rules

`.oar/rules.json`, checked in order; the first match decides:

```json
{
  "rules": [
    { "tool": "Bash", "contains": ["rm -rf", "git push --force"], "effect": "deny", "reason": "destructive_command" },
    { "tool": "mcp__prod-db__*", "contains": ["drop", "delete"], "effect": "hold", "reason": "needs_a_person" }
  ],
  "default": "allow"
}
```

- `tool`: a tool name (`Bash`, `Write`), a prefix ending in `*` (`mcp__prod-db__*`), or `*`.
- `contains`: words to look for in the tool's input, ignoring case. Leave it out to match every call.
- `effect`:
  - `allow`: the call runs.
  - `hold`: Claude Code asks you first, in its permission prompt. If you allow it, your approval is recorded.
  - `deny`: the call is blocked, and Claude is told why.

## See and check the records

```bash
npx -y @openactionrecord/claude-code bundle          # the latest session -> oar-bundle-<session>.json
npx @openactionrecord/cli verify oar-bundle-<session>.json
npx @openactionrecord/cli html oar-bundle-<session>.json   # a page that verifies it offline
```

Bundles disclose nothing: commands, file paths and outputs are salted commitments.

## Where things are kept

| Path | What | Share it? |
|---|---|---|
| `.oar/records/<session>.jsonl` | The signed records, append-only | Yes, as a bundle |
| `.oar/salts/<session>.jsonl` | The salts and values behind the commitments (your tool inputs) | **No.** Readable only by you, ignored by git |
| `~/.oar/keys/claude-code.json` | The signing key, made on first use (`OAR_HOME` to move it) | **No.** Readable only by you |
| `.oar/config.json` | Optional: `org`, `agent`, `approver`, `failClosed` | Yes |

**Fail closed.** If the hook can't check or record a call (a broken rules file, an unreadable store), it blocks the
call and says why. Set `"failClosed": false` in `.oar/config.json` to let calls run unrecorded instead.

Records are signed by your own key: this proves what your machine recorded, and that nothing was changed or removed
afterwards. For evidence an outsider can rely on, add a separate sealing service and outside timestamps
(see [`examples/sealer-server.ts`](../../examples/sealer-server.ts)).
