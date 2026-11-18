# Open Action Record (OAR) specification, version 0.3

**Status:** draft for public review, October 2026. Licensed CC BY 4.0. Comments and proposals: open an issue or a discussion in this repository.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119 and RFC 8174.

> **About the name.** The format was first published as *Agent Action Receipts* (AAR). Wire identifiers keep that prefix for compatibility: the `aar_version` field and the key-set path `/.well-known/aar-keys.json`. A future major version may rename them; verifiers MUST then accept both the old and the new identifiers.

## 1. Purpose

AI agents now take actions that move money and change accounts: refunds, credits, payouts, cancellations, account changes, database writes. Logs of what a tool was called with are not enough when something goes wrong. The questions that matter in a dispute, an audit, an insurance claim or a post-incident review are:

1. **What was asked, and what did the rules decide?**
2. **Who approved this exact action**, when a person's approval was required?
3. **What actually changed** in the system of record, and does that system confirm it?
4. **Can I check all of this myself**, offline, without trusting the system that wrote it, and without seeing personal data I do not need?

An **Open Action Record** is a signed record of one step in the life of one agent action: the decision; a person's approval or rejection; the execution, with commitments to the affected state before and after; and a confirmation read back from the system of record. Records are chained per agent, MAY be countersigned by a separate sealing service, and MAY be covered by an outside RFC 3161 timestamp.

OAR is designed so that a third party can verify, offline and years later:

1. **Integrity**: no record changed after it was signed (and sealed).
2. **Completeness**: no record was removed, inserted or reordered (hash chain, and with a sealing service, sealed checkpoints).
3. **Authority**: which rules decided, and which named person approved, with what method.
4. **Effect**: what the action changed (before and after commitments) and whether the system of record confirms it.
5. **Privacy by default**: amounts, parameters, identifiers and state are behind salted commitments, disclosed field by field.

OAR does not define how agents are built or how rules are written. It records what happened, in a form anyone can check.

## 2. Terminology

- **Issuer**: the party that decides on actions (or records the decisions of the system that does) and signs records.
- **Sealing service** (sealer): a separately operated service that countersigns each record's payload digest with a sequence number and time, keeps a hash-chained log, and signs checkpoints over it. It sees digests only, never record contents.
- **Record**: a payload with the issuer's signature and, optionally, a seal.
- **Action**: one request by one agent to change a system (for example, refund 1,900.00 on order 1142).
- **System of record**: the system the action changes (a payment processor, an order system, a database).
- **Commitment**: `C(v, s) = "sha256:" + hex(SHA-256(JCS({ "salt": s, "value": v })))`, where `s` is 32 random bytes in lower-case hex.
- **Disclosure**: a `{ receiptId, field, salt, value }` object that opens one commitment.
- **Bundle**: one JSON file with records, keys, checkpoints and optional disclosures (section 8).
- **JCS**: the JSON Canonicalization Scheme, RFC 8785.

## 3. Cryptography

- **Canonical form**: every signed or hashed JSON value MUST be serialized with JCS (RFC 8785) and encoded as UTF-8.
- **Digest**: `D(x) = "sha256:" + lower-case hex(SHA-256(JCS(x)))`.
- **Signatures**: Ed25519 (RFC 8032) over the canonical bytes, encoded as lower-case hex (64 bytes).
- **Keys**: JWK sets (RFC 7517; OKP/Ed25519 per RFC 8037) with a `kid` per key. Issuers and sealing services SHOULD publish their key sets at `/.well-known/aar-keys.json`, and SHOULD keep retired public keys published.
- **Salts**: MUST come from a cryptographically secure random generator and MUST NOT be reused across values.

## 4. The record

```json
{
  "payload": { "...": "section 4.1" },
  "issuer_sig": { "alg": "EdDSA", "kid": "<issuer key id>", "sig": "<hex Ed25519 signature over JCS(payload)>" },
  "seal": { "sealer_kid": "<sealer key id>", "seq": 42, "sealed_at": "<RFC 3339 UTC>", "sig": "<hex>" }
}
```

`seal` is present when a sealing service countersigned the record (section 5).

### 4.1 Payload fields

| Field | Required | Meaning |
|---|---|---|
| `aar_version` | yes | `"0.3"`. Verifiers MUST also accept `"0.2-mvp"`. |
| `receipt_id` | yes | `"urn:uuid:<uuid>"` |
| `phase` | yes | `decision`, `execution` or `confirmation`. An approval or rejection is a `decision` record. |
| `org_id` | yes | The operator's identifier. Not personal data. |
| `agent_id` | yes | The agent. Each agent has its own chain. |
| `run_id` | yes | Groups the actions of one conversation, job or session. |
| `action` | yes | `{ "type": <kind of action>, "target": <system it acts on> }`, for example `{ "type": "refund", "target": "stripe" }`. Never personal data. |
| `instance_commitment` | yes | Commitment to the exact action instance: its type, parameters and idempotency key. A writer MAY reuse the action's commitment on each of its records or commit afresh (new salt) on each; records of one action are linked by `decision_ref`, not by this value. |
| `authorization_ref` | yes | `D(rules)`: the version of the rules that decided. |
| `principal` | yes | Who decided: `"policy:<id>"`, or `"approver:<ref>"` for a person. |
| `approval` | no | `{ "method": "standing_mandate" \| "button" \| "passkey" \| "external", "approver"?, "at", "assertion_digest"?, "display_commitment"?, "binding"?, "evidence"? }` (section 4.3) |
| `consumption_commitment` | no | Commitment to limit usage at decision time (for example, money used today before and after). |
| `result` | yes | Decision: `allowed`, `held`, `denied`. Approval: `approved`, `rejected`, `expired`. Execution: `executed`, `failed`, `refused` (section 4.5). Confirmation: `confirmed`, `not_confirmed`. |
| `reasons` | yes | Reason codes (section 7). |
| `enforced` | yes | `false` when the decision was recorded but not applied (observe mode). |
| `decision_ref` | no | Approval, execution and confirmation records: the `receipt_id` of the record this one follows. |
| `target_ref_commitment` | no | Execution and confirmation: commitment to the system's identifier for what changed (a refund ID, a row key). |
| `state_before_commitment` | no | Execution: commitment to the affected state, read just before the change. |
| `state_after_commitment` | no | Execution: commitment to the same state, read just after. |
| `external_ref` | no | `{ "format", "digest", "id"? }`: a receipt in another format that this record adds evidence to (section 4.4). |
| `authorities` | no | Decision: the outside artifacts the decision relied on, each with its digest, validity window and status when checked (section 4.5). |
| `authority_check` | no | Execution: the authority set checked again just before the action committed (section 4.5). |
| `issued_at` | yes | RFC 3339 UTC. |
| `prev_receipt_hash` | no | `D(previous record of the same agent, including its seal)`. Absent only on an agent's first record. |

Payloads MUST NOT contain amounts, addresses, email addresses, customer identifiers or other personal data in clear. Such values belong behind commitments. Unknown fields MUST be preserved by verifiers (they are covered by the signature) and MAY be ignored.

### 4.2 Lifecycle of one action

1. **Decision**: `allowed`, `held` or `denied`, with reasons and the rules digest.
2. Optional **approval** (phase `decision`): `approved` or `rejected` by a named approver, or `expired`. `decision_ref` names the held decision.
3. **Execution**: `executed`, with `target_ref_commitment`, `state_before_commitment` and `state_after_commitment` where available, or `failed`, or `refused` when an authority the decision relied on changed before the action committed (section 4.5). If the operator's own system ran the action, the issuer records its report the same way.
4. **Confirmation**: the issuer (or another party) reads the system of record, read-only, and records `confirmed`, or `not_confirmed` with reason `outcome_missing` or `outcome_mismatch`. `decision_ref` names the execution record.

A `not_confirmed` result MUST be recorded as well. A missing confirmation is itself a signal, and verifiers SHOULD report it.

**State projections.** The state committed before and after is the minimal projection of the system of record that the action type changes. For example: refund `{ order, totalCents, refundedCents }`; store credit `{ customer balance }`; address change `{ shipping address }`; database delete `{ row count, primary keys }`. Implementations SHOULD document their projection per action type.

### 4.3 Approval evidence

An approval record carries `approval.method`, `approval.approver` (a stable reference, not an email address) and `approval.at`.

When `method` is `passkey`, the issuer MUST derive the WebAuthn challenge from the action and the decision:

```
challenge = base64url(SHA-256(JCS({
  "v": 1,
  "purpose": "<domain separator, e.g. \"oar.approval\">",
  "action_id": <receipt_id of the held decision>,
  "decision": "approve" | "reject",
  "instance_commitment": <the action's instance commitment>,
  "nonce": <fresh random value>
})))
```

The challenge MUST be single-use and short-lived. The issuer MUST verify the assertion (origin, relying party, user verification, signature counter) before recording the decision, MUST keep the full assertion so it can be disclosed, and records `assertion_digest = D(assertion as JSON)`. A verifier given the assertion, the approver's credential public key and the nonce can recompute the challenge and check that the approver's authenticator signed this decision for this action instance.

#### 4.3.1 Approval binding (version 2)

Version 2 records the value the approver confirmed inside the approval record, so verifiers can check it, and adds what the approver was shown. Payment rules ask for this: under PSD2's strong customer authentication (Delegated Regulation 2018/389, Article 5), the payer is made aware of the amount and the payee, and any change to either invalidates the authentication.

- **What the approver was shown.** The issuer MAY commit to the text and values displayed to the approver (for example `{ "text": "Pay $48,000.00 to payee P-1002", "amountCents": 4800000, "payee": "P-1002" }`) as `approval.display_commitment`, opened by a disclosure with field `display`.
- **The binding.** Before asking the approver, the issuer computes

  ```
  binding = D({
    "v": 2,
    "purpose": "oar.approval",
    "action_id": <receipt_id of the held decision>,
    "instance_commitment": <the approval record's instance_commitment>,
    "display_commitment": <approval.display_commitment, or null>,
    "nonce": <32 random bytes, lower-case hex>,
    "decision"?: "approve" | "reject"
  })
  ```

  and records `approval.binding = { "v": 2, "nonce", "decision"?, "digest": binding }`. `decision` is present when the approver's own device signs the decision (a passkey: one challenge per button); it is absent when an outside service returns the decision.
- **Passkeys.** The WebAuthn challenge is the 32 bytes of `binding`, base64url. The rules above on single use, verification and keeping the assertion apply.
- **Approval by an outside service** (`method: "external"`): a bank app, a SIM check, a digital identity wallet or another service confirms the approver. The issuer sends `binding` to the service, which SHOULD return it in its proof. The record MUST carry `approval.binding` and `approval.evidence = { "provider", "format", "digest", "id"? }`, where `digest` is `"sha256:" + hex(SHA-256(proof bytes exactly as received))`. The issuer MUST keep the proof so it can be disclosed. A verifier holding the proof checks its digest and that it confirms `binding`.
- A nonce MUST NOT be reused. A binding is valid for one approval record only.

Verifiers check every binding (section 6, check 7). An issuer cannot then record a binding made for another action, change what the approver was shown after the fact, or record "approved" where the approver's device signed a rejection, without the check failing.

The `button` method records a decision made in an authenticated session without an authenticator assertion; verifiers SHOULD treat it as weaker evidence. `standing_mandate` marks a decision allowed by the rules alone.

### 4.4 Adding evidence to another receipt format

Agent tool calls may already be recorded in another format (a signed decision receipt, a SCITT statement, a gateway's receipt). To add OAR's approval and outcome evidence without replacing that format, the issuer sets `external_ref` on the action's decision record:

```json
"external_ref": { "format": "acta", "digest": "sha256:<hex of the other receipt's bytes, exactly as issued>", "id": "<its identifier, optional>" }
```

The OAR records of the action then bind to that receipt. A verifier holding the other receipt checks that its digest matches.

### 4.5 Authority set and the re-check at commit

An agent action often relies on artifacts from outside the issuer: a delegated authorization (for example an AAuth or x401 token), an OAuth grant with authorization details (RFC 9396), a session, a payment mandate, a SIM or device check, or an outside approval service's result. Each can expire or be revoked between the moment the action is decided and the moment it commits. OAR binds those artifacts to the one action and records that they were checked again when it committed.

**At decision.** The decision record MAY carry `authorities`, a non-empty list:

```json
"authorities": [
  { "type": "aauth", "issuer": "https://auth.example", "digest": "sha256:<hex of the artifact's bytes, exactly as received>",
    "not_before": "2026-11-18T14:00:00Z", "expires_at": "2026-11-18T14:15:00Z",
    "checked_at": "2026-11-18T14:02:11Z", "status": "valid" }
]
```

| Field | Required | Meaning |
|---|---|---|
| `type` | yes | The kind of artifact, for example `aauth`, `x401`, `oauth-rar`, `session`, `mandate`, `sim-check`. Implementations MAY add types; verifiers treat them as opaque. |
| `issuer` | yes | Who issued it: a URL, domain or other stable identifier. Not personal data. |
| `digest` | yes | `sha256:<hex>` of the artifact's bytes exactly as received. The artifact itself is not in the record. |
| `not_before`, `expires_at` | no | The artifact's own validity window, RFC 3339 UTC. |
| `checked_at` | yes | When the issuer checked it, RFC 3339 UTC. |
| `status` | yes | What the check found: `valid`, `expired`, `revoked`, `invalid` or `unknown`. |

A decision with result `allowed`, or an approval with result `approved`, MUST NOT rely on an authority whose status is not `valid`. An authority recorded as `valid` MUST be inside its own validity window at `checked_at`. The record's signature covers the list, so the set cannot be changed later without the change showing.

**At commit.** Just before the action commits, the issuer checks every authority in the set again and records the result on the execution record:

```json
"authority_check": { "checked_at": "2026-11-18T14:04:02Z", "set_digest": "sha256:<hex>", "result": "current" }
```

- `set_digest` is `D({ v: 1, purpose: "oar.authorities", authorities })` over the decision's list, so the check names exactly the set it covers. The set is taken from the nearest record of the action, following `decision_ref` back, that carries `authorities`.
- `result` `current`: every authority was still valid at `checked_at`. The execution result is then `executed` or `failed`.
- `result` `changed`: at least one authority had expired, been revoked or become invalid. The action MUST NOT run, the execution result is `refused`, and `changes` MAY list which ones: `[{ "index": <position in the set, from 0>, "status": <new status> }]`. The reason code is `authority_revoked`, `authority_expired` or `authority_invalid` (section 7).
- An action whose decision carries `authorities` MUST NOT be recorded as `executed` without an `authority_check`.

The re-check is the issuer's own check of each artifact (a token introspection, a revocation list, a session lookup, a call to the approval service). OAR records what was checked, when, and with what result; it does not define how each kind of artifact is checked. If an authority cannot be checked at commit (its issuer cannot be reached), the action fails closed: it is `refused`, with reason `authority_invalid` or `system_unavailable`.

## 5. Sealing service, log and checkpoints (optional)

A record without a seal is **issuer-signed**: any later change to it shows, but the issuer could rewrite its own history. A sealing service closes that gap.

- The issuer sends `D(payload)` only. The sealer assigns the next sequence number `seq` (starting at 1) and signs `JCS({ "digest": D(payload), "seq": seq, "sealed_at": t })`.
- The sealer's log is hash-chained: `head_1 = D({ "prev": null, "digest", "seq", "sealed_at" })`, and `head_n = D({ "prev": head_(n-1), "digest", "seq", "sealed_at" })`.
- A **checkpoint** is the sealer's signature over `JCS({ "count": n, "head_digest": head_n, "at": t })`, published with `sealer_kid` and `sig`.
- The sealer MUST be operated separately from the issuer, with its own key and storage. An issuer SHOULD NOT execute an action whose decision could not be sealed (fail closed).

### 5.1 Outside timestamps on checkpoints (optional)

- A checkpoint MAY carry `anchors`: `[{ "type": "rfc3161", "tsa": <authority name>, "gen_time": <RFC 3339 UTC>, "token": <base64 DER> }]`. `anchors` is not covered by the sealer's signature; the token is its own proof.
- The **anchor digest** is `SHA-256(JCS({ count, head_digest, at, sealer_kid, sig }))`: the full signed checkpoint, so the timestamp also covers the sealer's signature. It is the token's message imprint.
- The token is an RFC 3161 TimeStampToken: CMS SignedData over a TSTInfo, signed by the authority, with its certificates included.
- Timestamping SHOULD NOT block sealing. A record newer than the latest timestamped checkpoint is reported as pending, not as a failure.

### 5.2 Evidence levels

Every verifier report states the level a record reached, so a stripped seal cannot pass unnoticed:

| Level | Meaning |
|---|---|
| `issuer-signed` | Signed by the issuer. Any change shows; the issuer could rewrite its own history. |
| `sealed` | Also countersigned by a separate sealing service and covered by its hash-chained log. |
| `timestamped` | Sealed, and the covering checkpoint carries a valid outside timestamp: nobody can change, delete or backdate the record without it showing. |

A timestamp proves when a record existed, not that it was true when it was made. Stronger assurance comes from a sealing service or confirmation run by a party other than the issuer.

## 6. Verification

Inputs: the records, the disclosures given (optional), the checkpoints, the issuer's and the sealer's public keys, and the root certificates accepted for outside timestamps. Verifiers report eight checks per record: `pass`, `fail` or `not_checked`.

1. **Issuer signature**: `issuer_sig.alg` is `EdDSA` and the signature verifies over `JCS(payload)` with the issuer key `kid`.
2. **Seal**: the seal verifies over `JCS({ digest: D(payload), seq, sealed_at })` with the sealer key. A record without a seal is `not_checked` (level `issuer-signed`) unless the verifier requires seals, in which case it fails.
3. **Chain**: group by `agent_id`; order by `seq` (records without a seal by `issued_at`); the first record has no `prev_receipt_hash`; each other record's `prev_receipt_hash` equals `D(previous record)`. For a partial set (`scope.complete` false), a missing predecessor is `not_checked`, not a failure.
4. **Checkpoint coverage**: take the valid checkpoint with the highest `count`. For a complete set, every `seq` from 1 to `count` is present exactly once and recomputing the log head gives `head_digest`. For a partial set, a valid seal with `seq <= count` passes.
5. **Disclosures**: for each disclosure, `D({ salt, value })` equals the record's commitment for that field (`instance`, `consumption`, `target_ref`, `state_before`, `state_after`, and `display` for `approval.display_commitment`).
6. **Outside timestamp**: take the first checkpoint with a valid sealer signature and an `anchors` entry whose `count` covers the record's `seq`. Its token passes when its message imprint equals the anchor digest; the `messageDigest` signed attribute equals the hash of the TSTInfo; the signature over the signed attributes verifies with the signer certificate (RSA PKCS#1 v1.5 or ECDSA); the signer certificate has the `timeStamping` extended key usage and was valid at `genTime`; and its chain reaches an accepted root. For a complete set, the records must also recompute that checkpoint's `head_digest`. Revocation is not checked.
7. **Approval binding**: for a record whose `approval` carries `binding`, or whose method is `external`: `binding.v` is 2, `binding.nonce` is 64 lower-case hex characters, `decision_ref` is present, and recomputing the binding (section 4.3.1) from `decision_ref`, `instance_commitment`, `approval.display_commitment`, the nonce and `decision` gives `binding.digest`; `decision` `approve` requires result `approved`, and `reject` requires `rejected`; an `external` approval carries `binding` and `evidence` with `provider`, `format` and a `sha256` digest. Records with neither are `not_checked`.
8. **Authority**: for a record that carries `authorities`: every entry has `type`, `issuer`, a `sha256` digest, `checked_at` and a known `status`; no entry recorded as `valid` is outside its own validity window at its `checked_at`; and a record with result `allowed` or `approved` has only `valid` entries. For an execution record that carries `authority_check`: an earlier record of the action carries `authorities`; recomputing the set digest gives `set_digest`; a `current` check names no authority that had expired by its `checked_at` and its record is not `refused`; a `changed` check has result `refused`. An execution with result `executed` whose action carries `authorities` but no `authority_check` fails. Records with neither are `not_checked`.

The result is `pass` only if no check fails anywhere. Verifiers SHOULD let users supply keys obtained independently (for example from the published key sets) to rule out a substituted bundle.

**Outcome.** Verifiers SHOULD also report each action's outcome from its records, grouping the records of one action by following `decision_ref` back to its first record: `confirmed`, `not_confirmed`, executed without confirmation, `failed`, held awaiting approval, approved without a recorded execution, `denied`, `rejected`, `expired`, or `refused` (not run: an authority changed before it committed).

**Outcome classes.** So that a relying party can act on an outcome without knowing every value, verifiers SHOULD also report one of three classes per action:

| Class | Outcomes | Meaning |
|---|---|---|
| `committed` | `confirmed` | The action ran, and the system of record shows the change. |
| `refused` | `denied`, `rejected`, `expired`, `refused` | The action did not run, and the records show why. |
| `unresolved` | every other outcome | The records do not show that the change happened: held, approved without a recorded execution, `failed`, executed without confirmation, or `not_confirmed`. |

Only `committed` means the change is known to have happened. A relying party SHOULD treat `unresolved` as not done until a later record resolves it.

## 7. Reason codes

Reason codes are short, stable strings in `snake_case`, for example `within_limits`, `needs_approval`, `over_approval_limit`, `over_maximum`, `daily_budget_exceeded`, `approved_by_person`, `rejected_by_person`, `executed`, `execution_failed`, `outcome_confirmed`, `outcome_missing`, `outcome_mismatch`. Implementations MAY add codes; verifiers MUST treat unknown codes as opaque.

**Common codes.** Where one of these fits, writers SHOULD use it rather than a code of their own, so that records from different systems read the same way:

| Code | Meaning |
|---|---|
| `new_payee` | The payment goes to a payee this organisation has not paid before. |
| `payee_details_changed` | The action changes where money is paid: a payee's or account's bank or payout details. |
| `identity_change_requires_approval` | The action changes who controls an account: an email address, phone number or login method. |
| `velocity_exceeded` | Too many actions of this kind in a short period, by this agent or for one customer. |
| `outside_working_hours` | The action was requested outside the hours the rules allow. |
| `agents_paused` | An emergency stop was in force, so no agent action could run. |
| `system_unavailable` | A check, the sealing service or an approval service could not be reached, so the action did not run (fail closed). |
| `rules_changed_since_decision` | The rules changed between the decision and the execution, so the action was checked again. |
| `override_by_person` | A person allowed an action that the rules alone would have denied. |
| `outcome_differs_from_approval` | What changed in the system of record differs from what the person approved. |
| `authority_revoked` | An authority the decision relied on was revoked before the action committed, so it did not run (section 4.5). |
| `authority_expired` | An authority the decision relied on expired before the action committed, so it did not run. |
| `authority_invalid` | An authority the decision relied on was found invalid, or could not be checked, before the action committed, so it did not run. |
| `authority_conflict` | Two authorities the action relied on disagree (for example, a mandate and an approval service), so the receiver's policy did not allow it. |

## 8. Bundles

A bundle is one JSON object:

| Field | Meaning |
|---|---|
| `format` | `"oar-bundle/0.1"`. Verifiers MUST also read `"aar-evidence/0.1"` packages, which call `records` `receipts`. |
| `generated_at` | RFC 3339 UTC. |
| `org` | `{ "id", "name" }` |
| `purpose` | Optional: `dispute`, `audit`, `insurance`, `board`, `debugging`. |
| `scope` | `{ "complete": boolean, "action_id"?, "from"?, "to"? }`. `complete` is true only when the bundle holds every record up to its latest checkpoint (or, without a sealing service, the agent's whole chain). |
| `records` | The records. |
| `disclosures` | Disclosures to open selected commitments. MAY be empty: the bundle still proves integrity, completeness and outcome without revealing values. |
| `checkpoints` | The sealer's signed checkpoints, with `anchors` where present. |
| `keys` | `{ "issuer": JWKS, "sealer"?: JWKS }` |
| `retention` | Optional: `{ "keep_until": <RFC 3339 date>, "basis"?: <short text, for example "AI Act Article 19, six months"> }`. A statement by whoever made the bundle about how long it should be kept (section 11.1). Not covered by any signature; verifiers MAY show it and MUST NOT fail a bundle because of it. |

Verifiers MUST ignore bundle fields they do not know.

## 9. Conformance

An implementation conforms when it reaches the expected result on every case in `vectors/manifest.json` and `vectors/compat/manifest.json`. The repository includes three conforming verifiers: the TypeScript reference verifier, a standalone verifier in plain JavaScript on WebCrypto (runs offline in a browser), and a Python verifier.

## 10. Security considerations

- **Issuer key compromise**: with a sealing service, an issuer key alone cannot rewrite sealed history. Keys SHOULD be rotated with new `kid`s, keeping old public keys published.
- **Who runs the sealer**: a sealer run by the same organisation as the issuer protects against edits by others (customers, staff without access to both keys) but not against the operator acting with both keys. Outside timestamps bound when records existed. A sealer or countersignature run by another party (for example the customer) gives stronger assurance.
- **State reads**: before and after state is read by the issuer. A compromised issuer could record false state; the confirmation, reproducible by anyone with read access to the system of record, limits this. Profiles MAY have the confirmation made by another party.
- **Withholding**: a verifier given a subset cannot detect records left out beyond the checkpoint count; complete bundles can.
- **Time**: times are claims of the issuer and sealer; an outside timestamp bounds them from above.
- **Timestamp authority**: verifiers trust their configured roots. Revocation is not checked; a compromised authority could backdate tokens.
- **Authorities**: records hold digests of outside artifacts, not the artifacts. A verifier can check that a given artifact is the one the decision relied on, but trusts the issuer's record of each status. The re-check at commit narrows the window in which a revoked authority could still be used to the time between `authority_check.checked_at` and the commit itself; issuers SHOULD keep that window short and SHOULD record the check as close to the commit as their systems allow.
- **Substituted bundles**: keys inside a bundle are a convenience. Verifiers SHOULD let users check against independently obtained keys.

## 11. Privacy considerations

Records hold commitments, not values. Fresh 32-byte salts make commitments to small value spaces (amounts) unguessable. Disclosures SHOULD be shared only with parties that need them. Approver references SHOULD be stable identifiers, not email addresses. WebAuthn assertions MAY contain authenticator data and SHOULD be disclosed only to verifiers who need them.

### 11.1 Retention and erasure

Records are append-only: deleting or editing one breaks the chain and the checkpoints, and verification reports it. Rules that require keeping records (for example, logs of high-risk AI systems for at least six months under the EU AI Act, Article 19) and rules that require erasing personal data on request can both apply to the same records. OAR separates the two:

- **Keep the records.** Records, seals and checkpoints hold digests and commitments, never values in clear (section 4.1). They SHOULD be kept for the longest period that applies.
- **Erase the openings.** The salt and value behind a commitment are kept apart from the records (as disclosures, or in the issuer's own store). To erase a value, the issuer deletes every copy of its salt and value. The commitment can then never be opened, and every check in section 6 still passes: check 5 covers only the disclosures given. The test vector `erased-values.json` shows this.
- **Keep salts and values apart from records,** so that each can be deleted without touching the records. Issuers SHOULD record where each salt is kept.
- A bundle MAY state how long it should be kept (`retention`, section 8).

Whether a commitment whose opening still exists is personal data depends on who holds the opening and on the law that applies. In the EU, the Court of Justice held in *EDPS v SRB* (C-413/23 P, 4 September 2025) that pseudonymised data is not personal data for a recipient who cannot reasonably re-identify the person, but stays personal data for a controller who can. Operators SHOULD confirm their approach with their own counsel.

## 12. Relationship to other work

OAR is a domain profile for agent actions. Its sealing service, signed statements and checkpoints follow the shape of the IETF SCITT architecture (RFC 9943): signed statements registered with a transparency service that returns receipts. The approval and outcome evidence (sections 4.2 to 4.4) is designed to be added to other agent receipt formats rather than replace them. A COSE encoding and a SCITT registration profile are planned.

### 12.1 Composing with other protocols

Protocols for agent identity and authorization (for example AAuth, x401 and OAuth 2.0 Rich Authorization Requests, RFC 9396) answer whether an agent may ask. Approval services answer whether a person agreed. OAR does not replace them: it records which of their artifacts one action relied on, and what each said when the action was decided and again when it committed (section 4.5). Two joins make this work:

1. **Authority to action**, at decision: the signed decision record binds the digest of each outside artifact to the one action instance (`instance_commitment`).
2. **Action to outcome**, at commit and after: the execution record binds the re-check to that set (`set_digest`), and the confirmation binds the action to what the system of record shows.

When several authorities apply and disagree, which one wins is the receiver's policy, not part of this format. The record shows the authorities, their statuses and the result, so the policy that was applied can be checked afterwards; a conflict the policy did not allow is recorded with `authority_conflict`.

### 12.2 Relying on an OAR record

A party that receives an OAR bundle (an auditor, an insurer, a payment network, a bank's fraud team) SHOULD:

- verify the bundle against keys it obtained independently (section 10);
- act on the outcome class (section 6), treating only `committed` as done;
- for an action that relied on outside authorities, check that the execution carries an `authority_check` with result `current`, and, where it holds an artifact, that the artifact's digest is in the set;
- for an approval, check the binding (check 7), and open `display` only where it needs to see what the approver was shown.

A verified record shows what the issuer recorded and that it has not been changed since. It does not show that the issuer's checks were correct; that rests on the issuer, the sealing service and the other evidence in section 10.

## 13. Changes

- **Since 0.4 (November 2026, draft)**: authority set and the re-check at commit (section 4.5, check 8); execution result `refused`; outcome classes `committed`, `refused` and `unresolved` (section 6); reason codes `authority_revoked`, `authority_expired`, `authority_invalid` and `authority_conflict` (section 7); composing with other protocols and relying on a record (sections 12.1 and 12.2). The new fields are optional; records still carry `aar_version` `"0.3"`.
- **0.4 (November 2026, draft)**: approval binding version 2, what the approver was shown, and approvals by an outside service (section 4.3.1, check 7); common reason codes (section 7); optional bundle field `retention` and the rule that verifiers ignore unknown bundle fields (section 8); retention and erasure (section 11.1). Records still carry `aar_version` `"0.3"`; the new fields are optional, and verifiers that predate them ignore them. A mapping to rules in the EU, the US and Canada is in `docs/REGULATORY-MAPPING.md`.
- **0.3 (October 2026, first public draft)**: `state_before_commitment` and `state_after_commitment`; the `confirmation` phase; outside timestamps on checkpoints; `external_ref`; the issuer-signed profile and evidence levels; bundle format `oar-bundle/0.1`.
- **0.2-mvp**: decision, approval and execution records; commitments; chain; sealing service and checkpoints; evidence packages (`aar-evidence/0.1`).
