import { randomBytes, randomUUID } from 'node:crypto';
import { commitmentFor } from './crypto/commitment.js';
import { canonicalDigest, isSha256Digest } from './crypto/hash.js';
import { toJwk, type SigningKey } from './crypto/keys.js';
import { BUNDLE_FORMAT, type Bundle, type BundlePurpose } from './bundle.js';
import {
  OAR_VERSION,
  payloadHash,
  recordHash,
  signRecord,
  type ApprovalMethod,
  type ExternalRef,
  type OarRecord,
  type Payload,
  type RecordResult,
} from './record.js';
import type { SealingService } from './sealer.js';
import { actionKey } from './summary.js';
import type { DisclosureField, DisclosureInput, VerificationKeys } from './verify.js';

// The developer API: record what an agent's action did, step by step or around a function you already have.
//
//   const oar = createRecorder({ issuer, org: 'acme', agent: 'support-bot' });
//   const out = await oar.run({ type: 'refund', target: 'stripe', params, readState, execute, confirm });
//   const bundle = await oar.bundle();
//
// Values you pass as `params`, `usage`, state and target references are never written in clear: each record
// carries a salted commitment, and the recorder keeps the salts so you can disclose a value later, to the
// people who need it.

export interface RecorderOptions {
  /** The key that signs records. Generate one with `generateSigningKey()`; keep the private key secret. */
  issuer: SigningKey;
  /** Your organisation or app identifier. Not personal data. */
  org: string;
  /** The agent whose actions are recorded. One recorder per agent keeps one chain per agent. */
  agent: string;
  /** Identifies this run or session of the agent. Default: a random "run:<uuid>". */
  run?: string;
  /** A human-readable name for bundles. Default: `org`. */
  orgName?: string;
  /** A separate sealing service. Without one, records are issuer-signed only. */
  sealer?: SealingService;
  /** The rules that decide: an object (its digest is recorded) or a "sha256:<hex>" digest. */
  policy?: unknown;
  /** Names the rules in `principal` ("policy:<id>"). Default: "default". */
  policyId?: string;
  /**
   * This agent's earlier records, and their disclosures, when one agent's actions are recorded by more than one
   * process (a hook that runs once per tool call). The chain continues after the last record, actions in it can
   * be continued with `action(id)`, and `bundle()` includes them. Use the same `org`, `agent` and `run`.
   */
  history?: { records: readonly OarRecord[]; disclosures?: readonly DisclosureInput[] };
  /** For tests and reproducible vectors. */
  now?: () => Date;
  randomId?: () => string;
  randomSalt?: () => string;
}

export interface ActionInput {
  /** The kind of action: "refund", "store_credit", "db.delete", "deploy". */
  type: string;
  /** The system it acts on: "stripe", "shopify", "postgres". Never personal data. */
  target: string;
  /** The exact parameters. Committed, never written in clear. */
  params: Record<string, unknown>;
  /** Makes the instance unique; retries with the same key are the same action. Default: random. */
  idempotencyKey?: string;
  /** Limit usage at decision time, for example `{ todayCents: 1200, limitCents: 5000 }`. Committed. */
  usage?: unknown;
  /** The receipt in another format that this action's records add approval and outcome evidence to. */
  external?: ExternalRef;
}

export interface DecideInput extends ActionInput {
  result: 'allowed' | 'held' | 'denied';
  reasons?: string[];
  /** False to record without enforcing (observe mode). Default true. */
  enforced?: boolean;
}

export interface ActionHandle {
  /** The decision record's id ("urn:uuid:..."): the action's identifier. */
  readonly id: string;
  readonly type: string;
  readonly target: string;
  readonly instanceCommitment: string;
  /** The last record written for this action. */
  lastRecordId: string;
  status: 'allowed' | 'held' | 'denied' | 'approved' | 'rejected' | 'executed' | 'failed' | 'confirmed' | 'not_confirmed';
}

export interface ApproveInput {
  /** A stable reference to the person, for example "jordan" or an employee ID. Not an email address. */
  approver: string;
  approved?: boolean;
  method?: Exclude<ApprovalMethod, 'standing_mandate'>;
  /** Passkey approvals: the WebAuthn assertion (JSON). Its digest is recorded; keep the assertion to disclose it. */
  assertion?: unknown;
}

export interface ExecuteInput {
  /** The affected state read just before the change (for a refund: order total and amount refunded so far). */
  before?: unknown;
  /** The same state read just after. */
  after?: unknown;
  /** The identifier of what changed: a refund ID, a row key. Committed. */
  targetRef?: string;
  /** False when the change failed. Default true. */
  ok?: boolean;
  reasons?: string[];
}

export interface ConfirmInput {
  /** Whether the system of record, read back after the change, shows it. */
  confirmed: boolean;
  /** Default "outcome_confirmed" or "outcome_missing"; use "outcome_mismatch" when it shows something else. */
  reason?: 'outcome_confirmed' | 'outcome_missing' | 'outcome_mismatch';
  /** The identifier that was checked. Default: the execution's `targetRef`. */
  targetRef?: string;
}

export interface RunInput<T> extends ActionInput {
  /** Your rules. Return "held" to require a person's approval, "denied" to block. Default: allowed. */
  check?: (params: Record<string, unknown>) => CheckResult | Promise<CheckResult>;
  /** Asked when `check` holds the action. Without it, a held action stops at "held". */
  approve?: (action: ActionHandle) => ApproveInput | Promise<ApproveInput>;
  /** Reads the affected state from the system of record; called before and after `execute`. */
  readState?: () => unknown | Promise<unknown>;
  /** Does the action. Errors are recorded as a failed execution, then re-thrown. */
  execute: () => T | Promise<T>;
  /** The identifier of what changed, from the result (for a refund: the refund ID). */
  targetRef?: (result: T) => string | undefined;
  /** Reads the system of record again and says whether it shows the change. */
  confirm?: (result: T) => boolean | Promise<boolean>;
}

export interface CheckResult {
  result: 'allowed' | 'held' | 'denied';
  reasons?: string[];
}

export interface RunResult<T> {
  status: 'completed' | 'denied' | 'held' | 'rejected';
  /** True or false when `confirm` ran; undefined otherwise. */
  confirmed?: boolean;
  result?: T;
  action: ActionHandle;
}

export interface BundleOptions {
  /**
   * Which committed values to disclose in the bundle. Default "none": the bundle proves what happened without
   * revealing amounts, parameters or state. Use "all" for your own debugging, or list fields.
   */
  disclose?: 'none' | 'all' | DisclosureField[];
  purpose?: BundlePurpose;
  /** Only the records of this action. */
  actionId?: string;
}

export class Recorder {
  private readonly options: RecorderOptions;
  private readonly now: () => Date;
  private readonly randomId: () => string;
  private readonly randomSalt: () => string;
  private readonly run_id: string;
  private readonly authorizationRef: string;
  private readonly policyPrincipal: string;
  private readonly written: OarRecord[] = [];
  private readonly secrets: DisclosureInput[] = [];
  private readonly actions = new Map<string, { handle: ActionHandle; principal: string; targetRef?: string; external?: ExternalRef }>();
  private queue: Promise<unknown> = Promise.resolve();
  private lastIssuedAt = 0;

  constructor(options: RecorderOptions) {
    if (!options.issuer?.kid || !options.issuer.privateKey) throw new TypeError('issuer: expected { kid, privateKey }');
    if (!options.org || !options.agent) throw new TypeError('org and agent are required');
    this.options = options;
    this.now = options.now ?? (() => new Date());
    this.randomId = options.randomId ?? (() => randomUUID());
    this.randomSalt = options.randomSalt ?? (() => randomBytes(32).toString('hex'));
    this.run_id = options.run ?? `run:${this.randomId()}`;
    this.authorizationRef = isSha256Digest(options.policy) ? options.policy : canonicalDigest(options.policy ?? { policy: 'none' });
    this.policyPrincipal = `policy:${options.policyId ?? 'default'}`;
    if (options.history) this.restore(options.history);
  }

  /** Every record written so far, oldest first. */
  get records(): readonly OarRecord[] {
    return this.written;
  }

  /** The salts and values behind this recorder's commitments, to keep (secretly) for later disclosure. */
  get disclosures(): readonly DisclosureInput[] {
    return this.secrets;
  }

  /** The handle of an action recorded by this recorder or found in its `history`; undefined if unknown. */
  action(id: string): ActionHandle | undefined {
    return this.actions.get(id)?.handle;
  }

  /** Records the decision on an action. Returns the handle to use for the next steps. */
  decide(input: DecideInput): Promise<ActionHandle> {
    return this.serial(async () => {
      validateAction(input);
      const id = this.newId();
      const instanceValue = { type: input.type, params: input.params, idempotency_key: input.idempotencyKey ?? id };
      const instance = this.commit(id, 'instance', instanceValue);
      const usage = input.usage === undefined ? undefined : this.commit(id, 'consumption', input.usage);
      const reasons = input.reasons ?? [input.result === 'allowed' ? 'within_limits' : input.result === 'held' ? 'needs_approval' : 'over_limit'];
      await this.write({
        receipt_id: id,
        phase: 'decision',
        action: { type: input.type, target: input.target },
        instance_commitment: instance,
        principal: this.policyPrincipal,
        ...(input.result === 'allowed' ? { approval: { method: 'standing_mandate' as const, at: this.stamp() } } : {}),
        ...(usage ? { consumption_commitment: usage } : {}),
        result: input.result,
        reasons,
        enforced: input.enforced ?? true,
        ...(input.external ? { external_ref: checkExternal(input.external) } : {}),
      });
      const handle: ActionHandle = { id, type: input.type, target: input.target, instanceCommitment: instance, lastRecordId: id, status: input.result };
      this.actions.set(id, { handle, principal: this.policyPrincipal, ...(input.external ? { external: input.external } : {}) });
      return handle;
    });
  }

  /** Records a person's approval or rejection of a held action. */
  approve(action: ActionHandle, input: ApproveInput): Promise<OarRecord> {
    return this.serial(async () => {
      const state = this.state(action);
      if (state.handle.status !== 'held') throw new Error(`Only a held action can be approved or rejected (this one is ${state.handle.status}).`);
      if (!input.approver || /@/.test(input.approver)) throw new TypeError('approver: a stable reference such as "jordan", not an email address');
      const approved = input.approved ?? true;
      const method = input.method ?? (input.assertion ? 'passkey' : 'button');
      const id = this.newId();
      const principal = `approver:${input.approver}`;
      const record = await this.write({
        receipt_id: id,
        phase: 'decision',
        action: { type: state.handle.type, target: state.handle.target },
        instance_commitment: state.handle.instanceCommitment,
        principal,
        approval: {
          method,
          approver: input.approver,
          at: this.stamp(),
          ...(input.assertion !== undefined ? { assertion_digest: canonicalDigest(input.assertion) } : {}),
        },
        result: approved ? 'approved' : 'rejected',
        reasons: [approved ? 'approved_by_person' : 'rejected_by_person'],
        enforced: true,
        decision_ref: state.handle.lastRecordId,
      });
      state.principal = principal;
      state.handle.lastRecordId = id;
      state.handle.status = approved ? 'approved' : 'rejected';
      return record;
    });
  }

  /** Records the execution, with commitments to the affected state before and after. */
  execute(action: ActionHandle, input: ExecuteInput = {}): Promise<OarRecord> {
    return this.serial(async () => {
      const state = this.state(action);
      if (state.handle.status !== 'allowed' && state.handle.status !== 'approved') {
        throw new Error(`Only an allowed or approved action can be executed (this one is ${state.handle.status}).`);
      }
      const ok = input.ok ?? true;
      const id = this.newId();
      const before = input.before === undefined ? undefined : this.commit(id, 'state_before', input.before);
      const after = input.after === undefined ? undefined : this.commit(id, 'state_after', input.after);
      const target = input.targetRef === undefined ? undefined : this.commit(id, 'target_ref', input.targetRef);
      const record = await this.write({
        receipt_id: id,
        phase: 'execution',
        action: { type: state.handle.type, target: state.handle.target },
        instance_commitment: state.handle.instanceCommitment,
        principal: state.principal,
        result: ok ? 'executed' : 'failed',
        reasons: input.reasons ?? [ok ? 'executed' : 'execution_failed'],
        enforced: true,
        decision_ref: state.handle.lastRecordId,
        ...(target ? { target_ref_commitment: target } : {}),
        ...(before ? { state_before_commitment: before } : {}),
        ...(after ? { state_after_commitment: after } : {}),
      });
      if (input.targetRef !== undefined) state.targetRef = input.targetRef;
      state.handle.lastRecordId = id;
      state.handle.status = ok ? 'executed' : 'failed';
      return record;
    });
  }

  /** Records whether the system of record, read back after the change, shows it. */
  confirm(action: ActionHandle, input: ConfirmInput): Promise<OarRecord> {
    return this.serial(async () => {
      const state = this.state(action);
      if (state.handle.status !== 'executed') throw new Error(`Only an executed action can be confirmed (this one is ${state.handle.status}).`);
      const id = this.newId();
      const targetRef = input.targetRef ?? state.targetRef;
      const target = targetRef === undefined ? undefined : this.commit(id, 'target_ref', targetRef);
      const record = await this.write({
        receipt_id: id,
        phase: 'confirmation',
        action: { type: state.handle.type, target: state.handle.target },
        instance_commitment: state.handle.instanceCommitment,
        principal: state.principal,
        result: input.confirmed ? 'confirmed' : 'not_confirmed',
        reasons: [input.reason ?? (input.confirmed ? 'outcome_confirmed' : 'outcome_missing')],
        enforced: true,
        decision_ref: state.handle.lastRecordId,
        ...(target ? { target_ref_commitment: target } : {}),
      });
      state.handle.lastRecordId = id;
      state.handle.status = input.confirmed ? 'confirmed' : 'not_confirmed';
      return record;
    });
  }

  /**
   * Wraps one action end to end: check, optional approval, state before, execute, state after, confirmation.
   * Every step is recorded, including denials, rejections and failures.
   */
  async run<T>(input: RunInput<T>): Promise<RunResult<T>> {
    const verdict = input.check ? await input.check(input.params) : { result: 'allowed' as const };
    const action = await this.decide({ ...input, result: verdict.result, ...(verdict.reasons ? { reasons: verdict.reasons } : {}) });
    if (verdict.result === 'denied') return { status: 'denied', action };
    if (verdict.result === 'held') {
      if (!input.approve) return { status: 'held', action };
      const answer = await input.approve(action);
      await this.approve(action, answer);
      if (answer.approved === false) return { status: 'rejected', action };
    }

    const before = input.readState ? await input.readState() : undefined;
    let result: T;
    try {
      result = await input.execute();
    } catch (error) {
      const after = input.readState ? await safely(input.readState) : undefined;
      await this.execute(action, { ok: false, ...(before !== undefined ? { before } : {}), ...(after !== undefined ? { after } : {}) });
      throw error;
    }
    const after = input.readState ? await input.readState() : undefined;
    const targetRef = input.targetRef?.(result);
    await this.execute(action, {
      ...(before !== undefined ? { before } : {}),
      ...(after !== undefined ? { after } : {}),
      ...(targetRef !== undefined ? { targetRef } : {}),
    });
    if (!input.confirm) return { status: 'completed', result, action };
    const confirmed = await input.confirm(result);
    await this.confirm(action, { confirmed });
    return { status: 'completed', confirmed, result, action };
  }

  /** The public keys a verifier needs. */
  async keys(): Promise<VerificationKeys> {
    return {
      issuer: { keys: [toJwk(this.options.issuer)] },
      ...(this.options.sealer ? { sealer: await this.options.sealer.keys() } : {}),
    };
  }

  /** A self-contained evidence bundle anyone can verify offline. */
  async bundle(options: BundleOptions = {}): Promise<Bundle> {
    await this.queue;
    const instance = options.actionId ? this.actions.get(options.actionId)?.handle.instanceCommitment : undefined;
    if (options.actionId && !instance) throw new Error(`Unknown action ${options.actionId}`);
    const records = options.actionId ? this.written.filter((r) => actionKey(r, this.written) === options.actionId) : [...this.written];
    const ids = new Set(records.map((r) => r.payload.receipt_id));
    const disclose = options.disclose ?? 'none';
    const disclosures =
      disclose === 'none' ? [] : this.secrets.filter((d) => ids.has(d.receiptId) && (disclose === 'all' || disclose.includes(d.field)));
    const checkpoints = this.options.sealer ? [...(await this.options.sealer.checkpoints())] : [];
    const latest = checkpoints.reduce((max, cp) => Math.max(max, cp.count), 0);
    const sealed = new Set(records.map((r) => r.seal?.seq).filter((s): s is number => s !== undefined));
    let complete = !instance;
    for (let seq = 1; complete && seq <= latest; seq++) complete = sealed.has(seq);
    const times = records.map((r) => r.payload.issued_at).sort();
    return {
      format: BUNDLE_FORMAT,
      generated_at: this.now().toISOString(),
      org: { id: this.options.org, name: this.options.orgName ?? this.options.org },
      ...(options.purpose ? { purpose: options.purpose } : {}),
      scope: {
        ...(options.actionId ? { action_id: options.actionId } : {}),
        ...(times.length ? { from: times[0]!, to: times[times.length - 1]! } : {}),
        complete,
      },
      records: structuredClone(records),
      disclosures: structuredClone(disclosures),
      checkpoints: structuredClone(checkpoints),
      keys: await this.keys(),
    };
  }

  // ---- internals ----

  private restore(history: NonNullable<RecorderOptions['history']>): void {
    const rootOf = new Map<string, string>();
    for (const record of history.records) {
      const p = record.payload;
      if (p.org_id !== this.options.org || p.agent_id !== this.options.agent) {
        throw new Error('history: every record must have the same org and agent as this recorder');
      }
      // A step whose earlier record is missing stays its own action; verification reports the gap.
      const root = p.decision_ref ? (rootOf.get(p.decision_ref) ?? p.decision_ref) : p.receipt_id;
      rootOf.set(p.receipt_id, root);
      const status = p.result as ActionHandle['status'];
      const known = this.actions.get(root);
      if (known) {
        known.handle.lastRecordId = p.receipt_id;
        known.handle.status = status;
        known.principal = p.principal;
      } else {
        const handle: ActionHandle = {
          id: root,
          type: p.action.type,
          target: p.action.target,
          instanceCommitment: p.instance_commitment,
          lastRecordId: p.receipt_id,
          status,
        };
        this.actions.set(root, { handle, principal: p.principal, ...(p.external_ref ? { external: p.external_ref } : {}) });
      }
      this.lastIssuedAt = Math.max(this.lastIssuedAt, Date.parse(p.issued_at));
      this.written.push(structuredClone(record));
    }
    this.secrets.push(...structuredClone(history.disclosures ?? []));
  }

  private serial<R>(fn: () => Promise<R>): Promise<R> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private state(action: ActionHandle) {
    const state = this.actions.get(action.id);
    if (!state) throw new Error(`Unknown action ${action.id}: it was not recorded by this recorder.`);
    return state;
  }

  private newId(): string {
    return `urn:uuid:${this.randomId()}`;
  }

  /** Strictly increasing timestamps, so records sort in the order they were written. */
  private stamp(): string {
    const t = Math.max(this.now().getTime(), this.lastIssuedAt + 1);
    this.lastIssuedAt = t;
    return new Date(t).toISOString();
  }

  private commit(receiptId: string, field: DisclosureField, value: unknown): string {
    const salt = this.randomSalt();
    const commitment = commitmentFor(value, salt);
    this.secrets.push({ receiptId, field, salt, value });
    return commitment;
  }

  private async write(
    fields: Omit<Payload, 'aar_version' | 'org_id' | 'agent_id' | 'run_id' | 'authorization_ref' | 'issued_at' | 'prev_receipt_hash'> & { result: RecordResult },
  ): Promise<OarRecord> {
    const prev = this.written[this.written.length - 1];
    const payload: Payload = {
      aar_version: OAR_VERSION,
      ...fields,
      org_id: this.options.org,
      agent_id: this.options.agent,
      run_id: this.run_id,
      authorization_ref: this.authorizationRef,
      issued_at: fields.approval?.at ?? this.stamp(),
      ...(prev ? { prev_receipt_hash: recordHash(prev) } : {}),
    };
    const record = signRecord(sortPayload(payload), this.options.issuer);
    if (this.options.sealer) record.seal = await this.options.sealer.seal(payloadHash(record.payload));
    this.written.push(record);
    return record;
  }
}

export function createRecorder(options: RecorderOptions): Recorder {
  return new Recorder(options);
}

/** Keeps payload keys in the order of the specification, for readable JSON (signatures do not depend on it). */
function sortPayload(p: Payload): Payload {
  const order: (keyof Payload)[] = [
    'aar_version', 'receipt_id', 'phase', 'org_id', 'agent_id', 'run_id', 'action', 'instance_commitment', 'authorization_ref', 'principal',
    'approval', 'consumption_commitment', 'result', 'reasons', 'enforced', 'decision_ref', 'target_ref_commitment',
    'state_before_commitment', 'state_after_commitment', 'external_ref', 'issued_at', 'prev_receipt_hash',
  ];
  const out: Record<string, unknown> = {};
  for (const key of order) if (p[key] !== undefined) out[key] = p[key];
  return out as unknown as Payload;
}

function validateAction(input: ActionInput): void {
  if (!input.type || typeof input.type !== 'string') throw new TypeError('type: expected a string such as "refund"');
  if (!input.target || typeof input.target !== 'string') throw new TypeError('target: expected a string such as "stripe"');
  if (typeof input.params !== 'object' || input.params === null || Array.isArray(input.params)) throw new TypeError('params: expected an object');
}

function checkExternal(ref: ExternalRef): ExternalRef {
  if (!ref.format || !isSha256Digest(ref.digest)) throw new TypeError('external: expected { format, digest: "sha256:<hex>" }');
  return { format: ref.format, digest: ref.digest, ...(ref.id ? { id: ref.id } : {}) };
}

async function safely<T>(fn: () => T | Promise<T>): Promise<T | undefined> {
  try {
    return await fn();
  } catch {
    return undefined;
  }
}
