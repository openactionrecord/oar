import { randomBytes } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { toJwk, type Jwks, type SigningKey } from './crypto/keys.js';
import { createSeal, nextLogHead, signCheckpoint, type CheckpointAnchor, type Seal, type SignedCheckpoint } from './record.js';
import { anchorDigest, verifyTimestampToken } from './timestamp/timestamp.js';
import { TSA_ROOTS, type TsaRoot } from './timestamp/tsa-roots.js';

// A sealing service countersigns each record's payload digest with a sequence number, keeps a hash-chained log
// and signs checkpoints over it. Run it as a separate service, with its own key, so that the writer of the
// records cannot rewrite them alone (examples/sealer-server.ts). It sees digests only, never record contents.

/** What a recorder needs from a sealing service, local or remote. */
export interface SealingService {
  seal(digest: string): Seal | Promise<Seal>;
  /** The service's public keys. */
  keys(): Jwks | Promise<Jwks>;
  /** Signed checkpoints so far (newest last). */
  checkpoints(): SignedCheckpoint[] | Promise<SignedCheckpoint[]>;
}

export interface LocalSealerOptions {
  key: SigningKey;
  /** Sign a checkpoint automatically every N seals (default 1: every seal). */
  checkpointEvery?: number;
  now?: () => Date;
}

export interface LocalSealer extends SealingService {
  seal(digest: string): Seal;
  keys(): Jwks;
  checkpoints(): SignedCheckpoint[];
  /** Signs a checkpoint over everything sealed so far (returns the latest if nothing is new). */
  checkpoint(): SignedCheckpoint | undefined;
  /** Gets an RFC 3161 timestamp for the latest checkpoint from an outside authority and attaches it. */
  anchor(tsa?: TsaOptions): Promise<CheckpointAnchor | undefined>;
}

/** An in-process sealing service. Its log lives in memory; persist `checkpoints()` and the seals if you need to. */
export function createLocalSealer(options: LocalSealerOptions): LocalSealer {
  const now = options.now ?? (() => new Date());
  const every = options.checkpointEvery ?? 1;
  let seq = 0;
  let head: string | null = null;
  let lastCheckpointed = 0;
  const signed: SignedCheckpoint[] = [];

  const sealer: LocalSealer = {
    seal(digest) {
      seq += 1;
      const sealedAt = now().toISOString();
      const seal = createSeal(digest, seq, sealedAt, options.key);
      head = nextLogHead(head, { seq, digest, sealed_at: sealedAt });
      if (seq - lastCheckpointed >= every) sealer.checkpoint();
      return seal;
    },
    keys: () => ({ keys: [toJwk(options.key)] }),
    checkpoints: () => signed,
    checkpoint() {
      if (head === null) return undefined;
      if (lastCheckpointed === seq) return signed[signed.length - 1];
      const cp = signCheckpoint({ count: seq, head_digest: head, at: now().toISOString() }, options.key);
      signed.push(cp);
      lastCheckpointed = seq;
      return cp;
    },
    async anchor(tsa = {}) {
      const cp = signed[signed.length - 1];
      if (!cp) return undefined;
      const stamped = await requestTimestamp(anchorDigest(cp), tsa);
      const anchor: CheckpointAnchor = { type: 'rfc3161', tsa: stamped.tsa, gen_time: stamped.genTime, token: stamped.token };
      cp.anchors = [...(cp.anchors ?? []), anchor];
      return anchor;
    },
  };
  return sealer;
}

export const DEFAULT_TSA_URL = 'http://timestamp.digicert.com';

export interface TsaOptions {
  /** The authority's RFC 3161 endpoint. Default: DigiCert's free public timestamp service. */
  url?: string;
  fetch?: typeof fetch;
  /** Roots the answer must chain to. Default: the bundled DigiCert roots. */
  roots?: readonly TsaRoot[];
  timeoutMs?: number;
}

export class TimestampError extends Error {
  override name = 'TimestampError';
}

/** An RFC 3161 TimeStampReq (DER) for a SHA-256 digest, asking for the authority's certificates. */
export function timestampRequest(imprintHex: string, nonce: Uint8Array): Uint8Array {
  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1' }),
      hashedMessage: new asn1js.OctetString({ valueHex: Buffer.from(imprintHex, 'hex') }),
    }),
    nonce: new asn1js.Integer({ valueHex: nonce }),
    certReq: true,
  });
  return new Uint8Array(req.toSchema().toBER(false));
}

/** Asks an outside authority for a timestamp over `imprintHex` (SHA-256) and checks the answer. */
export async function requestTimestamp(imprintHex: string, tsa: TsaOptions = {}): Promise<{ token: string; tsa: string; genTime: string }> {
  const nonce = randomBytes(8);
  nonce[0] = nonce[0]! & 0x7f; // keep the nonce positive
  let res: Response;
  try {
    res = await (tsa.fetch ?? fetch)(tsa.url ?? DEFAULT_TSA_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
      body: Buffer.from(timestampRequest(imprintHex, nonce)),
      signal: AbortSignal.timeout(tsa.timeoutMs ?? 10_000),
    });
  } catch {
    throw new TimestampError('The timestamp authority could not be reached.');
  }
  if (!res.ok) throw new TimestampError(`The timestamp authority answered with an error (${res.status}).`);

  let token: string;
  let tokenNonce: string | undefined;
  try {
    const resp = pkijs.TimeStampResp.fromBER(new Uint8Array(await res.arrayBuffer()));
    if (resp.status.status !== pkijs.PKIStatus.granted && resp.status.status !== pkijs.PKIStatus.grantedWithMods) throw new Error('refused');
    if (!resp.timeStampToken) throw new Error('no token');
    token = Buffer.from(resp.timeStampToken.toSchema().toBER(false)).toString('base64');
    const signedData = new pkijs.SignedData({ schema: resp.timeStampToken.content });
    const eContent = signedData.encapContentInfo.eContent!;
    const tstDer = eContent.idBlock.isConstructed
      ? Buffer.concat((eContent.valueBlock.value as asn1js.OctetString[]).map((c) => Buffer.from(c.valueBlock.valueHexView)))
      : Buffer.from(eContent.valueBlock.valueHexView);
    const tst = pkijs.TSTInfo.fromBER(new Uint8Array(tstDer));
    tokenNonce = tst.nonce ? Buffer.from(tst.nonce.valueBlock.valueHexView).toString('hex').replace(/^(00)+/, '') : undefined;
  } catch {
    throw new TimestampError('The timestamp authority did not return a timestamp.');
  }
  if (tokenNonce !== Buffer.from(nonce).toString('hex').replace(/^(00)+/, '')) throw new TimestampError('The timestamp does not answer this request.');

  const checked = verifyTimestampToken(token, imprintHex, tsa.roots ?? TSA_ROOTS);
  if (!checked.ok) throw new TimestampError(`The timestamp does not verify: ${checked.reason}`);
  return { token, tsa: checked.tsa, genTime: checked.genTime };
}
