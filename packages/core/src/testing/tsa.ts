import { webcrypto } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

type Crypto = typeof webcrypto;
type CryptoKey = webcrypto.CryptoKey;
type SubtleCrypto = webcrypto.SubtleCrypto;
import type { TsaRoot } from '../timestamp/tsa-roots.js';

// A test RFC 3161 time-stamping authority, for tests and test vectors only. It issues real tokens (CMS SignedData
// over a TSTInfo) under its own test root, which verifiers accept only when it is passed in explicitly.

pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto }) as never);

const SHA256 = '2.16.840.1.101.3.4.2.1';

export interface TestTsaKeys {
  /** PKCS#8, base64. */
  root: string;
  tsa: string;
}

export interface TestTsa {
  name: string;
  roots: TsaRoot[];
  keys: TestTsaKeys;
  /** A token over `imprintHex` (SHA-256), signed at `genTime`. */
  issue(imprintHex: string, genTime: Date, nonce?: bigint): Promise<string>;
  /** Answers an RFC 3161 TimeStampReq (DER) with a TimeStampResp (DER), as an authority's HTTP endpoint would. */
  respond(request: Uint8Array, genTime: Date): Promise<Uint8Array>;
}

export interface TestTsaOptions {
  algorithm?: 'RSA' | 'ECDSA';
  /** Fixed keys make RSA tokens byte-for-byte repeatable (for test vectors). */
  keys?: TestTsaKeys;
  name?: string;
}

const NOT_BEFORE = new Date('2026-01-01T00:00:00Z');
const NOT_AFTER = new Date('2036-01-01T00:00:00Z');

function algorithms(kind: 'RSA' | 'ECDSA') {
  return kind === 'RSA'
    ? { generate: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } }
    : { generate: { name: 'ECDSA', namedCurve: 'P-256' }, import: { name: 'ECDSA', namedCurve: 'P-256' } };
}

async function keyPair(kind: 'RSA' | 'ECDSA', pkcs8?: string): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey; pkcs8: string }> {
  const subtle = webcrypto.subtle as unknown as SubtleCrypto;
  const alg = algorithms(kind);
  if (!pkcs8) {
    const pair = (await subtle.generateKey(alg.generate as never, true, ['sign', 'verify'])) as { privateKey: CryptoKey; publicKey: CryptoKey };
    return { ...pair, pkcs8: Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey)).toString('base64') };
  }
  const privateKey = await subtle.importKey('pkcs8', Buffer.from(pkcs8, 'base64'), alg.import as never, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', privateKey);
  const publicJwk = kind === 'RSA' ? { kty: jwk.kty, n: jwk.n, e: jwk.e } : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const publicKey = await subtle.importKey('jwk', publicJwk, alg.import as never, true, ['verify']);
  return { privateKey, publicKey, pkcs8 };
}

function name(cn: string): pkijs.RelativeDistinguishedNames {
  return new pkijs.RelativeDistinguishedNames({
    typesAndValues: [new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: cn }) })],
  });
}

async function certificate(input: {
  serial: number;
  subject: string;
  issuer: string;
  publicKey: CryptoKey;
  signingKey: CryptoKey;
  ca: boolean;
}): Promise<pkijs.Certificate> {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: input.serial });
  cert.subject = name(input.subject);
  cert.issuer = name(input.issuer);
  cert.notBefore.value = NOT_BEFORE;
  cert.notAfter.value = NOT_AFTER;
  await cert.subjectPublicKeyInfo.importKey(input.publicKey);
  cert.extensions = input.ca
    ? [
        new pkijs.Extension({ extnID: '2.5.29.19', critical: true, extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false) }),
        new pkijs.Extension({ extnID: '2.5.29.15', critical: true, extnValue: new asn1js.BitString({ valueHex: new Uint8Array([0x06]).buffer, unusedBits: 1 }).toBER(false) }),
      ]
    : [new pkijs.Extension({ extnID: '2.5.29.37', critical: true, extnValue: new pkijs.ExtKeyUsage({ keyPurposes: ['1.3.6.1.5.5.7.3.8'] }).toSchema().toBER(false) })];
  await cert.sign(input.signingKey, 'SHA-256');
  return cert;
}

export async function createTestTsa(options: TestTsaOptions = {}): Promise<TestTsa> {
  const kind = options.algorithm ?? 'RSA';
  const tsaName = options.name ?? 'OAR Test Timestamp Authority';
  const rootKeys = await keyPair(kind, options.keys?.root);
  const tsaKeys = await keyPair(kind, options.keys?.tsa);
  const rootCert = await certificate({ serial: 1, subject: 'OAR Test TSA Root', issuer: 'OAR Test TSA Root', publicKey: rootKeys.publicKey, signingKey: rootKeys.privateKey, ca: true });
  const tsaCert = await certificate({ serial: 2, subject: tsaName, issuer: 'OAR Test TSA Root', publicKey: tsaKeys.publicKey, signingKey: rootKeys.privateKey, ca: false });
  const rootDer = new Uint8Array(rootCert.toSchema(true).toBER(false));
  const sha = new Uint8Array(await webcrypto.subtle.digest('SHA-256', rootDer));
  const roots: TsaRoot[] = [{ name: 'OAR Test TSA Root', sha256: Buffer.from(sha).toString('hex'), der: Buffer.from(rootDer).toString('base64') }];
  let serial = 1;

  const issue = async (imprintHex: string, genTime: Date, nonce?: bigint): Promise<string> => {
    const tstInfo = new pkijs.TSTInfo({
      version: 1,
      policy: '1.3.6.1.4.1.99999.1',
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256 }),
        hashedMessage: new asn1js.OctetString({ valueHex: Buffer.from(imprintHex, 'hex') }),
      }),
      serialNumber: new asn1js.Integer({ value: serial++ }),
      genTime,
      ...(nonce !== undefined ? { nonce: new asn1js.Integer({ valueHex: bigintBytes(nonce) }) } : {}),
    });
    const tstDer = tstInfo.toSchema().toBER(false);
    const digest = await webcrypto.subtle.digest('SHA-256', tstDer);
    const signed = new pkijs.SignedData({
      version: 3,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.9.16.1.4', eContent: new asn1js.OctetString({ valueHex: tstDer }) }),
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({ issuer: tsaCert.issuer, serialNumber: tsaCert.serialNumber }),
          signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: [
              new pkijs.Attribute({ type: '1.2.840.113549.1.9.3', values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.16.1.4' })] }),
              new pkijs.Attribute({ type: '1.2.840.113549.1.9.4', values: [new asn1js.OctetString({ valueHex: digest })] }),
            ],
          }),
        }),
      ],
      certificates: [tsaCert],
    });
    await signed.sign(tsaKeys.privateKey, 0, 'SHA-256');
    const contentInfo = new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: signed.toSchema(true) });
    return Buffer.from(contentInfo.toSchema().toBER(false)).toString('base64');
  };

  const respond = async (request: Uint8Array, genTime: Date): Promise<Uint8Array> => {
    const req = pkijs.TimeStampReq.fromBER(request);
    const imprint = Buffer.from(req.messageImprint.hashedMessage.valueBlock.valueHexView).toString('hex');
    const nonce = req.nonce ? BigInt(`0x${Buffer.from(req.nonce.valueBlock.valueHexView).toString('hex') || '0'}`) : undefined;
    const token = await issue(imprint, genTime, nonce);
    const resp = new pkijs.TimeStampResp({
      status: new pkijs.PKIStatusInfo({ status: pkijs.PKIStatus.granted }),
      timeStampToken: pkijs.ContentInfo.fromBER(Buffer.from(token, 'base64')),
    });
    return new Uint8Array(resp.toSchema().toBER(false));
  };

  return { name: tsaName, roots, keys: { root: rootKeys.pkcs8, tsa: tsaKeys.pkcs8 }, issue, respond };
}

function bigintBytes(n: bigint): ArrayBuffer {
  let hex = n.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  if (/^[89a-f]/.test(hex)) hex = `00${hex}`;
  return new Uint8Array(Buffer.from(hex, 'hex')).buffer;
}
