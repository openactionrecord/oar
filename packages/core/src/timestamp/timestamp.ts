import { X509Certificate, createHash, verify as verifySignature } from 'node:crypto';
import * as asn1js from 'asn1js';
import { canonicalBytes } from '../crypto/canonical.js';
import type { SignedCheckpoint } from '../record.js';
import { TSA_ROOTS, type TsaRoot } from './tsa-roots.js';

// Outside timestamps on checkpoints: an RFC 3161 time-stamping authority signs the digest of
// a signed checkpoint, so the operator cannot later rewrite or backdate the records it covers without it showing.
// This is the reference check of a timestamp token (asn1js for the structure, node:crypto for signatures and
// certificates). The standalone verifier (standalone.ts) checks the same token with its own code on WebCrypto.


/** SHA-256 (hex) of the signed checkpoint, the value the authority timestamps. Covers the sealer's signature too. */
export function anchorDigest(cp: Pick<SignedCheckpoint, 'count' | 'head_digest' | 'at' | 'sealer_kid' | 'sig'>): string {
  const body = { count: cp.count, head_digest: cp.head_digest, at: cp.at, sealer_kid: cp.sealer_kid, sig: cp.sig };
  return createHash('sha256').update(canonicalBytes(body)).digest('hex');
}

export type TimestampResult = { ok: true; genTime: string; tsa: string; root: string } | { ok: false; reason: string };

const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  messageDigest: '1.2.840.113549.1.9.4',
  timeStamping: '1.3.6.1.5.5.7.3.8',
} as const;

const HASHES: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

// Signature algorithms the verifiers accept: RSA PKCS#1 v1.5 and ECDSA (RSA-PSS is not accepted).
const SIGNATURES = new Set([
  '1.2.840.113549.1.1.1',
  '1.2.840.113549.1.1.11',
  '1.2.840.113549.1.1.12',
  '1.2.840.113549.1.1.13',
  '1.2.840.10045.4.3.2',
  '1.2.840.10045.4.3.3',
  '1.2.840.10045.4.3.4',
]);

class TokenError extends Error {}

type Node = asn1js.AsnType;

function parse(bytes: Uint8Array): Node {
  // Copy first: Node's pooled Buffers are views into a shared ArrayBuffer, which asn1js would read from offset 0.
  const { result, offset } = asn1js.fromBER(new Uint8Array(bytes).buffer);
  if (offset === -1 || result.error) throw new TokenError('The timestamp token is not valid DER.');
  return result;
}

function kids(node: Node | undefined): Node[] {
  const value = (node as { valueBlock?: { value?: unknown } } | undefined)?.valueBlock?.value;
  return Array.isArray(value) ? (value as Node[]) : [];
}

function at(node: Node | undefined, i: number): Node {
  const child = kids(node)[i];
  if (!child) throw new TokenError('The timestamp token is incomplete.');
  return child;
}

function isContext(node: Node | undefined, tag: number): boolean {
  return node?.idBlock.tagClass === 3 && node.idBlock.tagNumber === tag;
}

function oidOf(node: Node): string {
  if (!(node instanceof asn1js.ObjectIdentifier)) throw new TokenError('The timestamp token has an unexpected structure.');
  return node.valueBlock.toString();
}

/**
 * The content of an OCTET STRING, read from the encoding (asn1js decodes content that looks like ASN.1 itself).
 * A constructed (chunked) OCTET STRING, as some CMS encoders write, is joined.
 */
function octets(node: Node): Uint8Array {
  if (!(node instanceof asn1js.OctetString)) throw new TokenError('The timestamp token has an unexpected structure.');
  return contentOf(der(node));
}

function contentOf(tlv: Uint8Array): Uint8Array {
  const first = tlv[1] ?? 0;
  const content = tlv.subarray(first < 0x80 ? 2 : 2 + (first & 0x7f));
  if (tlv[0] !== 0x24) return content;
  const chunks: Uint8Array[] = [];
  for (const chunk of kids(parse(Uint8Array.from([0x30, ...lengthBytes(content.length), ...content])))) chunks.push(contentOf(der(chunk)));
  return Uint8Array.from(chunks.flatMap((c) => [...c]));
}

function lengthBytes(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return [0x80 | bytes.length, ...bytes];
}

function der(node: Node): Uint8Array {
  return new Uint8Array(node.valueBeforeDecodeView);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function serialHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex').replace(/^(00)+/, '').toUpperCase();
}

function commonName(cert: X509Certificate): string {
  const cn = cert.subject.split('\n').find((line) => line.startsWith('CN='));
  return cn ? cn.slice(3) : cert.subject.replace(/\n/g, ', ');
}

function validAt(cert: X509Certificate, when: Date): boolean {
  return new Date(cert.validFrom) <= when && when <= new Date(cert.validTo);
}

/**
 * Checks an RFC 3161 timestamp token: it timestamps `imprintHex` (SHA-256), its signature is valid, and the
 * signing certificate is a timestamping certificate that chains to one of `roots` and was valid at the time.
 * Certificate revocation is not checked.
 */
export function verifyTimestampToken(token: string, imprintHex: string, roots: readonly TsaRoot[] = TSA_ROOTS): TimestampResult {
  try {
    return check(token, imprintHex, roots);
  } catch (error) {
    return { ok: false, reason: error instanceof TokenError ? error.message : 'The timestamp token could not be read.' };
  }
}

function check(token: string, imprintHex: string, roots: readonly TsaRoot[]): TimestampResult {
  const contentInfo = parse(Buffer.from(token, 'base64'));
  if (oidOf(at(contentInfo, 0)) !== OID.signedData) throw new TokenError('This is not a timestamp token.');
  const signedData = at(at(contentInfo, 1), 0);
  const parts = kids(signedData);

  // encapContentInfo: the TSTInfo the authority signed.
  const encap = at(signedData, 2);
  if (oidOf(at(encap, 0)) !== OID.tstInfo) throw new TokenError('This is not a timestamp token.');
  const tstInfoDer = octets(at(at(encap, 1), 0));
  const tstInfo = parse(tstInfoDer);
  const imprint = at(tstInfo, 2);
  if (oidOf(at(at(imprint, 0), 0)) !== '2.16.840.1.101.3.4.2.1') throw new TokenError('The timestamp does not use SHA-256.');
  if (Buffer.from(octets(at(imprint, 1))).toString('hex') !== imprintHex) {
    throw new TokenError('The timestamp is for a different checkpoint.');
  }
  const genNode = at(tstInfo, 4);
  if (!(genNode instanceof asn1js.GeneralizedTime)) throw new TokenError('The timestamp has no time.');
  const genTime = genNode.toDate();

  const certs = kids(parts.find((p) => isContext(p, 0))).map((c) => new X509Certificate(Buffer.from(der(c))));
  const signerInfo = at(parts[parts.length - 1], 0);
  const sid = at(signerInfo, 1);
  const digestOid = oidOf(at(at(signerInfo, 2), 0));
  const hash = HASHES[digestOid];
  if (!hash) throw new TokenError('The timestamp uses an unsupported hash algorithm.');
  const signedAttrs = at(signerInfo, 3);
  if (!isContext(signedAttrs, 0)) throw new TokenError('The timestamp has no signed attributes.');
  if (!SIGNATURES.has(oidOf(at(at(signerInfo, 4), 0)))) throw new TokenError('The timestamp uses an unsupported signature algorithm.');
  const signature = octets(at(signerInfo, 5));

  // The signed attributes must carry the digest of the TSTInfo.
  const digestAttr = kids(signedAttrs).find((attr) => oidOf(at(attr, 0)) === OID.messageDigest);
  if (!digestAttr) throw new TokenError('The timestamp has no message digest.');
  const expectedDigest = createHash(hash).update(tstInfoDer).digest();
  if (!equalBytes(octets(at(at(digestAttr, 1), 0)), expectedDigest)) throw new TokenError('The timestamp token was changed after signing.');

  // The signer is named by issuer and serial number, or (rarely) by a key identifier; then it is the
  // certificate whose key verifies the signature.
  const candidates = isContext(sid, 0)
    ? certs
    : certs.filter((c) => serialHex(Buffer.from(c.serialNumber, 'hex')) === serialHex((at(sid, 1) as asn1js.Integer).valueBlock.valueHexView));
  if (candidates.length === 0) throw new TokenError("The timestamp token does not include the authority's certificate.");

  // The signature covers the DER of the signed attributes as a SET (tag 0x31 instead of [0]).
  const attrsDer = der(signedAttrs);
  const toVerify = Buffer.concat([Buffer.from([0x31]), Buffer.from(attrsDer.subarray(1))]);
  const signer = candidates.find((c) => verifySignature(hash, toVerify, c.publicKey, signature));
  if (!signer) throw new TokenError('The timestamp signature does not verify.');

  if (!(signer.keyUsage ?? []).includes(OID.timeStamping)) throw new TokenError("The signing certificate is not a timestamping certificate.");
  if (!validAt(signer, genTime)) throw new TokenError("The authority's certificate was not valid at the time of the timestamp.");

  const root = chainToRoot(signer, certs, roots, genTime);
  return { ok: true, genTime: genTime.toISOString(), tsa: commonName(signer), root: root.name };
}

/** Follows issuers from the signer, through the token's certificates, to one of the accepted roots. */
function chainToRoot(signer: X509Certificate, certs: X509Certificate[], roots: readonly TsaRoot[], when: Date): TsaRoot {
  const trusted = roots.map((r) => ({ root: r, cert: new X509Certificate(Buffer.from(r.der, 'base64')) }));
  let current = signer;
  for (let depth = 0; depth < 6; depth++) {
    const fingerprint = current.fingerprint256.replace(/:/g, '').toLowerCase();
    const self = trusted.find((t) => t.root.sha256 === fingerprint);
    if (self) return self.root;
    const anchor = trusted.find((t) => current.checkIssued(t.cert) && current.verify(t.cert.publicKey));
    if (anchor) {
      if (!validAt(anchor.cert, when)) throw new TokenError('The root certificate was not valid at the time of the timestamp.');
      return anchor.root;
    }
    const issuer = certs.find((c) => c !== current && current.checkIssued(c) && current.verify(c.publicKey));
    if (!issuer) throw new TokenError("The authority's certificate does not chain to a recognised root.");
    if (!validAt(issuer, when)) throw new TokenError('A certificate in the chain was not valid at the time of the timestamp.');
    current = issuer;
  }
  throw new TokenError('The certificate chain is too long.');
}
