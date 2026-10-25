// A second, independent OAR verifier in plain JavaScript, using only the platform's WebCrypto (Ed25519 and
// SHA-256) and an RFC 8785 canonicalization of a few lines. It shares no code with verify.ts on purpose: it runs
// in the playground page and in offline verify.html files, years later, with nothing installed.
// Tests check that it reaches the same result as the reference verifier, including on tampered bundles.
//
// Kept as source text (not compiled code) so it can be embedded as-is in a self-contained HTML file.
//
// Outside timestamps (RFC 3161) are checked with a small DER reader of its own and WebCrypto (RSA PKCS#1 v1.5
// and ECDSA), against the bundled root certificates of the timestamp authority.

import type { webcrypto } from 'node:crypto';
import { TSA_ROOTS } from './timestamp/tsa-roots.js';

type SubtleCrypto = webcrypto.SubtleCrypto;

export const STANDALONE_VERIFIER_JS = `var OAR_TSA_ROOTS = ${JSON.stringify(TSA_ROOTS)};\n` + String.raw`async function oarVerifyBundle(pkg, subtle, opts) {
  var enc = new TextEncoder();
  var LABELS = { issuer_signature: 'Issuer signature', seal: 'Seal', chain: 'Chain', checkpoint: 'Checkpoint coverage', disclosures: 'Disclosures', timestamp: 'Outside timestamp' };
  var FIELDS = { instance: 'instance_commitment', consumption: 'consumption_commitment', target_ref: 'target_ref_commitment', state_before: 'state_before_commitment', state_after: 'state_after_commitment' };
  function jcs(v) {
    if (v === null || typeof v !== 'object') {
      if (typeof v === 'number' && !isFinite(v)) throw new Error('number cannot be canonicalized');
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) return '[' + v.map(function (x) { return x === undefined ? 'null' : jcs(x); }).join(',') + ']';
    return '{' + Object.keys(v).filter(function (k) { return v[k] !== undefined; }).sort().map(function (k) { return JSON.stringify(k) + ':' + jcs(v[k]); }).join(',') + '}';
  }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
  function fromHex(h) {
    if (typeof h !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(h)) throw new Error('bad hex');
    var a = new Uint8Array(h.length / 2);
    for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  }
  function fromB64u(s) {
    var b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
    return Uint8Array.from(b, function (c) { return c.charCodeAt(0); });
  }
  async function digest(v) { return 'sha256:' + hex(await subtle.digest('SHA-256', enc.encode(jcs(v)))); }
  async function sigOk(set, kid, value, sigHex) {
    var jwk = ((set && set.keys) || []).find(function (k) { return k.kid === kid && k.kty === 'OKP' && k.crv === 'Ed25519'; });
    if (!jwk) return false;
    try {
      var key = await subtle.importKey('raw', fromB64u(jwk.x), { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, fromHex(sigHex), enc.encode(jcs(value)));
    } catch (e) { return false; }
  }

  var keys = pkg.keys || {};
  var partial = !(pkg.scope && pkg.scope.complete);
  var requireSeal = !!(opts && opts.requireSeal);
  var messages = [];
  var entries = [];
  for (var envelope of pkg.records || pkg.receipts || []) {
    var p = envelope.payload || {};
    var r = { receiptId: String(p.receipt_id), agentId: String(p.agent_id), phase: p.phase, type: p.action && p.action.type, result: 'pass', level: 'issuer-signed', outcome: p.result, checks: { issuer_signature: 'fail', seal: 'fail', chain: 'not_checked', checkpoint: 'not_checked', disclosures: 'not_checked', timestamp: 'not_checked' }, messages: [] };
    var sig = envelope.issuer_sig || {};
    if (sig.alg === 'EdDSA' && (await sigOk(keys.issuer, sig.kid, p, sig.sig))) r.checks.issuer_signature = 'pass';
    else r.messages.push('The issuer signature does not match this record.');
    var sealValid = false;
    if (envelope.seal) {
      sealValid = await sigOk(keys.sealer, envelope.seal.sealer_kid, { digest: await digest(p), seq: envelope.seal.seq, sealed_at: envelope.seal.sealed_at }, envelope.seal.sig);
      if (sealValid) r.checks.seal = 'pass';
      else r.messages.push('The seal does not match this record.');
    } else if (requireSeal) r.messages.push('This record has not been sealed.');
    else { r.checks.seal = 'not_checked'; r.messages.push('Issuer-signed only: not countersigned by a separate sealing service.'); }
    entries.push({ envelope: envelope, report: r, sealValid: sealValid });
  }

  // Chain: each agent's records link through prev_receipt_hash, in seal order.
  var byAgent = {};
  entries.forEach(function (e) { (byAgent[e.report.agentId] = byAgent[e.report.agentId] || []).push(e); });
  for (var agent in byAgent) {
    var list = byAgent[agent].slice().sort(function (a, b) {
      var sa = a.envelope.seal ? a.envelope.seal.seq : Infinity, sb = b.envelope.seal ? b.envelope.seal.seq : Infinity;
      return sa !== sb ? sa - sb : String(a.envelope.payload.issued_at).localeCompare(String(b.envelope.payload.issued_at));
    });
    for (var i = 0; i < list.length; i++) {
      var e = list[i], prev = e.envelope.payload.prev_receipt_hash;
      if (i === 0) {
        if (prev === undefined) e.report.checks.chain = 'pass';
        else if (!partial) { e.report.checks.chain = 'fail'; e.report.messages.push('The record before this one is missing.'); }
      } else if (prev !== undefined && prev === (await digest(list[i - 1].envelope))) e.report.checks.chain = 'pass';
      else if (!(partial && prev !== undefined)) { e.report.checks.chain = 'fail'; e.report.messages.push('This record does not link to the previous record.'); }
    }
  }

  // Checkpoints: the sealer's signed count and log head over everything sealed so far.
  var checkpointFailed = false, latest = null;
  for (var cp of pkg.checkpoints || []) {
    if (await sigOk(keys.sealer, cp.sealer_kid, { count: cp.count, head_digest: cp.head_digest, at: cp.at }, cp.sig)) { if (!latest || cp.count > latest.count) latest = cp; }
    else { checkpointFailed = true; messages.push('A checkpoint has an invalid sealer signature.'); }
  }
  if (latest) {
    var covered = entries.filter(function (e) { return e.envelope.seal && e.envelope.seal.seq <= latest.count; });
    if (partial) covered.forEach(function (e) { e.report.checks.checkpoint = e.sealValid ? 'pass' : 'fail'; });
    else {
      var bySeq = {}, ok = true;
      covered.forEach(function (e) { if (bySeq[e.envelope.seal.seq]) ok = false; bySeq[e.envelope.seal.seq] = e; });
      var head = null;
      for (var s = 1; ok && s <= latest.count; s++) {
        var at = bySeq[s];
        if (!at) { ok = false; break; }
        head = await digest({ prev: head, digest: await digest(at.envelope.payload), seq: s, sealed_at: at.envelope.seal.sealed_at });
      }
      ok = ok && head === latest.head_digest;
      if (!ok) { checkpointFailed = true; messages.push('The records do not match the sealer\'s latest checkpoint.'); }
      var culprits = ok ? [] : covered.filter(function (e) { return !e.sealValid; });
      covered.forEach(function (e) { e.report.checks.checkpoint = ok || (culprits.length > 0 && e.sealValid) ? 'pass' : 'fail'; });
    }
  }

  // ---- Outside timestamps (RFC 3161): a minimal DER reader, X.509 and CMS on WebCrypto ----
  function tlv(buf, pos) {
    var tag = buf[pos], p = pos + 1, len = buf[p++];
    if (tag === undefined || len === undefined || (tag & 0x1f) === 0x1f) throw new Error('bad DER');
    if (len & 0x80) { var n = len & 0x7f; if (n < 1 || n > 4) throw new Error('bad DER'); len = 0; for (var i = 0; i < n; i++) len = len * 256 + buf[p++]; }
    if (p + len > buf.length) throw new Error('bad DER');
    return { tag: tag, raw: buf.subarray(pos, p + len), c: buf.subarray(p, p + len), next: p + len };
  }
  function der(buf) { return tlv(buf, 0); }
  function kids(n) { var out = [], p = 0; while (n && p < n.c.length) { var k = tlv(n.c, p); out.push(k); p = k.next; } return out; }
  function kid(n, i) { var k = kids(n)[i]; if (!k) throw new Error('incomplete'); return k; }
  function oid(n) {
    if (n.tag !== 6) throw new Error('not an OID');
    var b = n.c, parts = b[0] < 80 ? [Math.floor(b[0] / 40), b[0] % 40] : [2, b[0] - 80], v = 0;
    for (var i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
    return parts.join('.');
  }
  function octets(n) {
    if (n.tag === 4) return n.c;
    if (n.tag === 0x24) { var chunks = kids(n).map(octets), out = new Uint8Array(chunks.reduce(function (a, c) { return a + c.length; }, 0)), o = 0; chunks.forEach(function (c) { out.set(c, o); o += c.length; }); return out; }
    throw new Error('not an OCTET STRING');
  }
  function time(n) {
    var s = String.fromCharCode.apply(null, Array.from(n.c)), m;
    if (n.tag === 0x17 && (m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s))) { var yy = +m[1]; return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, m[2] - 1, +m[3], +m[4], +m[5], +m[6])); }
    if (n.tag === 0x18 && (m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z$/.exec(s))) return new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + (m[7] ? Math.round(parseFloat(m[7]) * 1000) : 0));
    throw new Error('bad time');
  }
  function same(a, b) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  function unpad(a) { var i = 0; while (i < a.length - 1 && a[i] === 0) i++; return a.subarray(i); }
  function b64(s) { return Uint8Array.from(atob(String(s)), function (c) { return c.charCodeAt(0); }); }
  var HASH = { '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
  var SIGHASH = { '1.2.840.113549.1.1.11': 'SHA-256', '1.2.840.113549.1.1.12': 'SHA-384', '1.2.840.113549.1.1.13': 'SHA-512', '1.2.840.10045.4.3.2': 'SHA-256', '1.2.840.10045.4.3.3': 'SHA-384', '1.2.840.10045.4.3.4': 'SHA-512' };
  var CURVES = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };
  function cert(raw) {
    var c = der(raw), t = kids(kid(c, 0)), i = t[0].tag === 0xa0 ? 1 : 0, spki = t[i + 5], alg = kid(spki, 0);
    var subject = t[i + 4], cn = 'unknown', eku = [];
    kids(subject).forEach(function (rdn) { kids(rdn).forEach(function (atv) { var a = kids(atv); if (oid(a[0]) === '2.5.4.3') cn = new TextDecoder().decode(a[1].c); }); });
    var exts = t.find(function (k) { return k.tag === 0xa3; });
    if (exts) kids(kid(exts, 0)).forEach(function (ext) { var e = kids(ext); if (oid(e[0]) === '2.5.29.37') eku = kids(der(e[e.length - 1].c)).map(oid); });
    return { raw: raw, tbs: kid(c, 0).raw, sigAlg: oid(kid(kid(c, 1), 0)), sig: kid(c, 2).c.subarray(1), serial: t[i].c, issuer: t[i + 2].raw, subject: subject.raw,
      notBefore: time(kid(t[i + 3], 0)), notAfter: time(kid(t[i + 3], 1)), spki: spki.raw, keyAlg: oid(kid(alg, 0)), curve: kids(alg)[1] && kids(alg)[1].tag === 6 ? oid(kids(alg)[1]) : null, eku: eku, cn: cn };
  }
  async function signedBy(c, hashName, sig, data) {
    try {
      if (!hashName) return false;
      if (c.keyAlg === '1.2.840.113549.1.1.1') {
        var rk = await subtle.importKey('spki', c.spki, { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['verify']);
        return await subtle.verify('RSASSA-PKCS1-v1_5', rk, sig, data);
      }
      var curve = CURVES[c.curve];
      if (c.keyAlg !== '1.2.840.10045.2.1' || !curve) return false;
      var s = der(sig), raw = new Uint8Array(curve[1] * 2);
      [kid(s, 0).c, kid(s, 1).c].forEach(function (x, j) { x = unpad(x); if (x.length > curve[1]) throw new Error('bad signature'); raw.set(x, (j + 1) * curve[1] - x.length); });
      var ek = await subtle.importKey('spki', c.spki, { name: 'ECDSA', namedCurve: curve[0] }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: hashName }, ek, raw, data);
    } catch (e) { return false; }
  }
  async function timestampCheck(token, imprintHex, roots) {
    function no(reason) { return { ok: false, reason: reason }; }
    try {
      var ci = der(b64(token));
      if (oid(kid(ci, 0)) !== '1.2.840.113549.1.7.2') return no('This is not a timestamp token.');
      var parts = kids(kid(kid(ci, 1), 0)), encap = parts[2];
      if (oid(kid(encap, 0)) !== '1.2.840.113549.1.9.16.1.4') return no('This is not a timestamp token.');
      var tst = octets(kid(kid(encap, 1), 0)), info = der(tst), imprint = kid(info, 2);
      if (oid(kid(kid(imprint, 0), 0)) !== '2.16.840.1.101.3.4.2.1') return no('The timestamp does not use SHA-256.');
      if (hex(octets(kid(imprint, 1))) !== imprintHex) return no('The timestamp is for a different checkpoint.');
      var gen = time(kid(info, 4));
      var certNode = parts.find(function (k) { return k.tag === 0xa0; });
      var certs = certNode ? kids(certNode).map(function (k) { return cert(k.raw); }) : [];
      var si = kids(kid(parts[parts.length - 1], 0)), hashName = HASH[oid(kid(si[2], 0))];
      if (!hashName) return no('The timestamp uses an unsupported hash algorithm.');
      if (si[3].tag !== 0xa0) return no('The timestamp has no signed attributes.');
      if (!(oid(kid(si[4], 0)) in SIGHASH) && oid(kid(si[4], 0)) !== '1.2.840.113549.1.1.1' && oid(kid(si[4], 0)) !== '1.2.840.10045.2.1') return no('The timestamp uses an unsupported signature algorithm.');
      var md = null;
      kids(si[3]).forEach(function (a) { var ak = kids(a); if (oid(ak[0]) === '1.2.840.113549.1.9.4') md = octets(kid(ak[1], 0)); });
      if (!md || hex(md) !== hex(await subtle.digest(hashName, tst))) return no('The timestamp token was changed after signing.');
      var signedAttrs = new Uint8Array(si[3].raw); signedAttrs[0] = 0x31;
      var candidates = si[1].tag === 0x30 ? certs.filter(function (c) { return same(unpad(c.serial), unpad(kid(si[1], 1).c)); }) : certs;
      if (!candidates.length) return no("The timestamp token does not include the authority's certificate.");
      var signer = null, signature = octets(si[5]);
      for (var c of candidates) if (await signedBy(c, hashName, signature, signedAttrs)) { signer = c; break; }
      if (!signer) return no('The timestamp signature does not verify.');
      if (signer.eku.indexOf('1.3.6.1.5.5.7.3.8') < 0) return no('The signing certificate is not a timestamping certificate.');
      if (!(signer.notBefore <= gen && gen <= signer.notAfter)) return no("The authority's certificate was not valid at the time of the timestamp.");
      var trusted = roots.map(function (r) { return { root: r, cert: cert(b64(r.der)) }; }), cur = signer;
      for (var depth = 0; depth < 6; depth++) {
        var fp = hex(await subtle.digest('SHA-256', cur.raw)), self = trusted.find(function (t) { return t.root.sha256 === fp; });
        if (self) return { ok: true, genTime: gen.toISOString(), tsa: signer.cn };
        var up = null;
        for (var t of trusted) if (same(cur.issuer, t.cert.subject) && (await signedBy(t.cert, SIGHASH[cur.sigAlg], cur.sig, cur.tbs))) { up = t; break; }
        if (up) {
          if (!(up.cert.notBefore <= gen && gen <= up.cert.notAfter)) return no('The root certificate was not valid at the time of the timestamp.');
          return { ok: true, genTime: gen.toISOString(), tsa: signer.cn };
        }
        var next = null;
        for (var k of certs) if (k !== cur && same(cur.issuer, k.subject) && (await signedBy(k, SIGHASH[cur.sigAlg], cur.sig, cur.tbs))) { next = k; break; }
        if (!next) return no("The authority's certificate does not chain to a recognised root.");
        if (!(next.notBefore <= gen && gen <= next.notAfter)) return no('A certificate in the chain was not valid at the time of the timestamp.');
        cur = next;
      }
      return no('The certificate chain is too long.');
    } catch (e) { return no('The timestamp token could not be read.'); }
  }

  // Each sealed record is timestamped by the first checkpoint with an outside timestamp that covers it.
  var tsaRoots = (opts && opts.tsaRoots) || OAR_TSA_ROOTS, timestampFailed = false, stamp = null;
  var anchored = [];
  for (var acp of pkg.checkpoints || []) {
    if (acp.anchors && acp.anchors.length && (await sigOk(keys.sealer, acp.sealer_kid, { count: acp.count, head_digest: acp.head_digest, at: acp.at }, acp.sig))) anchored.push(acp);
  }
  anchored.sort(function (a, b) { return a.count - b.count; });
  var heads = {};
  if (!partial) {
    var bySeqH = {};
    entries.forEach(function (e) { if (e.envelope.seal) bySeqH[e.envelope.seal.seq] = e; });
    var h = null;
    for (var q = 1; bySeqH[q]; q++) { h = await digest({ prev: h, digest: await digest(bySeqH[q].envelope.payload), seq: q, sealed_at: bySeqH[q].envelope.seal.sealed_at }); heads[q] = h; }
  }
  for (var a of anchored) {
    var anchor = a.anchors.find(function (x) { return x.type === 'rfc3161'; });
    var res = anchor
      ? await timestampCheck(anchor.token, hex(await subtle.digest('SHA-256', enc.encode(jcs({ count: a.count, head_digest: a.head_digest, at: a.at, sealer_kid: a.sealer_kid, sig: a.sig })))), tsaRoots)
      : { ok: false, reason: 'The timestamp is of an unsupported type.' };
    if (res.ok && heads[a.count] && heads[a.count] !== a.head_digest) res = { ok: false, reason: 'The records do not match the timestamped checkpoint.' };
    a.__stamp = res;
    if (!res.ok) { timestampFailed = true; messages.push('The outside timestamp on checkpoint ' + a.count + ' does not verify: ' + res.reason); }
    else stamp = { tsa: res.tsa, at: res.genTime, count: a.count };
  }
  var pending = 0;
  entries.forEach(function (e) {
    if (!e.envelope.seal || !e.sealValid) return;
    var by = anchored.find(function (c) { return c.count >= e.envelope.seal.seq; });
    if (!by) { pending++; e.report.messages.push('Sealed; outside timestamp pending.'); return; }
    e.report.checks.timestamp = by.__stamp.ok ? 'pass' : 'fail';
    if (!by.__stamp.ok) e.report.messages.push('The outside timestamp covering this record does not verify: ' + by.__stamp.reason);
  });
  anchored.forEach(function (c) { delete c.__stamp; });
  if (stamp) messages.push('Timestamped by ' + stamp.tsa + ' at ' + stamp.at + ': the records up to seal ' + stamp.count + ' existed then and have not changed since.');
  if (pending > 0) messages.push(stamp ? pending + (pending === 1 ? ' record is' : ' records are') + ' newer than the latest outside timestamp, so ' + (pending === 1 ? 'its timestamp is' : 'their timestamps are') + ' pending until the next one.' : 'No outside timestamp covers these records yet.');

  // Disclosures: each disclosed value with its salt must reproduce the commitment in the record.
  var byId = {};
  entries.forEach(function (e) { byId[e.report.receiptId] = e; });
  for (var d of pkg.disclosures || []) {
    var target = byId[d.receiptId];
    if (!target) { messages.push('A disclosure refers to a record that is not included.'); continue; }
    var commitment = target.envelope.payload[FIELDS[d.field]];
    var good = typeof commitment === 'string' && /^[0-9a-f]{64}$/.test(d.salt) && commitment === (await digest({ salt: d.salt, value: d.value }));
    if (good) { if (target.report.checks.disclosures !== 'fail') target.report.checks.disclosures = 'pass'; }
    else { target.report.checks.disclosures = 'fail'; target.report.messages.push('The disclosed ' + String(d.field).replace('_', ' ') + ' details do not match the record.'); }
  }

  var failedChecks = [];
  var LEVELS = ['issuer-signed', 'sealed', 'timestamped'];
  var LEVEL_TEXT = { 'issuer-signed': 'Issuer-signed', sealed: 'Sealed by a separate service', timestamped: 'Sealed and timestamped by an outside authority' };
  var lowest = 2;
  entries.forEach(function (e) {
    for (var k in e.report.checks) if (e.report.checks[k] === 'fail' && failedChecks.indexOf(k) < 0) failedChecks.push(k);
    e.report.result = Object.values(e.report.checks).indexOf('fail') >= 0 ? 'fail' : 'pass';
    e.report.level = e.report.checks.timestamp === 'pass' ? 'timestamped' : e.report.checks.seal === 'pass' ? 'sealed' : 'issuer-signed';
    lowest = Math.min(lowest, LEVELS.indexOf(e.report.level));
  });
  var level = entries.length ? LEVELS[lowest] : 'issuer-signed';
  if (checkpointFailed && failedChecks.indexOf('checkpoint') < 0) failedChecks.push('checkpoint');
  if (timestampFailed && failedChecks.indexOf('timestamp') < 0) failedChecks.push('timestamp');
  var failed = checkpointFailed || timestampFailed || entries.some(function (e) { return e.report.result === 'fail'; });
  messages.unshift(failed ? 'Verification failed: ' + failedChecks.map(function (c) { return LABELS[c]; }).join(', ') + ' check failed.' : 'All ' + entries.length + ' records passed verification. Evidence level: ' + LEVEL_TEXT[level] + '.');
  return { result: failed ? 'fail' : 'pass', level: level, receipts: entries.map(function (e) { return e.report; }), failedChecks: failedChecks, messages: messages, checkpoint: latest ? { count: latest.count, at: latest.at } : null, timestamp: stamp };
}`;

export interface StandaloneReport {
  result: 'pass' | 'fail';
  level: 'issuer-signed' | 'sealed' | 'timestamped';
  receipts: { receiptId: string; agentId: string; phase: string; type?: string; outcome: string; result: 'pass' | 'fail'; level: string; checks: Record<string, 'pass' | 'fail' | 'not_checked'>; messages: string[] }[];
  failedChecks: string[];
  messages: string[];
  checkpoint: { count: number; at: string } | null;
  /** The latest checkpoint with a valid outside timestamp. */
  timestamp: { tsa: string; at: string; count: number } | null;
}

export interface StandaloneOptions {
  /** Root certificates accepted for outside timestamps; defaults to the bundled DigiCert roots. */
  tsaRoots?: { name: string; sha256: string; der: string }[];
  /** Fail records that carry no seal. */
  requireSeal?: boolean;
}

type StandaloneVerifier = (pkg: unknown, subtle: SubtleCrypto, options?: StandaloneOptions) => Promise<StandaloneReport>;

/** Loads the standalone verifier as a function (browser or Node 20+, which both have WebCrypto Ed25519). */
export function loadStandaloneVerifier(): StandaloneVerifier {
  return new Function(`${STANDALONE_VERIFIER_JS}; return oarVerifyBundle;`)() as StandaloneVerifier;
}

/**
 * A self-contained, offline verifier page: open it in any modern browser, with no network, to check the evidence
 * bundle embedded in it (or any other bundle, chosen from disk). No external scripts, styles or requests.
 */
export function standaloneVerifierHtml(embeddedPackageJson?: string): string {
  // Keep the embedded JSON from closing the script element early.
  const embedded = embeddedPackageJson ? embeddedPackageJson.replace(/</g, '\\u003c') : 'null';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Open Action Record verifier</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;color:#1c2421;margin:32px auto;max-width:980px;padding:0 16px}
h1{font-size:20px;margin:0} .muted{color:#5b6660} code{font-size:12px}
.badge{display:inline-block;padding:6px 12px;border-radius:999px;font-weight:600;margin:12px 0}
.pass{color:#1f5f3f} .fail{color:#b42318;font-weight:600} .not_checked{color:#5b6660}
.badge.pass{background:#e6f2ec} .badge.fail{background:#fbe9e7}
table{border-collapse:collapse;width:100%;margin-top:12px} th,td{border-bottom:1px solid #dde2df;padding:6px 8px;text-align:left;vertical-align:top}
.box{border:1px solid #dde2df;border-radius:12px;padding:12px 16px;margin-top:16px}
</style></head><body>
<h1>Open Action Record verifier</h1>
<p class="muted">Checks Open Action Records (OAR): each record's issuer signature, its seal from a separate sealing service (when present), the hash chain, the sealing service's signed checkpoint, the outside timestamp on it, and any disclosed details. Runs entirely in this page, with no network: nothing is sent anywhere.</p>
<div class="box"><label>Check another bundle: <input type="file" id="file" accept=".json,application/json"></label></div>
<div id="out"><p class="muted">Checking…</p></div>
<script>
${STANDALONE_VERIFIER_JS}
var EMBEDDED = ${embedded};
var LABEL = { pass: 'pass', fail: 'FAIL', not_checked: 'not checked' };
var CHECKS = [['issuer_signature', 'Issuer signature'], ['seal', 'Seal'], ['chain', 'Chain'], ['checkpoint', 'Checkpoint'], ['timestamp', 'Timestamp'], ['disclosures', 'Disclosures']];
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function fp(set) { return ((set && set.keys) || []).map(function (k) { return esc(k.kid) + ' (' + esc(String(k.x).slice(0, 16)) + '…)'; }).join(', '); }
async function show(pkg) {
  var out = document.getElementById('out');
  if (!window.crypto || !crypto.subtle) { out.innerHTML = '<p class="fail">This browser has no WebCrypto. Use a current Chrome, Edge, Firefox or Safari.</p>'; return; }
  try {
    var r = await oarVerifyBundle(pkg, crypto.subtle);
    var rows = r.receipts.map(function (x) {
      return '<tr><td><code>' + esc(x.receiptId.replace('urn:uuid:', '').slice(0, 8)) + '</code></td><td>' + esc(x.phase) + '</td><td>' + esc(x.outcome) + '</td>' +
        CHECKS.map(function (c) { return '<td class="' + x.checks[c[0]] + '">' + LABEL[x.checks[c[0]]] + '</td>'; }).join('') +
        '<td class="muted">' + esc(x.messages.join(' ')) + '</td></tr>';
    }).join('');
    out.innerHTML = '<div class="badge ' + r.result + '">' + (r.result === 'pass' ? 'Verified · ' + esc(r.level) : 'Verification failed') + '</div>' +
      '<p>' + r.messages.map(esc).join('<br>') + '</p>' +
      '<p class="muted">' + esc(pkg.org && pkg.org.name) + (pkg.purpose ? ' · ' + esc(pkg.purpose) : '') + ' · generated ' + esc(pkg.generated_at) + ' · ' + r.receipts.length + ' records' +
      (r.checkpoint ? ' · checkpoint covers ' + r.checkpoint.count + ' seals (' + esc(r.checkpoint.at) + ')' : '') + '</p>' +
      '<table><thead><tr><th>Record</th><th>Phase</th><th>Result</th>' + CHECKS.map(function (c) { return '<th>' + c[1] + '</th>'; }).join('') + '<th>Notes</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<p class="muted">Keys used, from the bundle: issuer ' + fp(pkg.keys && pkg.keys.issuer) + (pkg.keys && pkg.keys.sealer ? '; sealer ' + fp(pkg.keys.sealer) : '; no sealing service') + '. To rule out a substituted bundle, compare them with the keys the issuer and the sealing service publish (/.well-known/aar-keys.json).</p>';
  } catch (e) { out.innerHTML = '<p class="fail">This file is not a bundle this verifier can read.</p>'; }
}
document.getElementById('file').addEventListener('change', function (ev) {
  var f = ev.target.files[0]; if (!f) return;
  f.text().then(function (t) { try { show(JSON.parse(t)); } catch (e) { document.getElementById('out').innerHTML = '<p class="fail">Not a JSON file.</p>'; } });
});
if (EMBEDDED) show(EMBEDDED); else document.getElementById('out').innerHTML = '<p class="muted">Choose a bundle (.json) to check.</p>';
</script>
</body></html>`;
}
