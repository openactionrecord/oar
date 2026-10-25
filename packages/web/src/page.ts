import { STANDALONE_VERIFIER_JS } from '@openactionrecord/core/standalone';

// The playground: one static, self-contained HTML file. No external scripts, fonts or requests; bundles are
// verified with the standalone verifier on the browser's WebCrypto, and never leave the page.

const REPO = 'https://github.com/openactionrecord/oar';

export function playgroundHtml(samples: { valid: unknown; issuerSigned: unknown }): string {
  const json = (v: unknown) => JSON.stringify(v).replace(/</g, '\\u003c');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Open Action Record · playground</title>
<meta name="description" content="Verify Open Action Records in your browser: proof of what an AI agent's action actually changed, and who approved it. Nothing is uploaded.">
<meta property="og:title" content="Open Action Record (OAR)">
<meta property="og:description" content="Your agent says it did it. OAR proves what actually changed, and who approved it.">
<style>
:root{--bg:#fbfbf9;--panel:#ffffff;--ink:#16181a;--muted:#5f6670;--line:#e3e5e8;--accent:#0f766e;--accent-ink:#ffffff;--pass:#15803d;--pass-bg:#e8f5ec;--fail:#b42318;--fail-bg:#fdecea;--warn:#a15c07;--warn-bg:#fdf4e3;--code:#f3f4f2;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0f1113;--panel:#16191c;--ink:#eceef0;--muted:#9aa3ad;--line:#2a2f35;--accent:#2dd4bf;--accent-ink:#06201d;--pass:#4ade80;--pass-bg:#10291a;--fail:#f87171;--fail-bg:#2d1414;--warn:#fbbf24;--warn-bg:#2b2110;--code:#1d2125}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
header{padding:40px 0 24px;border-bottom:1px solid var(--line)}
.brand{font:600 13px/1 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font-size:clamp(28px,3.8vw,40px);line-height:1.12;margin:12px 0 12px;letter-spacing:-.02em;max-width:980px}
.lede{font-size:17px;color:var(--muted);max-width:760px;margin:0}
.lede b{color:var(--ink);font-weight:600}
.cta{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px;align-items:center}
.cmd{font:13px var(--mono);background:var(--code);border:1px solid var(--line);border-radius:8px;padding:8px 12px;user-select:all}
.btn{font:inherit;font-size:14px;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;padding:7px 12px;cursor:pointer}
.btn:hover{border-color:var(--muted)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600}
.btn.danger{color:var(--fail)}
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.15fr);gap:20px;padding:24px 0 40px}
@media (max-width:900px){main{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
.panel h2{font-size:13px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 12px}
.row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
textarea{width:100%;height:440px;resize:vertical;font:12px/1.5 var(--mono);color:var(--ink);background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px;tab-size:2}
.drop{font-size:13px;color:var(--muted);margin-top:8px}
.verdict{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 14px;border-radius:10px;font-weight:600;font-size:17px}
.verdict.pass{background:var(--pass-bg);color:var(--pass)} .verdict.fail{background:var(--fail-bg);color:var(--fail)}
.chip{font:600 12px var(--mono);padding:3px 8px;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
.msgs{color:var(--muted);font-size:13px;margin:8px 0 0;padding-left:18px}
.action{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-top:12px}
.action .top{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:baseline}
.action .what{font:600 14px var(--mono)}
.outcome{font-size:13px;font-weight:600}
.outcome.good{color:var(--pass)} .outcome.bad{color:var(--fail)} .outcome.wait{color:var(--warn)}
ol.steps{list-style:none;margin:10px 0 0;padding:0}
ol.steps li{display:grid;grid-template-columns:110px 1fr;gap:8px;font-size:14px;padding:3px 0}
ol.steps .ph{font:12px var(--mono);color:var(--muted);padding-top:2px}
.state{font:12px/1.5 var(--mono);background:var(--code);border-radius:6px;padding:6px 8px;margin-top:8px;overflow-x:auto;white-space:pre}
details{margin-top:14px} summary{cursor:pointer;color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px;display:block;overflow-x:auto}
th,td{border-bottom:1px solid var(--line);padding:5px 6px;text-align:left;white-space:nowrap}
td.pass{color:var(--pass)} td.fail{color:var(--fail);font-weight:700} td.not_checked{color:var(--muted)}
section.how{border-top:1px solid var(--line);padding:28px 0 8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.card h3{margin:0 0 6px;font-size:15px}
.card p{margin:0;color:var(--muted);font-size:14px}
pre.code{font:12.5px/1.55 var(--mono);background:var(--code);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto}
footer{border-top:1px solid var(--line);padding:20px 0 40px;color:var(--muted);font-size:13px}
.sr{position:absolute;left:-9999px}
</style>
</head>
<body>
<header><div class="wrap">
  <div class="brand">Open Action Record · OAR</div>
  <h1>Your agent says it did it.<br>OAR proves what actually changed, and who approved it.</h1>
  <p class="lede">An open record format for AI agent actions: the decision, <b>the person who approved this exact action</b>, <b>the state before and after</b>, and <b>a confirmation read back from the system of record</b>. Signed, chained, optionally sealed and timestamped, with no personal data in clear. This page verifies records <b>entirely in your browser</b>; nothing is uploaded.</p>
  <div class="cta">
    <span class="cmd">npx @openactionrecord/cli demo</span>
    <span class="cmd">npm i @openactionrecord/core</span>
    <a class="btn" href="${REPO}">GitHub</a>
    <a class="btn" href="${REPO}/blob/main/SPEC.md">Specification</a>
  </div>
</div></header>

<div class="wrap"><main>
  <section class="panel" aria-labelledby="in-h">
    <h2 id="in-h">Bundle</h2>
    <div class="row">
      <button class="btn primary" data-sample="valid">Sample: three agent actions</button>
      <button class="btn" data-sample="issuerSigned">Sample: no sealing service</button>
      <label class="btn">Open a file<input id="file" class="sr" type="file" accept=".json,application/json"></label>
    </div>
    <div class="row">
      <button class="btn danger" data-tamper="decision">Tamper: erase the need for approval</button>
      <button class="btn danger" data-tamper="amount">Tamper: edit a disclosed amount</button>
      <button class="btn danger" data-tamper="delete">Tamper: delete a record</button>
    </div>
    <label class="sr" for="json">Bundle JSON</label>
    <textarea id="json" spellcheck="false"></textarea>
    <div class="drop">Edit anything above, or drop a <code>.json</code> bundle onto the page. It is checked as you type.</div>
  </section>

  <section class="panel" aria-labelledby="out-h" aria-live="polite">
    <h2 id="out-h">What the records prove</h2>
    <div id="out"><p class="msgs">Loading…</p></div>
  </section>
</main></div>

<section class="how"><div class="wrap">
  <div class="cards">
    <div class="card"><h3>Approval of the exact action</h3><p>A held action records who approved it, bound to a commitment of that one action: this refund, this amount. An approval cannot be reused for another.</p></div>
    <div class="card"><h3>What actually changed</h3><p>The execution record commits to the affected state before and after, and a separate confirmation reads the system of record back. An agent that reports success without effect shows up.</p></div>
    <div class="card"><h3>Safe to share</h3><p>Amounts, parameters, IDs and state are salted commitments. Disclose a field only to the people who need it; the record proves the rest.</p></div>
    <div class="card"><h3>Adds to what you have</h3><p>Already sign tool calls with another receipt format? Point an OAR record at it with <code>external_ref</code> and add the approval and outcome evidence it lacks.</p></div>
  </div>
  <h2 style="font-size:20px;margin:28px 0 8px">Record your own agent in a few lines</h2>
<pre class="code">import { createRecorder, generateSigningKey } from '@openactionrecord/core';

const oar = createRecorder({ issuer: generateSigningKey('my-agent'), org: 'acme', agent: 'support-bot' });

const out = await oar.run({
  type: 'refund', target: 'stripe', params: { order: '1142', amountCents: 190000 },
  check: (p) => (p.amountCents > 125000 ? { result: 'held' } : { result: 'allowed' }),
  approve: async () => ({ approver: 'jordan', approved: await askOnSlack() }),
  readState: () => stripe.orderState('1142'),     // read before and after
  execute: () => stripe.refunds.create({ ... }),
  targetRef: (refund) => refund.id,
  confirm: (refund) => stripe.refunds.retrieve(refund.id).then((r) => r.status === 'succeeded'),
});

await writeFile('evidence.json', JSON.stringify(await oar.bundle()));   // verify it here, or: npx @openactionrecord/cli verify evidence.json</pre>
</div></section>

<footer><div class="wrap">
  Open Action Record is an open format: specification CC BY 4.0, code Apache-2.0. Maintained by Tridris; contributions welcome on <a href="${REPO}">GitHub</a>.
  The sample bundles use sample keys. Verification here checks the keys inside the bundle; compare them with the keys the issuer publishes to rule out a substituted bundle.
</div></footer>

<script>
${STANDALONE_VERIFIER_JS}
var SAMPLES = { valid: ${json(samples.valid)}, issuerSigned: ${json(samples.issuerSigned)} };
var $ = function (id) { return document.getElementById(id); };
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
var OUTCOME = {
  confirmed: ['Done, and confirmed in the system of record', 'good'],
  not_confirmed: ['Executed, but the system of record does NOT show it', 'bad'],
  executed_unconfirmed: ['Executed; no confirmation recorded', 'wait'],
  failed: ['Execution failed', 'bad'],
  awaiting_approval: ['Held, waiting for a person', 'wait'],
  denied: ['Blocked by the rules', 'bad'],
  rejected: ['Rejected by a person', 'bad'],
  expired: ['Approval expired', 'bad'],
  allowed_not_executed: ['Allowed; no execution recorded', 'wait']
};
var LEVEL = { 'issuer-signed': 'Issuer-signed only', sealed: 'Sealed by a separate service', timestamped: 'Sealed + outside timestamp' };

function stories(pkg) {
  var recs = pkg.records || pkg.receipts || [], groups = {}, order = [], byId = {};
  recs.forEach(function (r) { byId[r.payload && r.payload.receipt_id] = r; });
  function key(r) { var cur = r; for (var i = 0; i < 16; i++) { var parent = cur.payload.decision_ref && byId[cur.payload.decision_ref]; if (!parent) break; cur = parent; } return cur.payload.decision_ref || cur.payload.receipt_id; }
  recs.forEach(function (r) { if (!r.payload) return; var k = key(r); if (!groups[k]) { groups[k] = []; order.push(k); } groups[k].push(r); });
  return order.map(function (k) {
    var list = groups[k];
    function last(f) { for (var i = list.length - 1; i >= 0; i--) if (f(list[i].payload)) return list[i]; return null; }
    var dec = last(function (p) { return p.phase === 'decision' && ['allowed', 'held', 'denied'].indexOf(p.result) >= 0; });
    var appr = last(function (p) { return p.phase === 'decision' && ['approved', 'rejected', 'expired'].indexOf(p.result) >= 0; });
    var exe = last(function (p) { return p.phase === 'execution'; });
    var conf = last(function (p) { return p.phase === 'confirmation'; });
    var o = conf ? (conf.payload.result === 'confirmed' ? 'confirmed' : 'not_confirmed') : exe ? (exe.payload.result === 'executed' ? 'executed_unconfirmed' : 'failed') :
      appr ? (appr.payload.result === 'approved' ? 'allowed_not_executed' : appr.payload.result) : dec && dec.payload.result === 'denied' ? 'denied' : dec && dec.payload.result === 'held' ? 'awaiting_approval' : 'allowed_not_executed';
    function disclosed(rec, field) { if (!rec) return undefined; var d = (pkg.disclosures || []).find(function (x) { return x.receiptId === rec.payload.receipt_id && x.field === field; }); return d ? d.value : undefined; }
    return { first: list[0].payload, list: list, outcome: o, before: disclosed(exe, 'state_before'), after: disclosed(exe, 'state_after') };
  });
}

function stepText(p) {
  var why = (p.reasons || []).length ? ' (' + p.reasons.join(', ') + ')' : '';
  if (p.phase === 'decision' && ['approved', 'rejected', 'expired'].indexOf(p.result) >= 0) return ['approval', (p.result === 'approved' ? 'Approved' : p.result === 'rejected' ? 'Rejected' : 'Expired') + (p.approval && p.approval.approver ? ' by ' + p.approval.approver : '') + (p.approval && p.approval.method ? ' (' + p.approval.method + ')' : '')];
  if (p.phase === 'decision') return ['decision', (p.result === 'allowed' ? 'Allowed by ' : p.result === 'held' ? 'Held for approval by ' : 'Blocked by ') + p.principal + why];
  if (p.phase === 'execution') return ['execution', p.result === 'executed' ? 'Executed' + (p.state_before_commitment && p.state_after_commitment ? '; state before and after recorded' : '') : 'Execution failed' + why];
  return ['confirmation', p.result === 'confirmed' ? 'Confirmed in the system of record' : 'NOT confirmed in the system of record' + why];
}

var CHECKS = [['issuer_signature', 'Signature'], ['seal', 'Seal'], ['chain', 'Chain'], ['checkpoint', 'Checkpoint'], ['timestamp', 'Timestamp'], ['disclosures', 'Disclosures']];
var LABEL = { pass: 'pass', fail: 'FAIL', not_checked: '–' };

async function check() {
  var out = $('out'), pkg;
  try { pkg = JSON.parse($('json').value); } catch (e) { out.innerHTML = '<div class="verdict fail">Not valid JSON</div><p class="msgs">' + esc(e.message) + '</p>'; return; }
  if (!window.crypto || !crypto.subtle) { out.innerHTML = '<div class="verdict fail">This browser has no WebCrypto</div>'; return; }
  var r;
  try { r = await oarVerifyBundle(pkg, crypto.subtle); } catch (e) { out.innerHTML = '<div class="verdict fail">Not a bundle this verifier can read</div>'; return; }
  var byId = {}; r.receipts.forEach(function (x) { byId[x.receiptId] = x; });
  var html = '<div class="verdict ' + r.result + '">' + (r.result === 'pass' ? '✓ Verified' : '✗ Verification failed') +
    (r.result === 'pass' ? ' <span class="chip">' + esc(LEVEL[r.level] || r.level) + '</span>' : '') + '</div>' +
    '<ul class="msgs">' + r.messages.map(function (m) { return '<li>' + esc(m) + '</li>'; }).join('') + '</ul>';
  stories(pkg).forEach(function (s) {
    var oc = OUTCOME[s.outcome] || [s.outcome, 'wait'];
    var bad = s.list.some(function (x) { var rep = byId[x.payload.receipt_id]; return rep && rep.result === 'fail'; });
    html += '<div class="action"><div class="top"><span class="what">' + esc(s.first.action && s.first.action.type) + ' → ' + esc(s.first.action && s.first.action.target) + '</span>' +
      '<span class="outcome ' + (bad ? 'bad' : oc[1]) + '">' + esc(bad ? 'These records do not verify' : oc[0]) + '</span></div><ol class="steps">' +
      s.list.map(function (x) { var t = stepText(x.payload), rep = byId[x.payload.receipt_id]; return '<li><span class="ph">' + t[0] + (rep && rep.result === 'fail' ? ' ✗' : '') + '</span><span>' + esc(t[1]) + '</span></li>'; }).join('') + '</ol>' +
      (s.before !== undefined || s.after !== undefined ? '<div class="state">before ' + esc(JSON.stringify(s.before)) + '\\nafter  ' + esc(JSON.stringify(s.after)) + '</div>' : '') + '</div>';
  });
  html += '<details' + (r.result === 'fail' ? ' open' : '') + '><summary>Every check on every record</summary><table><thead><tr><th>Record</th><th>Phase</th><th>Result</th>' +
    CHECKS.map(function (c) { return '<th>' + c[1] + '</th>'; }).join('') + '</tr></thead><tbody>' +
    r.receipts.map(function (x) { return '<tr><td><code>' + esc(x.receiptId.replace('urn:uuid:', '').slice(0, 8)) + '</code></td><td>' + esc(x.phase) + '</td><td>' + esc(x.outcome) + '</td>' +
      CHECKS.map(function (c) { return '<td class="' + x.checks[c[0]] + '">' + LABEL[x.checks[c[0]]] + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></details>';
  out.innerHTML = html;
}

function load(obj) { $('json').value = JSON.stringify(obj, null, 2); check(); }
document.querySelectorAll('[data-sample]').forEach(function (b) { b.addEventListener('click', function () { load(SAMPLES[b.dataset.sample]); }); });
document.querySelectorAll('[data-tamper]').forEach(function (b) {
  b.addEventListener('click', function () {
    var pkg; try { pkg = JSON.parse($('json').value); } catch (e) { pkg = JSON.parse(JSON.stringify(SAMPLES.valid)); }
    var recs = pkg.records || pkg.receipts || [];
    if (b.dataset.tamper === 'decision') { var h = recs.find(function (r) { return r.payload.result === 'held'; }); if (h) { h.payload.result = 'allowed'; h.payload.reasons = ['within_limits']; } }
    if (b.dataset.tamper === 'amount') { var d = (pkg.disclosures || []).find(function (x) { return x.field === 'state_after'; }); if (d && d.value) { for (var k in d.value) if (typeof d.value[k] === 'number' && k !== 'totalCents') { d.value[k] = Math.round(d.value[k] / 10); break; } } }
    if (b.dataset.tamper === 'delete' && recs.length > 1) recs.splice(1, 1);
    load(pkg);
  });
});
var timer; $('json').addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(check, 300); });
$('file').addEventListener('change', function (e) { var f = e.target.files[0]; if (f) f.text().then(function (t) { $('json').value = t; check(); }); });
document.addEventListener('dragover', function (e) { e.preventDefault(); });
document.addEventListener('drop', function (e) { e.preventDefault(); var f = e.dataTransfer.files[0]; if (f) f.text().then(function (t) { $('json').value = t; check(); }); });
load(SAMPLES.valid);
</script>
</body>
</html>
`;
}
