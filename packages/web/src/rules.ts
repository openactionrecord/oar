// Builds rules.html: docs/REGULATORY-MAPPING.md as a page people can forward. A tiny Markdown subset only
// (headings, paragraphs, lists, tables, bold, italics, code, links), so no Markdown dependency is needed.

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function inline(s: string): string {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, t: string, u: string) => `<a href="${u.startsWith('http') ? u : `https://github.com/openactionrecord/oar/blob/main/${u.replace(/^\.\.\//, '')}`}">${t}</a>`);
}

const cells = (line: string) => line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());

export function markdownToHtml(md: string): string {
  const lines = md.split('\n');
  const out: string[] = [];
  let para: string[] = [];
  const flush = () => {
    if (para.length) out.push(`<p>${inline(para.join(' '))}</p>`);
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const h = /^(#{1,3}) (.*)$/.exec(line);
    if (h) {
      flush();
      const level = h[1]!.length;
      out.push(`<h${level}>${inline(h[2]!)}</h${level}>`);
    } else if (line.startsWith('|')) {
      flush();
      const head = cells(line);
      i++; // the separator row
      const rows: string[][] = [];
      while (i + 1 < lines.length && lines[i + 1]!.startsWith('|')) rows.push(cells(lines[++i]!));
      out.push(
        `<div class="table"><table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows
          .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`)
          .join('')}</tbody></table></div>`,
      );
    } else if (/^- /.test(line)) {
      flush();
      const items = [line.slice(2)];
      while (i + 1 < lines.length && /^- /.test(lines[i + 1]!)) items.push(lines[++i]!.slice(2));
      out.push(`<ul>${items.map((t) => `<li>${inline(t)}</li>`).join('')}</ul>`);
    } else if (line.trim() === '') flush();
    else para.push(line.trim());
  }
  flush();
  return out.join('\n');
}

export function rulesHtml(md: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OAR and the rules</title>
<meta name="description" content="How Open Action Record evidence lines up with rules in the EU, the US and Canada: the AI Act, PSD2, GDPR, New York DFS, NIST and OSFI.">
<style>
:root{--bg:#fbfbf9;--panel:#ffffff;--ink:#16181a;--muted:#5f6670;--line:#e3e5e8;--accent:#0f766e;--code:#f3f4f2;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1113;--panel:#16191c;--ink:#eceef0;--muted:#9aa3ad;--line:#2a2f35;--accent:#2dd4bf;--code:#1d2125}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}
header{border-bottom:1px solid var(--line);padding:14px 0}
header a{color:var(--ink);font-weight:600;text-decoration:none}
main{padding:24px 0 40px}
h1{font-size:30px;line-height:1.25;margin:8px 0 8px}
h2{font-size:21px;margin:36px 0 10px;padding-top:10px;border-top:1px solid var(--line)}
a{color:var(--accent)}
code{font:0.9em var(--mono);background:var(--code);padding:1px 4px;border-radius:4px}
.table{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
table{border-collapse:collapse;width:100%;min-width:720px;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-weight:600;background:var(--code)}
tr:last-child td{border-bottom:0}
footer{border-top:1px solid var(--line);padding:20px 0 40px;color:var(--muted);font-size:13px}
</style>
</head>
<body>
<header><div class="wrap"><a href="./">Open Action Record</a> · <a href="https://github.com/openactionrecord/oar">GitHub</a></div></header>
<main><div class="wrap">
${markdownToHtml(md)}
</div></main>
<footer><div class="wrap">Open Action Record is an open format: specification CC BY 4.0, code Apache-2.0. Maintained by the Open Action Record authors. Source of this page: <a href="https://github.com/openactionrecord/oar/blob/main/docs/REGULATORY-MAPPING.md">docs/REGULATORY-MAPPING.md</a>. Corrections welcome as an issue.</div></footer>
</body>
</html>
`;
}
