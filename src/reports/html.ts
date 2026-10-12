import type { Asset, Finding, Inventory, Severity } from '../types.js';
import { KIND_NAMES } from '../kinds.js';
import type { BaselineReport, FrameworkId } from '../frameworks/baselines.js';

/**
 * A single self-contained HTML file (no scripts, no external requests) that
 * reads well on screen and prints cleanly to PDF. Everything in it has
 * already been redacted by the scanner; it is escaped again here.
 */

const SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function sevPill(s?: Severity) {
  return s ? `<span class="pill sev-${s}">${s}</span>` : '<span class="muted">—</span>';
}

function findingRow(f: Finding, assetName: Map<string, string>) {
  return `<tr>
<td>${sevPill(f.severity)}</td>
<td><div class="t">${esc(f.title)}</div>${f.evidence ? `<code>${esc(f.evidence)}</code>` : ''}<div class="d">${esc(f.description)}</div>${f.owasp?.length || f.atlas?.length ? `<div class="tags">${[...(f.owasp ?? []), ...(f.atlas ?? [])].map((o) => `<span>${esc(o)}</span>`).join('')}</div>` : ''}</td>
<td>${esc(f.assetId ? assetName.get(f.assetId) : '')}${f.location ? `<div class="loc">${esc(f.location)}</div>` : ''}</td>
<td>${esc(f.remediation)}${f.muted ? `<div class="mutednote">${esc(f.muted.status)}${f.muted.reason ? `: ${esc(f.muted.reason)}` : ''}</div>` : ''}</td>
</tr>`;
}

function assetRow(a: Asset) {
  const where = [...new Set(a.occurrences.map((o) => o.source))];
  const detail =
    a.mcp?.url ?? (a.mcp?.package ? `${a.mcp.package.ecosystem}: ${a.mcp.package.name}${a.mcp.package.version ? `@${a.mcp.package.version}` : ''}` : a.mcp?.command) ??
    a.hook?.explanation?.summary ?? a.hook?.command ?? a.telemetry?.endpoint ?? a.apiKey?.masked ?? a.model?.runtime ?? a.app?.version ?? a.browserExtension?.browser ?? a.skill?.description ?? '';
  return `<tr><td>${esc(a.name)}${a.isNew ? ' <span class="pill new">new</span>' : ''}<div class="loc">${esc(detail).slice(0, 220)}</div></td><td class="loc">${where.slice(0, 3).map(esc).join('<br>')}${where.length > 3 ? `<br>+${where.length - 3} more` : ''}</td><td>${sevPill(a.risk)}</td></tr>`;
}

function baselineSection(base: Record<FrameworkId, BaselineReport>): string {
  const rows = Object.values(base).map((r) => `<tr><td>${esc(r.name)} ${esc(r.version)}</td><td>${r.coverage}%</td><td>${r.counts.met + r.counts.attested}</td><td>${r.counts.partial}</td><td>${r.counts.gap}</td><td>${r.counts.manual}</td></tr>`).join('');
  const open = Object.values(base).flatMap((r) => r.controls.filter((c) => c.status === 'gap' || c.status === 'partial').map((c) => `<div class="flow"><b>${esc(c.id)} ${esc(c.title)}</b> <span class="sub">${esc(r.name)} · ${c.status === 'gap' ? 'gap' : 'partly'}</span>${c.action ? `<div class="loc">${esc(c.action)}</div>` : ''}</div>`));
  return `<h2>Baselines</h2><p class="sub">A self-assessment, not a certification.</p><table><thead><tr><th>Framework</th><th>In place</th><th>Controls met</th><th>Partly</th><th>Gaps</th><th>Need your answer</th></tr></thead><tbody>${rows}</tbody></table>${open.length ? `<h3>What to work on</h3>${open.join('')}` : ''}`;
}

export function toHtml(inv: Inventory, title = 'AI-BOM report', base?: Record<FrameworkId, BaselineReport>): string {
  const active = inv.findings.filter((f) => !f.muted);
  const muted = inv.findings.filter((f) => f.muted);
  const assetName = new Map(inv.assets.map((a) => [a.id, a.name]));
  const counts = Object.fromEntries(SEV.map((s) => [s, active.filter((f) => f.severity === s).length]));
  const byKind = new Map<string, Asset[]>();
  for (const a of inv.assets) byKind.set(a.kind, [...(byKind.get(a.kind) ?? []), a]);
  const flows = inv.assets.filter((a) => (a.kind === 'hook' && a.hook?.explanation?.sendsTo.length) || a.kind === 'telemetry');
  const combos = active.filter((f) => f.ruleId.startsWith('COMBO-'));
  const date = new Date(inv.scannedAt);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
:root{--bg:#fbfbfd;--card:#fff;--ink:#1d1d1f;--sub:#6e6e73;--line:#e5e5ea;--crit:#c9342a;--high:#d7641d;--med:#b58a00;--low:#4b72b8;--ok:#2f8f4e;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#111113;--card:#1c1c1e;--ink:#f5f5f7;--sub:#a1a1a6;--line:#2c2c2e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:40px 24px 64px}
h1{font-size:28px;letter-spacing:-.02em;margin:0 0 4px}h2{font-size:19px;margin:40px 0 12px;letter-spacing:-.01em}h3{font-size:15px;margin:24px 0 8px}
.sub{color:var(--sub)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:24px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}.tile b{display:block;font-size:26px;letter-spacing:-.02em}.tile span{color:var(--sub);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}th{font-size:12px;color:var(--sub);font-weight:600}tr:last-child td{border-bottom:0}
code{display:block;margin:4px 0;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--sub);word-break:break-all}
.t{font-weight:600}.d{color:var(--sub);font-size:12.5px;margin-top:4px}.loc{color:var(--sub);font-size:12px;word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600;text-transform:capitalize;border:1px solid currentColor}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low,.sev-info{color:var(--low)}.new{color:var(--ok)}
.tags span{display:inline-block;margin:4px 4px 0 0;font-size:11px;color:var(--sub);border:1px solid var(--line);border-radius:6px;padding:0 6px}
.mutednote{margin-top:6px;font-size:12px;color:var(--sub);font-style:italic}.muted{color:var(--sub)}
.flow{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:8px}
footer{margin-top:48px;color:var(--sub);font-size:12px}
@media print{body{background:#fff;color:#000}main{padding:0}table,.tile,.flow{break-inside:avoid;border-color:#ccc}h2{break-after:avoid}}
</style></head><body><main>
<h1>${esc(title)}</h1>
<div class="sub">${esc(inv.host.hostname)} · ${esc(date.toUTCString())} · ai-bom ${esc(inv.tool.version)}</div>
<div class="tiles">
<div class="tile"><b>${inv.assets.length}</b><span>AI assets</span></div>
<div class="tile"><b>${inv.clients.length}</b><span>AI tools</span></div>
${SEV.slice(0, 4).map((s) => `<div class="tile"><b class="sev-${s}">${counts[s]}</b><span>${s}</span></div>`).join('')}
</div>
${combos.length ? `<h2>Dangerous combinations</h2>${combos.map((f) => `<div class="flow">${sevPill(f.severity)} <b>${esc(f.title)}</b><div class="loc">${esc(f.evidence)}</div></div>`).join('')}` : ''}
${flows.length ? `<h2>Where your data goes</h2>${flows.map((a) => `<div class="flow"><b>${esc(a.name)}</b> ${sevPill(a.risk)}<div class="loc">${esc(a.hook?.explanation?.summary ?? `${a.telemetry?.endpoint ?? ''}${a.telemetry?.logsPrompts ? ' · includes your prompts' : ''}`)}</div></div>`).join('')}` : ''}
<h2>Findings (${active.length})</h2>
${active.length ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>What to do</th></tr></thead><tbody>${active.map((f) => findingRow(f, assetName)).join('')}</tbody></table>` : '<p class="sub">No active findings.</p>'}
${muted.length ? `<h3>Muted (${muted.length})</h3><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Decision</th></tr></thead><tbody>${muted.map((f) => findingRow(f, assetName)).join('')}</tbody></table>` : ''}
${base ? baselineSection(base) : ''}
<h2>Inventory</h2>
${[...byKind].map(([k, list]) => `<h3>${esc(KIND_NAMES[k as keyof typeof KIND_NAMES])} (${list.length})</h3><table><thead><tr><th>Name</th><th>Where</th><th>Risk</th></tr></thead><tbody>${list.map(assetRow).join('')}</tbody></table>`).join('')}
<footer>Generated locally by ai-bom. Secret values are redacted. OWASP mappings: Top 10 for LLM Applications 2025 and Top 10 for Agentic Applications.</footer>
</main></body></html>
`;
}
