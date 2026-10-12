import type { Inventory, Severity } from '../types.js';
import { KIND_NAMES } from '../kinds.js';
import type { BaselineReport, FrameworkId } from '../frameworks/baselines.js';

const SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(inv: Inventory, title = 'AI-BOM report', base?: Record<FrameworkId, BaselineReport>): string {
  const active = inv.findings.filter((f) => !f.muted);
  const assetName = new Map(inv.assets.map((a) => [a.id, a.name]));
  const out: string[] = [];
  out.push(`# ${title}`, '');
  out.push(`Scanned ${new Date(inv.scannedAt).toUTCString()} with ai-bom ${inv.tool.version}.`, '');
  const counts = SEV.map((s) => [s, active.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  out.push(`**Findings:** ${counts.map(([s, n]) => `${n} ${s}`).join(', ') || 'none'}${inv.findings.length > active.length ? ` (${inv.findings.length - active.length} muted)` : ''}`, '');
  const kinds = new Map<string, number>();
  for (const a of inv.assets) kinds.set(a.kind, (kinds.get(a.kind) ?? 0) + 1);
  out.push(`**Inventory:** ${[...kinds].map(([k, n]) => `${n} ${KIND_NAMES[k as keyof typeof KIND_NAMES].toLowerCase()}`).join(', ') || 'nothing found'}`, '');
  if (active.length) {
    out.push('## Findings', '', '| Severity | Finding | Asset | Where | What to do |', '|---|---|---|---|---|');
    for (const f of active) {
      out.push(`| ${f.severity} | ${esc(f.title)}${f.evidence ? `<br><code>${esc(f.evidence).slice(0, 160)}</code>` : ''} | ${esc(f.assetId ? assetName.get(f.assetId) ?? '' : '')} | ${esc(f.location ?? '')} | ${esc(f.remediation)} |`);
    }
    out.push('');
  }
  if (base) {
    out.push('## Baselines', '', '_A self-assessment, not a certification._', '', '| Framework | In place | Partly | Gaps | Need your answer |', '|---|---|---|---|---|');
    for (const r of Object.values(base)) out.push(`| ${r.name} ${r.version} (${r.coverage}%) | ${r.counts.met + r.counts.attested} | ${r.counts.partial} | ${r.counts.gap} | ${r.counts.manual} |`);
    out.push('');
    for (const r of Object.values(base)) {
      const open = r.controls.filter((c) => c.status === 'gap' || c.status === 'partial');
      if (!open.length) continue;
      out.push(`### ${r.name}: what to work on`, '');
      for (const c of open) out.push(`- **${c.id} ${esc(c.title)}** (${c.status === 'gap' ? 'gap' : 'partly'})${c.action ? `: ${esc(c.action)}` : ''}`);
      out.push('');
    }
  }
  out.push('## Inventory', '', '| Kind | Name | Where | Risk |', '|---|---|---|---|');
  for (const a of inv.assets) out.push(`| ${KIND_NAMES[a.kind]} | ${esc(a.name)} | ${esc([...new Set(a.occurrences.map((o) => o.source))].slice(0, 2).join(', '))} | ${a.risk ?? '—'} |`);
  out.push('');
  return out.join('\n');
}
