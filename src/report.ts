import type { AssetKind, Inventory, Severity } from './types.js';
import { KIND_NAMES } from './kinds.js';

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c('1');
const dim = c('2');
const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: c('1;31'),
  high: c('31'),
  medium: c('33'),
  low: c('36'),
  info: dim,
};

const KIND_LABEL = KIND_NAMES;

export function renderSummary(inv: Inventory): string {
  const lines: string[] = [];
  lines.push(bold(`AI-BOM  ·  ${inv.host.hostname}  ·  ${new Date(inv.scannedAt).toLocaleString()}`));
  lines.push('');
  lines.push(`${bold('AI tools found')} (${inv.clients.length}): ${inv.clients.map((x) => x.name).join(', ') || dim('none')}`);
  lines.push(`${bold('Projects with AI config')}: ${inv.projects.length}`);
  lines.push('');

  const counts = new Map<AssetKind, { total: number; fresh: number }>();
  for (const a of inv.assets) {
    const e = counts.get(a.kind) ?? { total: 0, fresh: 0 };
    e.total++;
    if (a.isNew) e.fresh++;
    counts.set(a.kind, e);
  }
  lines.push(bold('Inventory'));
  for (const kind of Object.keys(KIND_LABEL) as AssetKind[]) {
    const e = counts.get(kind);
    if (!e) continue;
    lines.push(`  ${KIND_LABEL[kind].padEnd(20)} ${String(e.total).padStart(4)}${e.fresh ? c('32')(`  (+${e.fresh} new)`) : ''}`);
  }
  if (inv.removed?.length) lines.push(dim(`  ${inv.removed.length} asset(s) removed since last scan`));
  lines.push('');

  const bySev = new Map<Severity, number>();
  for (const f of inv.findings.filter((x) => !x.muted)) bySev.set(f.severity, (bySev.get(f.severity) ?? 0) + 1);
  const sevLine = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .filter((s) => bySev.get(s))
    .map((s) => SEV_COLOR[s](`${bySev.get(s)} ${s}`))
    .join('  ');
  if (inv.score) {
    const sc = inv.score;
    const col = sc.value >= 75 ? c('32') : sc.value >= 40 ? c('33') : c('31');
    lines.push(`${bold('Security score')}: ${col(`${sc.value}/100 (${sc.grade})`)}${sc.next[0] ? dim(`  · next: ${sc.next[0].title}${sc.next[0].fix ? ` → ${sc.next[0].fix} (ai-bom fix ${sc.next[0].findingId})` : ''}, +${sc.next[0].gain}`) : ''}`);
  }
  lines.push(`${bold('Findings')}: ${sevLine || c('32')('none')}`);
  const assetName = new Map(inv.assets.map((a) => [a.id, a.name]));
  for (const f of inv.findings.filter((x) => !x.muted && (x.severity === 'critical' || x.severity === 'high')).slice(0, 10)) {
    const where = f.assetId ? assetName.get(f.assetId) : f.location;
    lines.push(`  ${SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8))} ${f.title} ${dim(`— ${where ?? ''}`)}`);
  }
  const more = inv.findings.filter((x) => !x.muted && (x.severity === 'critical' || x.severity === 'high')).length - 10;
  if (more > 0) lines.push(dim(`  … and ${more} more`));
  const t = inv.triage;
  if (t && t.accepted + t.snoozed + t.falsePositive) {
    lines.push(dim(`  Muted: ${[t.accepted && `${t.accepted} accepted`, t.snoozed && `${t.snoozed} snoozed`, t.falsePositive && `${t.falsePositive} false positive`].filter(Boolean).join(', ')} (ai-bom triage list)`));
  }
  if (t?.expired) lines.push(SEV_COLOR.medium(`  ${t.expired} snooze(s) expired; those findings are active again.`));
  lines.push('');
  if (inv.vulnCheck) {
    lines.push(dim(`Checked ${inv.vulnCheck.packages} MCP package(s) against bundled advisories, ${inv.vulnCheck.sources.join(' and ')}.`));
    for (const e of inv.vulnCheck.errors) lines.push(SEV_COLOR.medium(`  ${e}`));
  } else lines.push(dim('Checked MCP packages against bundled advisories and local caches. Add --online to query OSV.dev and the NVD too.'));
  if (inv.errors.length) {
    lines.push('');
    lines.push(dim(`${inv.errors.length} file(s) could not be read (use --json to see details)`));
  }
  const gaps = inv.coverage?.gaps.filter((g) => !/^\d+ config file/.test(g.what)) ?? [];
  if (gaps.length) lines.push(dim(`Not covered by this scan: ${gaps.map((g) => g.what.toLowerCase()).join('; ')}. (--json has the reasons.)`));
  return lines.join('\n');
}
