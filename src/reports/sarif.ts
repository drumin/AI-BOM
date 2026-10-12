import path from 'node:path';
import type { Finding, Inventory, Severity } from '../types.js';
import { RULE_ATLAS } from '../frameworks/atlas.js';
import { RULES } from '../checks/index.js';

/** SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. */

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

function location(f: Finding, baseDir?: string) {
  if (!f.location) return undefined;
  const m = f.location.match(/^(.*?):(\d+)$/);
  let file = m ? m[1] : f.location;
  if (baseDir) {
    const rel = path.relative(baseDir, file);
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) file = rel;
  }
  return {
    physicalLocation: {
      artifactLocation: { uri: file.split(path.sep).map(encodeURIComponent).join('/').replace(/^%7E/, '~') },
      region: m ? { startLine: Number(m[2]) } : undefined,
    },
  };
}

export function toSarif(inv: Inventory, opts: { baseDir?: string } = {}) {
  const used = [...new Set(inv.findings.map((f) => f.ruleId))];
  const assetName = new Map(inv.assets.map((a) => [a.id, a.name]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ai-bom',
            version: inv.tool.version,
            informationUri: 'https://github.com/drumin/ai-scanner',
            rules: used.map((id) => {
              const r = RULES[id];
              const worst = inv.findings.filter((f) => f.ruleId === id).map((f) => f.severity).sort((a, b) => Number(SCORE[b]) - Number(SCORE[a]))[0] ?? 'medium';
              return {
                id,
                name: id.toLowerCase().replace(/(^|-)(\w)/g, (_m, _d, c: string) => c.toUpperCase()),
                shortDescription: { text: r?.title ?? id },
                fullDescription: { text: r?.description ?? id },
                help: { text: r?.remediation ?? '' },
                defaultConfiguration: { level: LEVEL[worst] },
                properties: { tags: ['security', 'ai', ...(r?.owasp ?? []), ...(RULE_ATLAS[id] ?? []).map((t) => `MITRE-ATLAS-${t}`)], 'security-severity': SCORE[worst] },
              };
            }),
          },
        },
        results: inv.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: [f.title, f.assetId && `(${assetName.get(f.assetId)})`, f.evidence && `— ${f.evidence}`].filter(Boolean).join(' ') },
          locations: [location(f, opts.baseDir)].filter(Boolean),
          partialFingerprints: { aiBomFindingId: f.id },
          properties: { severity: f.severity, remediation: f.remediation, advisory: f.advisory },
          suppressions: f.muted ? [{ kind: 'external', status: 'accepted', justification: f.muted.reason ?? f.muted.status }] : undefined,
        })),
      },
    ],
  };
}
