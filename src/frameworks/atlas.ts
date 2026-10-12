import type { Finding, Inventory } from '../types.js';
import { ATLAS_TACTICS, ATLAS_TECHNIQUES, ATLAS_VERSION } from './atlas-data.js';

export { ATLAS_TACTICS, ATLAS_TECHNIQUES, ATLAS_VERSION };

/**
 * MITRE ATLAS techniques each rule detects evidence of (an exposure an adversary
 * could use, or a sign one already did). Rules about hygiene rather than an
 * attack technique (unused servers, licenses) map to none.
 */
export const RULE_ATLAS: Record<string, string[]> = {
  'MCP-SECRET': ['AML.T0083', 'AML.T0055'],
  'MCP-UNPINNED': ['AML.T0109', 'AML.T0010.005'],
  'MCP-INSECURE-TRANSPORT': ['AML.T0132'],
  'MCP-BROAD-FS': ['AML.T0112.000', 'AML.T0053'],
  'MCP-CONTAINER-PRIVILEGED': ['AML.T0112.000'],
  'MCP-SHELL-COMMAND': ['AML.T0050', 'AML.T0112.000'],
  'PERM-BYPASS': ['AML.T0112.000', 'AML.T0053'],
  'PERM-BROAD-ALLOW': ['AML.T0053', 'AML.T0050'],
  'PERM-AUTO-PROJECT-MCP': ['AML.T0081', 'AML.T0010.005'],
  'SETTINGS-SECRET': ['AML.T0083'],
  'SETTINGS-API-REDIRECT': ['AML.T0081'],
  'SETTINGS-ENV-INJECTION': ['AML.T0081'],
  'SETTINGS-TRAFFIC-INTERCEPT': ['AML.T0081'],
  'PERM-BROAD-DIRS': ['AML.T0053'],
  'HOOK-EXEC': ['AML.T0081', 'AML.T0050'],
  'HOOK-NETWORK': ['AML.T0081', 'AML.T0025'],
  'HOOK-DATA-EGRESS': ['AML.T0081', 'AML.T0025'],
  'TELEMETRY-PROMPTS': ['AML.T0081', 'AML.T0025'],
  'TELEMETRY-EXPORT': ['AML.T0081'],
  'TELEMETRY-INSECURE': ['AML.T0025'],
  'AUTORUN-TASK': ['AML.T0011', 'AML.T0050'],
  'CONTENT-HIDDEN-UNICODE': ['AML.T0068', 'AML.T0051.001'],
  'CONTENT-PROMPT-INJECTION': ['AML.T0051.001', 'AML.T0080'],
  'CONTENT-DOWNLOAD-EXEC': ['AML.T0050', 'AML.T0011'],
  'CONTENT-SENSITIVE-PATHS': ['AML.T0055'],
  'CONTENT-SECRET': ['AML.T0083', 'AML.T0055'],
  'SKILL-EXFIL-PATTERN': ['AML.T0110', 'AML.T0086'],
  'SKILL-SUSPICIOUS-ENDPOINT': ['AML.T0110', 'AML.T0025'],
  'SKILL-UNRESTRICTED-TOOLS': ['AML.T0053', 'AML.T0112.000'],
  'MCP-TOOL-POISONING': ['AML.T0110', 'AML.T0051.001'],
  'TOOL-BEHAVIOR-MISMATCH': ['AML.T0110', 'AML.T0011.002'],
  'TOOL-UNDECLARED': ['AML.T0110'],
  'TOOLCALL-SECRET-SENT': ['AML.T0086', 'AML.T0057'],
  'TOOLCALL-SUSPICIOUS-DEST': ['AML.T0086', 'AML.T0025'],
  'TOOLCALL-INJECTION': ['AML.T0051.001', 'AML.T0099'],
  'COMBO-LETHAL-TRIFECTA': ['AML.T0051.001', 'AML.T0086'],
  'COMBO-SHELL-UNTRUSTED': ['AML.T0051.001', 'AML.T0050', 'AML.T0112.000'],
  'CONNECTOR-REVIEW': ['AML.T0012', 'AML.T0085.001'],
  'VULN-KNOWN': ['AML.T0010.005'],
  'VULN-POSSIBLE': ['AML.T0010.005'],
  'VULN-MALICIOUS': ['AML.T0011.001', 'AML.T0010.005'],
  'DEP-VULN': ['AML.T0010.001'],
  'TRUST-TYPOSQUAT': ['AML.T0010.005', 'AML.T0011.001'],
  'TRUST-TYPOSQUAT-SKILL': ['AML.T0010.005', 'AML.T0011.001'],
  'SKILL-DEP-TYPOSQUAT': ['AML.T0010.005', 'AML.T0011.001'],
  'SKILL-DEP-UNPINNED': ['AML.T0010.001'],
  'SKILL-BINARY': ['AML.T0011.001', 'AML.T0010.001'],
  'TRUST-INSTALL-SCRIPTS': ['AML.T0011.001', 'AML.T0010.005'],
  'TRUST-NEW-PACKAGE': ['AML.T0010.005'],
  'TRUST-DEPRECATED': ['AML.T0010.005'],
  'TRUST-NO-REPO': ['AML.T0010.005'],
  'TRUST-TOOLS-CHANGED': ['AML.T0109', 'AML.T0110'],
  'MCP-TOOL-SHADOWING': ['AML.T0110'],
  'MODEL-SERVER-EXPOSED': ['AML.T0132'],
  'MCP-UNLISTED-RUNNING': ['AML.T0010.005'],
  'LIVE-HIDDEN-TOOLS': ['AML.T0110'],
  'LIVE-DYNAMIC-DESCRIPTIONS': ['AML.T0110', 'AML.T0109'],
  'LIVE-NETWORK-AT-START': ['AML.T0110', 'AML.T0025'],
  'MODEL-PICKLE': ['AML.T0011.000', 'AML.T0010.003'],
  'APIKEY-PLAINTEXT': ['AML.T0055'],
  'APIKEY-NOT-GITIGNORED': ['AML.T0055'],
  'EXT-ALL-SITES': ['AML.T0112.000'],
  'USAGE-UNUSED': [],
  'CONTENT-NOT-INSPECTED': [],
  'CONTENT-PERSISTENCE': ['AML.T0081'],
  'CONTENT-HIDDEN-INSTRUCTION': ['AML.T0068', 'AML.T0051.001'],
  'DEP-LICENSE': [],
};

/** "AML.T0110 AI Agent Tool Poisoning", as stored on findings. */
export const atlasLabel = (id: string) => `${id} ${ATLAS_TECHNIQUES[id]?.name ?? ''}`.trim();
export const atlasFor = (ruleId: string) => (RULE_ATLAS[ruleId] ?? []).map(atlasLabel);
export const atlasUrl = (id: string) => `https://atlas.mitre.org/techniques/${id}`;
const idOf = (label: string) => label.split(' ')[0];

export interface AtlasView {
  version: string;
  tactics: {
    id: string;
    name: string;
    techniques: { id: string; name: string; url: string; findings: string[]; worst?: Finding['severity'] }[];
  }[];
  /** Techniques with at least one active finding. */
  seen: number;
  /** Techniques AI-BOM checks for. */
  checked: number;
}

const RANK = ['critical', 'high', 'medium', 'low', 'info'];

/** Active findings arranged on the ATLAS matrix; techniques AI-BOM checks but found nothing for are kept, empty. */
export function atlasView(inv: Pick<Inventory, 'findings'>): AtlasView {
  const byTech = new Map<string, Finding[]>();
  for (const f of inv.findings) {
    if (f.muted) continue;
    for (const l of f.atlas ?? []) {
      const id = idOf(l);
      byTech.set(id, [...(byTech.get(id) ?? []), f]);
    }
  }
  const checkedIds = new Set(Object.values(RULE_ATLAS).flat());
  const tactics = ATLAS_TACTICS.map((t) => ({
    ...t,
    techniques: [...checkedIds]
      .filter((id) => ATLAS_TECHNIQUES[id]?.tactics.includes(t.id))
      .map((id) => {
        const fs = byTech.get(id) ?? [];
        const worst = fs.map((f) => f.severity).sort((a, b) => RANK.indexOf(a) - RANK.indexOf(b))[0];
        return { id, name: ATLAS_TECHNIQUES[id].name, url: atlasUrl(id), findings: fs.map((f) => f.id), worst };
      })
      .sort((a, b) => b.findings.length - a.findings.length || a.id.localeCompare(b.id)),
  })).filter((t) => t.techniques.length);
  return { version: ATLAS_VERSION, tactics, seen: [...byTech.keys()].filter((k) => checkedIds.has(k)).length, checked: checkedIds.size };
}
