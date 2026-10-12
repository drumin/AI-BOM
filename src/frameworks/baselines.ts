import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Finding, Inventory } from '../types.js';
import { dataDir, readJsonFile, writeJsonFile } from '../util/store.js';
import { readScans, type ScanRecord } from '../state.js';

/**
 * NIST AI RMF 1.0 and ISO/IEC 42001:2023 Annex A, seen from one person's machine.
 *
 * Both are written for organizations. AI-BOM checks the controls a scan can
 * provide evidence for, and lets you record your own answer for the ones it
 * can't see (a policy, a purpose). Titles are short paraphrases, not the
 * standards' text; this is a self-assessment aid, not a certification.
 */

export type FrameworkId = 'nist-ai-rmf' | 'iso-42001';
export type ControlStatus = 'met' | 'partial' | 'gap' | 'manual' | 'attested' | 'na';

export interface Attestation {
  status: 'done' | 'na';
  note?: string;
  at: string;
}

export interface Evidence {
  inv: Inventory;
  scans: ScanRecord[];
  incidents: number;
  attestations: Record<string, Attestation>;
  now: Date;
}

interface CheckResult {
  status: Exclude<ControlStatus, 'manual' | 'attested'>;
  evidence: string[];
  findings?: string[];
  action?: string;
}

interface ControlDef {
  id: string;
  group: string;
  title: string;
  /** What the control asks for, applied to a personal AI setup. */
  ask: string;
  check?: (e: Evidence) => CheckResult;
  /** For controls only you can answer: what "done" looks like. */
  hint?: string;
  /** Written for organizations; usually not applicable to one person. */
  org?: boolean;
}

export interface ControlResult {
  id: string;
  group: string;
  title: string;
  ask: string;
  status: ControlStatus;
  auto: boolean;
  org?: boolean;
  evidence: string[];
  findings: string[];
  action?: string;
  hint?: string;
  attestation?: Attestation;
  /** You confirmed this, but long enough ago that it needs another look. Counts as unanswered until you re-confirm. */
  stale?: boolean;
}

export interface BaselineReport {
  framework: FrameworkId;
  name: string;
  version: string;
  url: string;
  controls: ControlResult[];
  counts: Record<ControlStatus, number>;
  /** Share of applicable controls in place (met/attested = 1, partial = 0.5), 0-100. */
  coverage: number;
}

/* ---------------- Evidence helpers ---------------- */

const DAY = 86_400_000;
const active = (e: Evidence, match: (f: Finding) => boolean) => e.inv.findings.filter((f) => !f.muted && match(f));
const rules = (...ids: string[]) => (f: Finding) => ids.some((id) => (id.endsWith('*') ? f.ruleId.startsWith(id.slice(0, -1)) : f.ruleId === id));
const severe = (fs: Finding[]) => fs.some((f) => f.severity === 'critical' || f.severity === 'high');
const ids = (fs: Finding[]) => fs.map((f) => f.id);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const daysAgo = (iso: string | undefined, now: Date) => (iso ? (now.getTime() - new Date(iso).getTime()) / DAY : Infinity);
/** Recorded scans in the window, counting the scan being evaluated if it wasn't recorded. */
const scansWithin = (e: Evidence, days: number) => {
  const at = new Set(e.scans.filter((s) => daysAgo(s.at, e.now) <= days).map((s) => s.at));
  if (daysAgo(e.inv.scannedAt, e.now) <= days) at.add(e.inv.scannedAt);
  return at.size;
};
const of = (e: Evidence, kind: string) => e.inv.assets.filter((a) => a.kind === kind);
const guardInstalled = (e: Evidence) => of(e, 'hook').some((a) => /\bguard\b/.test(a.hook?.command ?? '') && /ai-bom|cli\.js/.test(a.hook?.command ?? ''));

/** Findings → status: any critical/high is a gap, anything else partial, none met. */
function byFindings(fs: Finding[], ok: string[], what: string, action: string): CheckResult {
  if (!fs.length) return { status: 'met', evidence: ok };
  return {
    status: severe(fs) ? 'gap' : 'partial',
    evidence: [...ok, `${plural(fs.length, 'open finding')} about ${what}.`],
    findings: ids(fs),
    action,
  };
}

/* ---------------- Checks (shared by both frameworks) ---------------- */

const CHECKS = {
  inventory(e: Evidence): CheckResult {
    const assets = e.inv.assets.length;
    const tools = e.inv.clients.length;
    const connectors = of(e, 'connector').length;
    const ev = [`${plural(assets, 'AI asset')} across ${plural(tools, 'AI tool')} inventoried (${new Date(e.inv.scannedAt).toLocaleDateString()}). Export it as CycloneDX for a record.`];
    if (!assets) return { status: 'gap', evidence: ['Nothing was found to inventory.'], action: 'Run `ai-bom doctor` to see where AI-BOM looked.' };
    if (!connectors)
      return { status: 'partial', evidence: [...ev, 'No cloud connectors registered, so accounts linked to claude.ai, ChatGPT and similar are not covered.'], action: 'Register the connectors you use: `ai-bom connectors add <platform> <name>` or the Connectors tab.' };
    return { status: 'met', evidence: [...ev, `${plural(connectors, 'cloud connector')} included.`] };
  },

  components(e: Evidence): CheckResult {
    const servers = of(e, 'mcp-server');
    if (!servers.length) return { status: 'na', evidence: ['No MCP servers configured.'] };
    const unknown = servers.filter((a) => {
      const p = a.mcp?.package;
      if (a.mcp?.url) return false;
      if (!p) return true;
      if (p.ecosystem === 'local' || p.ecosystem === 'binary') return false;
      return !p.pinned && !p.installedVersions?.length;
    });
    const withDeps = servers.filter((a) => a.deps).length;
    const ev = [`${plural(servers.length, 'MCP server')}: ${servers.length - unknown.length} with a known source and version.`, `Dependencies read for ${withDeps}.`];
    if (!unknown.length) return { status: 'met', evidence: ev };
    return {
      status: 'partial',
      evidence: [...ev, `Version not known for: ${unknown.slice(0, 6).map((a) => a.name).join(', ')}${unknown.length > 6 ? '…' : ''}.`],
      findings: ids(active(e, (f) => f.ruleId === 'MCP-UNPINNED')),
      action: 'Pin each server to a version (`ai-bom fix` can do it), so what runs is what was checked.',
    };
  },

  controls(e: Evidence): CheckResult {
    return byFindings(
      active(e, rules('MCP-UNPINNED', 'MCP-SECRET', 'SETTINGS-SECRET', 'MCP-INSECURE-TRANSPORT')),
      ['Checked: version pinning, secrets in config files, insecure transport.'],
      'pinning, secrets or transport',
      'Apply the fixes: pin versions and move secrets to the keychain (`ai-bom fix`).',
    );
  },

  oversight(e: Evidence): CheckResult {
    return byFindings(
      active(e, rules('PERM-BYPASS', 'PERM-BROAD-ALLOW', 'PERM-AUTO-PROJECT-MCP', 'SKILL-UNRESTRICTED-TOOLS', 'COMBO-SHELL-UNTRUSTED')),
      ['Checked: approval prompts, broad allow rules, auto-approved project servers, unrestricted skills.'],
      'agents acting without your approval',
      'Keep approval prompts on and narrow allow rules, so you see what agents do before it happens.',
    );
  },

  securityEval(e: Evidence): CheckResult {
    const online = e.inv.vulnCheck && daysAgo(e.inv.vulnCheck.checkedAt, e.now) <= 7;
    const feed = e.inv.feed?.verified && daysAgo(e.inv.feed.generatedAt, e.now) <= 14;
    const ev = [`Static checks ran on ${plural(e.inv.assets.length, 'asset')} (${plural(e.inv.findings.length, 'finding')}).`];
    if (online) ev.push(`Packages checked online (${e.inv.vulnCheck!.sources.join(', ')}) ${new Date(e.inv.vulnCheck!.checkedAt).toLocaleDateString()}.`);
    if (feed) ev.push(`Signed advisory feed from ${new Date(e.inv.feed!.generatedAt).toLocaleDateString()}.`);
    if (online || feed) return { status: 'met', evidence: ev };
    return { status: 'partial', evidence: [...ev, 'Known vulnerabilities were checked against bundled advisories only.'], action: 'Run the online check (`ai-bom scan --online`) at least weekly.' };
  },

  privacy(e: Evidence): CheckResult {
    const hooks = of(e, 'hook').length;
    const tel = of(e, 'telemetry').length;
    return byFindings(
      active(e, rules('TELEMETRY-PROMPTS', 'TELEMETRY-INSECURE', 'HOOK-DATA-EGRESS', 'TOOLCALL-SECRET-SENT', 'TOOLCALL-SUSPICIOUS-DEST', 'SKILL-EXFIL-PATTERN')),
      [`${plural(hooks, 'hook')} and ${plural(tel, 'telemetry export')} reviewed for where your data goes.`],
      'data leaving your machine',
      'Remove hooks and telemetry that send prompts or secrets somewhere you did not choose.',
    );
  },

  monitoring(e: Evidence): CheckResult {
    const logs = e.inv.sessions?.files ?? 0;
    const guard = guardInstalled(e);
    const agents = Object.entries(e.inv.sessions?.agents ?? {}).filter(([, n]) => n).map(([a]) => a);
    const ev = [logs ? `${plural(logs, 'session log')} reviewed (${agents.join(', ') || 'agents'}).` : 'No agent session logs were read.', guard ? 'Live MCP call guard installed.' : 'Live MCP call guard not installed.'];
    if (logs && guard) return { status: 'met', evidence: ev };
    if (logs) return { status: 'partial', evidence: ev, action: 'Install the guard (`ai-bom guard --install`) to check MCP calls as they happen.' };
    return { status: 'gap', evidence: ev, action: 'Leave session-log reading on and install the guard (`ai-bom guard --install`).' };
  },

  eventLogs(e: Evidence): CheckResult {
    const logs = e.inv.sessions?.files ?? 0;
    if (!logs) return { status: 'gap', evidence: ['No agent session logs found or reading them is turned off.'], action: 'Keep your agents’ session logs (they are on by default) and let AI-BOM read them.' };
    return { status: 'met', evidence: [`${plural(logs, 'session log')} with ${plural(e.inv.sessions!.toolCalls, 'tool call')} on record; the Activity tab shows them as a timeline.`] };
  },

  cadence(e: Evidence): CheckResult {
    const n = scansWithin(e, 30);
    const ev = [`${plural(n, 'scan')} in the last 30 days.`];
    if (n >= 4) return { status: 'met', evidence: ev };
    return { status: n ? 'partial' : 'gap', evidence: ev, action: 'Scan automatically: `ai-bom watch --install`, or the menu bar (`ai-bom menubar --install`).' };
  },

  emergent(e: Evidence): CheckResult {
    const r = CHECKS.securityEval(e);
    const changed = active(e, rules('TRUST-TOOLS-CHANGED', 'LIVE-DYNAMIC-DESCRIPTIONS'));
    const ev = ['Tool descriptions are compared between scans (rug pulls), and new assets are flagged.', ...r.evidence.slice(1)];
    if (changed.length) return { status: 'partial', evidence: [...ev, `${plural(changed.length, 'server')} changed what it tells the model.`], findings: ids(changed), action: 'Review what changed before using those servers again.' };
    return { ...r, evidence: ev };
  },

  decommission(e: Evidence): CheckResult {
    if (!e.inv.sessions?.files) return { status: 'partial', evidence: ['Without session logs, unused tools can’t be identified.'], action: 'Let AI-BOM read session logs, then remove what you don’t use.' };
    const unused = active(e, rules('USAGE-UNUSED'));
    if (!unused.length) return { status: 'met', evidence: ['Every configured MCP server was used recently, or not enough log history yet to tell.'] };
    return { status: 'partial', evidence: [`${plural(unused.length, 'server')} configured but unused.`], findings: ids(unused), action: 'Remove servers you no longer use (one click, undoable).' };
  },

  highRisk(e: Evidence): CheckResult {
    const fs = active(e, (f) => f.severity === 'critical' || f.severity === 'high');
    if (!fs.length) return { status: 'met', evidence: ['No open critical or high findings: each was fixed or has a recorded decision.'] };
    return { status: 'gap', evidence: [`${plural(fs.length, 'critical or high finding')} without a fix or a decision.`], findings: ids(fs), action: 'Fix them, or accept each with a reason in Findings.' };
  },

  residual(e: Evidence): CheckResult {
    const accepted = e.inv.findings.filter((f) => f.muted?.status === 'accepted');
    const noReason = accepted.filter((f) => !f.muted?.reason?.trim());
    if (!accepted.length) return { status: 'met', evidence: ['No risks accepted.'] };
    const ev = [`${plural(accepted.length, 'accepted risk')}, stored with your reasons in ~/.ai-bom/triage.json.`];
    if (!noReason.length) return { status: 'met', evidence: ev };
    return { status: 'partial', evidence: [...ev, `${noReason.length} without a reason.`], findings: ids(noReason), action: 'Add a reason to each accepted finding.' };
  },

  deactivate(e: Evidence): CheckResult {
    const servers = of(e, 'mcp-server');
    const stuck = servers.filter((a) => !a.fixes?.length);
    const ev = ['`ai-bom incident` pauses every editable MCP server and data-sending hook as one undoable change.'];
    if (!stuck.length) return { status: 'met', evidence: ev };
    return { status: 'partial', evidence: [...ev, `${plural(stuck.length, 'server')} can only be turned off in its own app or plugin: ${stuck.slice(0, 5).map((a) => a.name).join(', ')}${stuck.length > 5 ? '…' : ''}.`], action: 'Know where to disable those (their app’s settings) in case you need to.' };
  },

  thirdParty(e: Evidence): CheckResult {
    const fs = active(e, rules('VULN-*', 'DEP-VULN', 'TRUST-*', 'MCP-UNPINNED'));
    const r = byFindings(fs, ['Checked: known vulnerabilities, dependencies, publisher signals, typosquats, version pinning.'], 'third-party servers and packages', 'Upgrade or replace affected servers (`ai-bom upgrade`), and pin versions.');
    if (r.status === 'met' && !(e.inv.vulnCheck && daysAgo(e.inv.vulnCheck.checkedAt, e.now) <= 7))
      return { status: 'partial', evidence: [...r.evidence, 'Publisher signals and live advisories need the online check.'], action: 'Run `ai-bom scan --online` regularly.' };
    return r;
  },

  models(e: Evidence): CheckResult {
    const models = of(e, 'model');
    if (!models.length) return { status: 'na', evidence: ['No local models found.'] };
    return byFindings(active(e, rules('MODEL-PICKLE')), [`${plural(models.length, 'local model')} inventoried with format and source.`], 'unsafe model formats', 'Prefer safetensors or GGUF over pickle-based weights.');
  },

  postDeploy(e: Evidence): CheckResult {
    const c = CHECKS.cadence(e);
    const m = CHECKS.monitoring(e);
    const ev = [...c.evidence, ...m.evidence, 'Every change AI-BOM makes is recorded and can be undone (History).'];
    if (c.status === 'met' && m.status !== 'gap') return { status: 'met', evidence: ev };
    return { status: 'partial', evidence: ev, action: c.action ?? m.action };
  },

  incidents(e: Evidence): CheckResult {
    if (!e.incidents) return { status: 'na', evidence: ['No incidents recorded. Incident mode writes a report to ~/.ai-bom/incidents/ when you use it.'] };
    return { status: 'met', evidence: [`${plural(e.incidents, 'incident report')} in ~/.ai-bom/incidents/ (what was paused, keys to rotate, recent activity).`] };
  },

  toolIntegrity(e: Evidence): CheckResult {
    const tools = of(e, 'mcp-server').reduce((n, a) => n + (a.mcp?.tools?.length ?? 0), 0);
    return byFindings(
      active(e, rules('TOOL-BEHAVIOR-MISMATCH', 'TOOL-UNDECLARED', 'MCP-TOOL-POISONING', 'MCP-TOOL-SHADOWING', 'LIVE-*', 'TRUST-TOOLS-CHANGED')),
      [`${plural(tools, 'tool')} compared with what their code does.`],
      'tools doing more than they say',
      'Remove or replace tools that do more than their description says.',
    );
  },

  dataResources(e: Evidence): CheckResult {
    const reaching = e.inv.assets.filter((a) => a.reach?.credentials.length || a.reach?.files.length).length;
    return byFindings(
      active(e, rules('MCP-SECRET', 'SETTINGS-SECRET', 'APIKEY-*', 'CONTENT-SECRET', 'CONTENT-SENSITIVE-PATHS', 'MCP-BROAD-FS')),
      [`What each tool can reach (files, credentials, accounts) is documented; ${plural(reaching, 'asset')} reach files or credentials.`],
      'credentials and data access',
      'Move secrets to the keychain and narrow folder access.',
    );
  },

  compute(e: Evidence): CheckResult {
    const models = of(e, 'model').length;
    const apps = of(e, 'app').length;
    const keys = of(e, 'api-key').length;
    return { status: 'met', evidence: [`${plural(models, 'local model')}, ${plural(apps, 'AI app')} and ${plural(keys, 'AI API key')} inventoried.`] };
  },
} satisfies Record<string, (e: Evidence) => CheckResult>;

/* ---------------- Frameworks ---------------- */

const NIST: ControlDef[] = [
  { id: 'GOVERN 1.1', group: 'Govern', org: true, title: 'Legal and regulatory requirements', ask: 'Know which laws and rules apply to how you use AI (work contracts, client data, privacy law).', hint: 'You know whether your employer or clients restrict which AI tools or data you may use.' },
  { id: 'GOVERN 1.5', group: 'Govern', title: 'Ongoing monitoring and periodic review', ask: 'Review your AI setup regularly, not once.', check: CHECKS.cadence },
  { id: 'GOVERN 1.6', group: 'Govern', title: 'Inventory of AI systems', ask: 'Keep an inventory of the AI tools, servers, skills and accounts you use.', check: CHECKS.inventory },
  { id: 'GOVERN 1.7', group: 'Govern', title: 'Decommissioning AI systems safely', ask: 'Remove AI tools you no longer use, so they stop having access.', check: CHECKS.decommission },
  { id: 'GOVERN 6.1', group: 'Govern', title: 'Policies for third-party AI risks', ask: 'Have a rule for how third-party servers, skills and plugins get added.', hint: 'For example: new servers only through `ai-bom add`, pinned to a version, from publishers you recognize.' },
  { id: 'GOVERN 6.2', group: 'Govern', title: 'Contingency for third-party failures or incidents', ask: 'Know what you will do if a tool you use is compromised.', hint: 'You know how to use `ai-bom incident` and where to rotate your main keys.' },
  { id: 'MAP 1.1', group: 'Map', title: 'Intended purpose and context documented', ask: 'Know what you use each AI tool for, and what data it should never see.', hint: 'A short note of what each tool is for and which data stays out (client data, production secrets…).' },
  { id: 'MAP 3.5', group: 'Map', title: 'Human oversight defined', ask: 'Agents ask before acting where it matters.', check: CHECKS.oversight },
  { id: 'MAP 4.1', group: 'Map', title: 'Risks of third-party components mapped', ask: 'Know which third-party packages and services your agents run, and their versions.', check: CHECKS.components },
  { id: 'MAP 4.2', group: 'Map', title: 'Internal controls for third-party components', ask: 'Controls around those components: pinned versions, secrets kept out of config files.', check: CHECKS.controls },
  { id: 'MEASURE 2.4', group: 'Measure', title: 'Behavior monitored in use', ask: 'Watch what agents and tools actually do, not only how they are configured.', check: CHECKS.monitoring },
  { id: 'MEASURE 2.7', group: 'Measure', title: 'Security and resilience evaluated', ask: 'Your setup is checked for security issues and known vulnerabilities.', check: CHECKS.securityEval },
  { id: 'MEASURE 2.10', group: 'Measure', title: 'Privacy risk examined', ask: 'Know where your prompts, files and secrets can be sent.', check: CHECKS.privacy },
  { id: 'MEASURE 3.1', group: 'Measure', title: 'Emergent risks tracked', ask: 'Notice new risks: new advisories, tools that change after you approved them.', check: CHECKS.emergent },
  { id: 'MANAGE 1.3', group: 'Manage', title: 'Responses to high-priority risks', ask: 'Each serious risk is fixed, avoided, or consciously accepted.', check: CHECKS.highRisk },
  { id: 'MANAGE 1.4', group: 'Manage', title: 'Residual risks documented', ask: 'Risks you accept are written down with a reason.', check: CHECKS.residual },
  { id: 'MANAGE 2.4', group: 'Manage', title: 'Ability to disengage or deactivate', ask: 'You can switch tools off quickly when something looks wrong.', check: CHECKS.deactivate },
  { id: 'MANAGE 3.1', group: 'Manage', title: 'Third-party risks monitored and controlled', ask: 'Third-party servers and packages are monitored for vulnerabilities and bad signals.', check: CHECKS.thirdParty },
  { id: 'MANAGE 3.2', group: 'Manage', title: 'Pre-trained models monitored', ask: 'Downloaded models are tracked and in safe formats.', check: CHECKS.models },
  { id: 'MANAGE 4.1', group: 'Manage', title: 'Post-deployment monitoring, incident response and change management', ask: 'Ongoing scans, monitoring and reversible changes.', check: CHECKS.postDeploy },
  { id: 'MANAGE 4.3', group: 'Manage', title: 'Incidents tracked and communicated', ask: 'When something goes wrong, there is a record of what happened and what you did.', check: CHECKS.incidents },
];

const ISO: ControlDef[] = [
  { id: 'A.2.2', group: 'A.2 Policies', title: 'AI policy', ask: 'A short policy for your own AI use.', hint: 'Which tools you use, which data never goes into them, and how a new tool gets approved.' },
  { id: 'A.3.2', group: 'A.3 Internal organization', org: true, title: 'AI roles and responsibilities', ask: 'Who is responsible for what. On your own machine, that is you.', hint: 'If others share this machine or your accounts, you know who may change AI settings.' },
  { id: 'A.4.2', group: 'A.4 Resources', title: 'Resource documentation', ask: 'The AI resources you use are documented.', check: CHECKS.inventory },
  { id: 'A.4.3', group: 'A.4 Resources', title: 'Data resources', ask: 'What data each tool can reach is known and limited.', check: CHECKS.dataResources },
  { id: 'A.4.4', group: 'A.4 Resources', title: 'Tooling resources', ask: 'The tools, packages and versions your agents use are documented.', check: CHECKS.components },
  { id: 'A.4.5', group: 'A.4 Resources', title: 'System and computing resources', ask: 'Models, AI apps and API keys on the machine are documented.', check: CHECKS.compute },
  { id: 'A.5.2', group: 'A.5 Impact assessment', title: 'AI system impact assessment', ask: 'Consider what could go wrong for you or others if an AI tool misbehaves.', hint: 'You considered the worst case for your most powerful tools (shell access, email, production credentials).' },
  { id: 'A.6.2.6', group: 'A.6 Life cycle', title: 'Operation and monitoring', ask: 'AI tools are monitored while in use.', check: CHECKS.monitoring },
  { id: 'A.6.2.8', group: 'A.6 Life cycle', title: 'Recording of event logs', ask: 'What agents did is logged and can be reviewed.', check: CHECKS.eventLogs },
  { id: 'A.8.4', group: 'A.8 Information for interested parties', title: 'Communication of incidents', ask: 'Incidents are recorded so they can be reported to whoever needs to know.', check: CHECKS.incidents },
  { id: 'A.9.2', group: 'A.9 Use of AI systems', title: 'Processes for responsible use', ask: 'Agents work with your approval where it matters.', check: CHECKS.oversight },
  { id: 'A.9.3', group: 'A.9 Use of AI systems', title: 'Objectives for responsible use', ask: 'You know what you want from AI and what you won’t use it for.', hint: 'A few lines on what AI should and shouldn’t do for you.' },
  { id: 'A.9.4', group: 'A.9 Use of AI systems', title: 'Intended use', ask: 'Tools do what they are described to do, and nothing more.', check: CHECKS.toolIntegrity },
  { id: 'A.10.2', group: 'A.10 Third parties', org: true, title: 'Allocating responsibilities', ask: 'Responsibilities between you and AI providers are clear.', hint: 'You know which provider handles your data for each AI tool, and under which terms.' },
  { id: 'A.10.3', group: 'A.10 Third parties', title: 'Suppliers', ask: 'Third-party servers and packages are vetted and monitored.', check: CHECKS.thirdParty },
];

export const FRAMEWORKS: Record<FrameworkId, { name: string; version: string; url: string; controls: ControlDef[] }> = {
  'nist-ai-rmf': { name: 'NIST AI RMF', version: '1.0 (AI 100-1)', url: 'https://www.nist.gov/itl/ai-risk-management-framework', controls: NIST },
  'iso-42001': { name: 'ISO/IEC 42001', version: '2023, Annex A', url: 'https://www.iso.org/standard/81230.html', controls: ISO },
};

export const isFramework = (s: unknown): s is FrameworkId => s === 'nist-ai-rmf' || s === 'iso-42001';
/** A confirmation older than this is treated as unanswered: policies and practices drift. */
export const ATTEST_MAX_AGE_DAYS = 90;

export const attestKey = (fw: FrameworkId, id: string) => `${fw}:${id}`;

export function evaluate(fw: FrameworkId, e: Evidence): BaselineReport {
  const def = FRAMEWORKS[fw];
  const controls = def.controls.map((c): ControlResult => {
    const base = { id: c.id, group: c.group, title: c.title, ask: c.ask, org: c.org, hint: c.hint };
    if (c.check) {
      const r = c.check(e);
      return { ...base, auto: true, status: r.status, evidence: r.evidence, findings: r.findings ?? [], action: r.action };
    }
    const a = e.attestations[attestKey(fw, c.id)];
    const stale = a?.status === 'done' && (e.now.getTime() - new Date(a.at).getTime()) / 86_400_000 > ATTEST_MAX_AGE_DAYS;
    const status: ControlStatus = !a || stale ? 'manual' : a.status === 'na' ? 'na' : 'attested';
    return { ...base, auto: false, status, evidence: a?.note ? [a.note] : [], findings: [], attestation: a, stale: stale || undefined };
  });
  const counts = { met: 0, partial: 0, gap: 0, manual: 0, attested: 0, na: 0 } as Record<ControlStatus, number>;
  for (const c of controls) counts[c.status]++;
  const applicable = controls.length - counts.na;
  const coverage = applicable ? Math.round(((counts.met + counts.attested + counts.partial / 2) / applicable) * 100) : 100;
  return { framework: fw, name: def.name, version: def.version, url: def.url, controls, counts, coverage };
}

/* ---------------- Persistence ---------------- */

export const attestationsFile = () => path.join(dataDir(), 'attestations.json');

export async function loadAttestations(): Promise<Record<string, Attestation>> {
  const f = await readJsonFile<{ entries?: Record<string, Attestation> }>(attestationsFile());
  return f?.entries ?? {};
}

/** Record (or clear, with status undefined) your answer for a control AI-BOM can't check. */
export async function attest(fw: FrameworkId, id: string, status: Attestation['status'] | undefined, note?: string): Promise<{ id: string; entries: Record<string, Attestation> }> {
  const c = FRAMEWORKS[fw].controls.find((x) => x.id.toLowerCase() === id.toLowerCase());
  if (!c) throw new Error(`Unknown control ${id} in ${FRAMEWORKS[fw].name}.`);
  if (c.check) throw new Error(`${c.id} is checked from your scan; it can’t be marked by hand.`);
  const entries = await loadAttestations();
  const key = attestKey(fw, c.id);
  if (status) entries[key] = { status, note: note?.trim().slice(0, 500) || undefined, at: new Date().toISOString() };
  else delete entries[key];
  await writeJsonFile(attestationsFile(), { version: 1, entries });
  return { id: c.id, entries };
}

async function countIncidents(): Promise<number> {
  try {
    return (await fs.readdir(path.join(dataDir(), 'incidents'))).filter((n) => n.endsWith('.md')).length;
  } catch {
    return 0;
  }
}

export async function gatherEvidence(inv: Inventory): Promise<Evidence> {
  return { inv, scans: await readScans(200), incidents: await countIncidents(), attestations: await loadAttestations(), now: new Date() };
}

export async function baselines(inv: Inventory): Promise<Record<FrameworkId, BaselineReport>> {
  const e = await gatherEvidence(inv);
  return { 'nist-ai-rmf': evaluate('nist-ai-rmf', e), 'iso-42001': evaluate('iso-42001', e) };
}
