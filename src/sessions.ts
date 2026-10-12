import path from 'node:path';
import { logSources, readCalls, resultText, type AgentId } from './agentlogs.js';
import type { Collector } from './collector.js';
import type { Asset, Inventory, Usage } from './types.js';
import type { Findings } from './checks/index.js';
import { INJECTION } from './checks/index.js';
import { scanHidden } from './analysis/hidden.js';
import { SUSPICIOUS_HOSTS } from './checks/capabilities.js';
import { findTokenPattern, redactText } from './util/secrets.js';

/**
 * Real usage and a per-call audit from Claude Code's session logs
 * (<claude dir>/projects/<project>/<session>.jsonl).
 *
 * Everything stays on this machine. From each tool call we keep only the tool
 * name, time and project for usage counts. MCP calls are also audited: their
 * arguments are checked for credentials and suspicious destinations, and their
 * results for text aimed at the model. Findings keep a short, redacted excerpt.
 */

export interface SessionOptions {
  /** Only read logs modified within this many days (default 90). */
  days?: number;
  maxFiles?: number;
  /** Home folder (for Codex and Gemini CLI logs). */
  home?: string;
}

interface Tally {
  count: number;
  last?: string;
  tools: Map<string, number>;
  projects: Set<string>;
}

type EventKind = 'secret' | 'injection' | 'destination';

interface CallEvent {
  kind: EventKind;
  /** agent|server key, as in SessionReport.mcp */
  server: string;
  tool: string;
  count: number;
  first?: string;
  last?: string;
  evidence: string;
  hidden?: boolean;
  file: string;
}

export interface SessionReport {
  files: number;
  toolCalls: number;
  mcpCalls: number;
  audited: number;
  since?: string;
  until?: string;
  /** Files read per agent. */
  agents: Partial<Record<AgentId, number>>;
  /** Keyed "agent|normalized server" (or "gemini-cli|?tool:<name>" when Gemini doesn't say which server). */
  mcp: Map<string, Tally>;
  skills: Map<string, Tally>;
  agentsUsed: Map<string, Tally>;
  events: Map<string, CallEvent>;
}

/** How Claude Code names MCP tools: mcp__<server>__<tool>, with the server name sanitized. */
export const normalizeServer = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

function tally(map: Map<string, Tally>, key: string, at: string | undefined, project: string | undefined, tool?: string) {
  let t = map.get(key);
  if (!t) map.set(key, (t = { count: 0, tools: new Map(), projects: new Set() }));
  t.count++;
  if (at && (!t.last || at > t.last)) t.last = at;
  if (project) t.projects.add(project);
  if (tool) t.tools.set(tool, (t.tools.get(tool) ?? 0) + 1);
}

function excerpt(text: string, index: number, width = 110): string {
  const start = Math.max(0, index - 30);
  return redactText(text.slice(start, start + width).replace(/\s+/g, ' ').trim());
}

const RAW_IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const PRIVATE_IP = /^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|aws_secret_access_key\s*=/;

/** Find the first credential in a tool call's arguments; returns "argument: kind". */
export function secretIn(input: unknown, prefix = ''): string | undefined {
  if (typeof input === 'string') {
    const t = findTokenPattern(input) ?? (PRIVATE_KEY.test(input) ? 'private key / cloud credential file' : undefined);
    return t ? `${prefix || 'input'}: ${t}` : undefined;
  }
  if (Array.isArray(input)) {
    for (let i = 0; i < input.length; i++) {
      const r = secretIn(input[i], `${prefix}[${i}]`);
      if (r) return r;
    }
  } else if (input && typeof input === 'object') {
    for (const [k, v] of Object.entries(input)) {
      const r = secretIn(v, prefix ? `${prefix}.${k}` : k);
      if (r) return r;
    }
  }
  return undefined;
}

export function suspiciousDestination(input: unknown): string | undefined {
  const text = JSON.stringify(input) ?? '';
  for (const m of text.matchAll(/https?:\/\/([A-Za-z0-9.-]+)(\/[^\s"'\\]*)?/g)) {
    const host = m[1].toLowerCase();
    if (SUSPICIOUS_HOSTS.test(host) || SUSPICIOUS_HOSTS.test(`${host}${m[2] ?? ''}`.replace(/\/[^/]*$/, ''))) return host;
    if (RAW_IP.test(host) && !PRIVATE_IP.test(host)) return host;
  }
  return undefined;
}

export { resultText };

/** Instruction text or invisible characters in a tool result, described for a finding. */
export function injectionIn(text: string): { evidence: string; hidden: boolean } | undefined {
  // Only strong signals: tool output (web pages, copied text) is full of stray zero-width spaces.
  const hidden = scanHidden(text);
  if (hidden?.strength === 'strong') {
    const msg = hidden.decoded.trim() ? `, hiding the text “${redactText(hidden.decoded.trim()).slice(0, 80)}”` : '';
    return { evidence: `invisible character ${hidden.first} in the result${msg}`, hidden: true };
  }
  for (const re of INJECTION) {
    const hit = re.exec(text);
    if (hit) return { evidence: excerpt(text, hit.index), hidden: false };
  }
  return undefined;
}

function record(r: SessionReport, e: Omit<CallEvent, 'count' | 'first' | 'last'>, at?: string) {
  const key = `${e.kind}|${e.server}|${e.tool}`;
  const cur = r.events.get(key);
  if (cur) {
    cur.count++;
    if (at && (!cur.last || at > cur.last)) cur.last = at;
    if (at && (!cur.first || at < cur.first)) cur.first = at;
  } else r.events.set(key, { ...e, count: 1, first: at, last: at });
}

export async function readSessions(claudeDir: string, opts: SessionOptions = {}): Promise<SessionReport> {
  const report: SessionReport = { files: 0, toolCalls: 0, mcpCalls: 0, audited: 0, agents: {}, mcp: new Map(), skills: new Map(), agentsUsed: new Map(), events: new Map() };
  const sources = await logSources({ claudeDir, home: opts.home ?? path.dirname(claudeDir) }, { days: opts.days, maxFiles: opts.maxFiles });
  for (const src of sources) {
    for (const file of src.files) {
      report.files++;
      report.agents[src.agent] = (report.agents[src.agent] ?? 0) + 1;
      for await (const c of readCalls(src, file)) {
        if (c.kind === 'prompt' || c.kind === 'response') continue;
        report.toolCalls++;
        const at = c.at;
        if (at && (!report.since || at < report.since)) report.since = at;
        if (at && (!report.until || at > report.until)) report.until = at;
        if (c.kind === 'mcp') {
          report.mcpCalls++;
          report.audited++;
          const server = c.server ? `${c.agent}|${normalizeServer(c.server)}` : `${c.agent}|?tool:${c.tool ?? c.name}`;
          const tool = c.tool ?? c.name;
          tally(report.mcp, server, at, c.project, tool);
          const secret = secretIn(c.input);
          if (secret) record(report, { kind: 'secret', server, tool, evidence: secret, file }, at);
          const dest = suspiciousDestination(c.input);
          if (dest) record(report, { kind: 'destination', server, tool, evidence: dest, file }, at);
          const inj = c.result ? injectionIn(c.result) : undefined;
          if (inj) record(report, { kind: 'injection', server, tool, evidence: inj.evidence, hidden: inj.hidden, file }, at);
        } else if (c.kind === 'skill' && typeof c.input.skill === 'string') {
          tally(report.skills, c.input.skill, at, c.project);
        } else if (c.kind === 'agent' && typeof c.input.subagent_type === 'string') {
          tally(report.agentsUsed, c.input.subagent_type, at, c.project);
        }
      }
    }
  }
  return report;
}

/** Clients whose session logs we read, named the same as the agent in the log. */
const LOGGED_CLIENTS = new Set<string>(['claude-code', 'codex', 'gemini-cli', 'claude-desktop', 'copilot-cli', 'cline']);

/** Keys ("agent|server") under which each agent's logs name this asset's MCP server. */
function serverKeys(a: Asset, pluginName: (id: string) => string | undefined): string[] {
  const out = new Set<string>();
  for (const o of a.occurrences) {
    if (a.kind === 'mcp-server' && LOGGED_CLIENTS.has(o.client)) {
      out.add(`${o.client}|${normalizeServer(o.name)}`);
      if (o.client === 'claude-code' && o.via) {
        const p = pluginName(o.via)?.split('@')[0];
        if (p) out.add(`claude-code|${normalizeServer(`plugin_${p}_${o.name}`)}`);
      }
    }
    if (a.kind === 'connector' && o.client === 'cloud:claude.ai') {
      out.add(`claude-code|${normalizeServer(o.name.startsWith('claude.ai') ? o.name : `claude.ai ${o.name}`)}`);
    }
  }
  // Gemini logs may name only the tool: match by the tools this server declares.
  if (a.kind === 'mcp-server' && a.occurrences.some((o) => o.client === 'gemini-cli')) for (const t of a.mcp?.tools ?? []) out.add(`gemini-cli|?tool:${t.name}`);
  return [...out];
}

function mergeTally(into: Tally | undefined, t: Tally): Tally {
  if (!into) return { count: t.count, last: t.last, tools: new Map(t.tools), projects: new Set(t.projects) };
  into.count += t.count;
  if (t.last && (!into.last || t.last > into.last)) into.last = t.last;
  for (const [k, n] of t.tools) into.tools.set(k, (into.tools.get(k) ?? 0) + n);
  for (const p of t.projects) into.projects.add(p);
  return into;
}

const toUsage = (t: Tally): Usage => ({
  count: t.count,
  lastUsedAt: t.last,
  tools: t.tools.size ? Object.fromEntries([...t.tools].sort((x, y) => y[1] - x[1])) : undefined,
  projects: t.projects.size ? [...t.projects].sort() : undefined,
  source: 'session-logs',
});

/** Attach usage to assets and turn audit events into findings. */
export function applySessions(col: Collector, report: SessionReport, f: Findings): Inventory['sessions'] {
  const assets = [...col.assets.values()];
  const pluginName = (id: string) => col.assets.get(id)?.name;
  const byServer = new Map<string, Asset>();
  for (const a of assets) for (const k of serverKeys(a, pluginName)) if (!byServer.has(k)) byServer.set(k, a);

  // The same server used from several agents adds up.
  const usage = new Map<string, Tally>();
  for (const [key, t] of report.mcp) {
    const a = byServer.get(key);
    if (a) usage.set(a.id, mergeTally(usage.get(a.id), t));
  }
  for (const [id, t] of usage) col.assets.get(id)!.usage = toUsage(t);
  for (const a of assets) {
    if (a.kind === 'skill' && !a.usage) {
      const key = [...report.skills.keys()].find((k) => k === a.name || k.split(':').pop() === a.name);
      if (key) a.usage = toUsage(report.skills.get(key)!);
    }
    if (a.kind === 'agent' && !a.usage) {
      const t = report.agentsUsed.get(a.name);
      if (t) a.usage = toUsage(t);
    }
  }

  for (const e of report.events.values()) {
    const a = byServer.get(e.server);
    const label = `${a?.name ?? e.server.split('|')[1].replace(/^\?tool:/, '')} → ${e.tool}`;
    const when = e.last ? ` Last seen ${e.last.slice(0, 10)}${e.count > 1 ? `; ${e.count} calls` : ''}.` : '';
    if (e.kind === 'secret') f.add('TOOLCALL-SECRET-SENT', 'high', { asset: a, location: e.file, evidence: `${label}: ${e.evidence}`, title: `Credential sent to ${label}`, detail: when });
    else if (e.kind === 'destination') f.add('TOOLCALL-SUSPICIOUS-DEST', 'high', { asset: a, location: e.file, evidence: `${label}: ${e.evidence}`, title: `${label} called ${e.evidence}`, detail: when });
    else f.add('TOOLCALL-INJECTION', e.hidden ? 'high' : 'medium', { asset: a, location: e.file, evidence: `${label}: ${e.evidence}`, title: `Instructions in ${label} output`, detail: when });
  }

  // Unused servers: only meaningful for agents whose logs cover a couple of weeks.
  const coverDays = report.since && report.until ? (Date.parse(report.until) - Date.parse(report.since)) / 86_400_000 : 0;
  if (coverDays >= 14) {
    const logged = new Set(Object.keys(report.agents));
    for (const a of assets) {
      if (a.kind !== 'mcp-server' || a.usage) continue;
      const occ = a.occurrences.filter((o) => o.enabled !== false && !o.via && o.scope !== 'managed');
      // Every tool that loads it must be one whose logs we read.
      if (!occ.length || occ.some((o) => !logged.has(o.client))) continue;
      f.add('USAGE-UNUSED', 'low', { asset: a, location: occ[0].source, evidence: `No calls in ${Math.round(coverDays)} days of session logs`, title: `${a.name} is never used` });
    }
  }
  return { files: report.files, toolCalls: report.toolCalls, mcpCalls: report.mcpCalls, audited: report.audited, since: report.since, agents: report.agents };
}
