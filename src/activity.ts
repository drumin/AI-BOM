import path from 'node:path';
import { logSources, readCalls, type AgentId, type Call, type CallKind } from './agentlogs.js';
import { secretIn, suspiciousDestination, injectionIn } from './sessions.js';
import { commandFlag } from './activity-rules.js';
import { CREDENTIAL_PATHS } from './checks/capabilities.js';
import { redactText } from './util/secrets.js';

/**
 * "What did my agent actually do?" A per-session timeline built from the
 * agents' own logs: your prompts, commands run, files read, written and edited,
 * pages fetched, MCP tools called. Risky steps are flagged. Built on demand, locally; MCP
 * arguments are summarized by key name only and text is redacted.
 */

export interface TimelineEvent {
  at?: string;
  kind: CallKind;
  /** One line, redacted: "Ran: git status", "Wrote src/app.ts", "github → create_issue (title, body)". Prompts: what you typed. */
  text: string;
  /** The untruncated text (redacted) when `text` was shortened. */
  detail?: string;
  flag?: string;
  /** Plain-language reason for the flag, and the part of the step that triggered it. */
  why?: string;
  match?: string;
  /** The flag this step would have had, if you hadn't muted that kind. */
  mutedFlag?: string;
  /** Which mute rule hid the flag (a kind, one match, or one step), so the UI can undo exactly that rule. */
  mutedKey?: string;
  /** MCP steps: the server as written in the agent's config. */
  server?: string;
  /** What a shell command printed (redacted, trimmed). Never kept for commands that touch credentials. */
  output?: string;
  /** Output was deliberately not kept (the command touched credentials). */
  outputHidden?: boolean;
  failed?: boolean;
  /** Made by a subagent (its id) rather than the main agent. */
  sub?: string;
  /** What sensitive thing this step touched (a credential file), for the data trail. */
  sensitive?: string;
  /** How this step was approved when no person was asked: auto mode, permissions bypassed, headless, no approvals. */
  auto?: Autonomy;
  /** Hosts this step contacted (first few). */
  hosts?: string[];
  /** A tool's result contained instructions for the model; later steps may be the agent following them. */
  injected?: boolean;
  /** Set when this step changed a file that steers the agent (see AGENT_FILES). */
  agentFile?: 'instructions' | 'memory' | 'mcp-config';
  /** Happened soon after a tool result that contained instructions for the model: what returned them. */
  after?: string;
}

/** Who was in the loop for a step. Absent means the agent asked for approval as usual. */
export type Autonomy = 'auto' | 'bypass' | 'headless' | 'no-approval' | 'edits' | 'background';

/** A file an agent read, created or edited itself (files changed by shell commands are not tracked). */
export interface TouchedFile {
  path: string;
  read: number;
  wrote: number;
  edited: number;
}

export interface SessionActivity {
  agent: AgentId;
  session: string;
  project?: string;
  start?: string;
  end?: string;
  counts: Partial<Record<CallKind, number>>;
  flagged: number;
  events: TimelineEvent[];
  /** Hosts contacted (fetches, curl/wget, MCP arguments). */
  hosts: string[];
  /** Files written or edited. */
  files: string[];
  /** Every file read, created or edited through the agent's own file tools, changes first. */
  touched: TouchedFile[];
  /** Steps left out of `events` to keep this small (never prompts or flagged steps). */
  omitted: number;
  /** Sensitive files touched and where data could have gone, when either happened. */
  exposure?: Exposure;
  /** The ways approvals were skipped in this session, most common first. */
  modes: Autonomy[];
  /** Steps that came soon after a tool result carrying instructions for the model. */
  followed: number;
}

/** Files that steer an agent: what it reads at the start of every session, and which tool servers it can use. */
const AGENT_FILES: { kind: 'instructions' | 'memory' | 'mcp-config'; re: RegExp }[] = [
  { kind: 'mcp-config', re: /(^|\/)\.mcp\.json$|\/\.(cursor|vscode)\/mcp\.json$|\/\.claude\.json$|\/\.codex\/config\.toml$|\/\.gemini\/settings\.json$|claude_desktop_config\.json$/ },
  { kind: 'memory', re: /\/\.claude\/projects\/[^/]+\/memory\/|(^|\/)MEMORY\.md$/ },
  { kind: 'instructions', re: /(^|\/)(CLAUDE|AGENTS|GEMINI)(\.local)?\.md$|(^|\/)\.(cursorrules|windsurfrules|clinerules)\b|\/\.cursor\/rules\/|\.github\/copilot-instructions\.md$|\/\.claude\/(commands|agents|skills|output-styles)\// },
];

export interface Exposure {
  sensitive: { what: string; at?: string; count: number }[];
  contacts: { name: string; type: 'host' | 'tool'; count: number; first?: string; last?: string; /** Reached at or after the first sensitive access. */ after: boolean }[];
}

const MAX_EVENTS = 800;
const MAX_PROMPTS = 300;
const MAX_RESPONSES = 600;
const MAX_RESPONSE_DETAIL = 6000;
const MAX_TOUCHED = 300;
const MAX_DETAIL = 2000;
const MAX_OUTPUT = 1200;
/** Tools whose path is a search folder, not a file that was opened. */
const NOT_A_FILE = /^(Glob|Grep|glob|list_directory|search_file_content)$/;
const clip = (s: string, n = 180) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const str = (v: unknown) => (typeof v === 'string' ? v : Array.isArray(v) ? v.filter((x) => typeof x === 'string').join(' ') : '');

/** Drop heredoc bodies (file contents being written) so only the command itself is judged. */
export function withoutHeredocs(cmd: string): string {
  return cmd.replace(/<<-?\s*(['"]?)(\w+)\1[^\n]*\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, '<<$2 …');
}

function commandOf(c: Call): string {
  const i = c.input;
  let cmd = str(i.command ?? i.cmd ?? i.raw);
  // Codex wraps commands as ["bash", "-lc", "…"].
  const m = cmd.match(/^(?:ba|z)?sh -l?c (.+)$/s);
  if (m) cmd = m[1];
  return cmd;
}

function filesOf(c: Call): string[] {
  const i = c.input;
  const direct = [i.file_path, i.path, i.notebook_path, i.absolute_path].filter((x): x is string => typeof x === 'string');
  if (direct.length) return direct;
  // Codex apply_patch: "*** Update File: path"
  return [...str(i.input ?? i.patch ?? i.raw).matchAll(/\*\*\* (?:Add|Update|Delete) File: (.+)/g)].map((m) => m[1].trim());
}

const HOST = /https?:\/\/([A-Za-z0-9.-]+)/g;
const hostsIn = (s: string) => [...s.matchAll(HOST)].map((m) => m[1].toLowerCase()).filter((h) => !/^(localhost|127\.0\.0\.1)$/.test(h));

function autonomyOf(c: Call): Autonomy | undefined {
  if (c.entry === 'claude-desktop-dispatch') return 'background';
  if (c.entry?.startsWith('sdk')) return 'headless';
  if (c.mode === 'bypassPermissions') return 'bypass';
  if (c.mode === 'auto') return 'auto';
  if (c.mode === 'acceptEdits' && (c.kind === 'write' || c.kind === 'edit')) return 'edits';
  if (c.mode === 'never') return 'no-approval';
  return undefined;
}

function describe(c: Call, cwd?: string): TimelineEvent & { hosts: string[]; files: string[] } {
  const ev: TimelineEvent & { hosts: string[]; files: string[] } = { at: c.at, kind: c.kind, text: '', hosts: [], files: [], sub: c.sub, auto: c.kind === 'response' ? undefined : autonomyOf(c) };
  const rel = (p: string) => (cwd && p.startsWith(cwd + path.sep) ? path.relative(cwd, p) : p);
  switch (c.kind) {
    case 'prompt':
    case 'response': {
      const full = redactText(c.text ?? '').trim();
      ev.text = clip(full.replace(/\s+/g, ' '), 240);
      if (full.length > ev.text.length || full.includes('\n')) ev.detail = full.slice(0, c.kind === 'response' ? MAX_RESPONSE_DETAIL : MAX_DETAIL);
      break;
    }
    case 'command': {
      const full = commandOf(c);
      const cmd = withoutHeredocs(full);
      const one = redactText(full.replace(/\s+/g, ' '));
      ev.text = `Ran: ${clip(one)}`;
      if (one.length > 180) ev.detail = redactText(full).slice(0, MAX_DETAIL);
      ev.hosts = hostsIn(cmd);
      const hit = commandFlag(cmd);
      if (hit) Object.assign(ev, { flag: hit.flag, why: hit.why, match: redactText(hit.match) });
      if (hit?.sensitive) {
        ev.outputHidden = true;
        ev.sensitive = hit.match;
      }
      else if (c.output) ev.output = redactText(c.output).slice(0, MAX_OUTPUT);
      ev.failed = c.failed || undefined;
      break;
    }
    case 'write':
    case 'edit': {
      const files = filesOf(c);
      ev.files = files;
      ev.text = `${c.kind === 'write' ? 'Wrote' : 'Edited'} ${files.map(rel).join(', ') || c.name}`;
      const agentFile = AGENT_FILES.find((a) => files.some((f) => a.re.test(f)));
      if (agentFile) ev.agentFile = agentFile.kind;
      const outside = files.find((f) => path.isAbsolute(f) && cwd && !f.startsWith(cwd + path.sep) && !f.startsWith('/tmp/') && !f.startsWith('/private/tmp/'));
      const startup = files.find((f) => /\/\.(zshrc|bashrc|bash_profile|profile|zprofile|ssh\/|aws\/|gitconfig)|\/Library\/LaunchAgents\/|\.claude\/settings/.test(f));
      if (startup) Object.assign(ev, { flag: 'Changed a startup, credential or agent settings file', why: 'This file runs automatically, holds credentials, or controls the agent itself, so a change here can alter behavior later without you noticing.', match: rel(startup) });
      else if (agentFile?.kind === 'mcp-config') Object.assign(ev, { flag: 'Changed which tool servers the agent uses', why: 'Adding or editing a server in this file gives the agent new tools and reach, and servers start with the agent’s own permissions.', match: rel(files.find((f) => agentFile.re.test(f)) ?? files[0]) });
      // The agent's own memory lives outside the project by design; changes there are judged by what came before them.
      else if (outside && agentFile?.kind !== 'memory') Object.assign(ev, { flag: 'Wrote outside the project folder', why: 'The agent was started in one project but changed a file somewhere else on your computer.', match: rel(outside) });
      break;
    }
    case 'read': {
      const files = filesOf(c);
      ev.text = `Read ${files.map(rel).join(', ') || str(c.input.pattern) || c.name}`;
      const cred = files.find((f) => CREDENTIAL_PATHS.some((re) => re.test(f)) || /\/\.ssh\/|\.env$/.test(f));
      if (cred) ev.sensitive = rel(cred);
      if (cred) Object.assign(ev, { flag: 'Read a credential file', why: 'It opened a file that normally holds passwords or keys. Its contents are now part of the conversation.', match: rel(cred) });
      break;
    }
    case 'fetch': {
      const url = str(c.input.url ?? c.input.prompt);
      ev.text = `Fetched ${clip(redactText(url), 140)}`;
      ev.hosts = hostsIn(url);
      const bad = suspiciousDestination(c.input);
      if (bad) Object.assign(ev, { flag: `Contacted ${bad}`, why: 'This host is commonly used for paste sites, webhooks or throwaway servers, which are where stolen data tends to end up.', match: bad });
      break;
    }
    case 'search':
      ev.text = `Searched the web: ${clip(redactText(str(c.input.query)), 120)}`;
      break;
    case 'mcp': {
      const keys = Object.keys(c.input).slice(0, 6);
      ev.text = `${c.server ?? '?'} → ${c.tool ?? c.name}${keys.length ? ` (${keys.join(', ')})` : ''}`;
      ev.hosts = hostsIn(JSON.stringify(c.input));
      const secret = secretIn(c.input);
      const dest = suspiciousDestination(c.input);
      const inj = c.result ? injectionIn(c.result) : undefined;
      ev.server = c.server;
      if (inj) ev.injected = true;
      if (secret) Object.assign(ev, { flag: `Sent a credential (${secret})`, why: 'A token or key was included in what was sent to this tool, so the tool’s server now has it.' });
      else if (dest) Object.assign(ev, { flag: `Sent data to ${dest}`, why: 'The tool was given a link to a host commonly used to collect data (paste sites, webhooks).', match: dest });
      else if (inj) Object.assign(ev, { flag: 'Result contained instructions for the model', why: 'The tool’s reply contained text addressed to the AI model, a known way to hijack an agent.' });
      break;
    }
    case 'skill':
      ev.text = `Used skill ${str(c.input.skill)}`;
      break;
    case 'agent':
      ev.text = `Started subagent ${str(c.input.subagent_type) || 'task'}: ${clip(redactText(str(c.input.description)), 100)}`;
      break;
    default:
      ev.text = c.name;
  }
  return ev;
}

export async function readActivity(dirs: { claudeDir: string; home: string }, opts: { days?: number; sessions?: number; session?: string; mutedFlags?: Iterable<string> } = {}): Promise<SessionActivity[]> {
  const muted = new Set(opts.mutedFlags ?? []);
  const byId = new Map<string, SessionActivity>();
  const touched = new Map<string, Map<string, TouchedFile>>();
  const counts = new Map<string, number>();
  const actionCount = new Map<string, number>();
  const modes = new Map<string, Map<Autonomy, number>>();
  const modeCount = (key: string, a: Autonomy) => {
    const m = modes.get(key) ?? modes.set(key, new Map()).get(key)!;
    m.set(a, (m.get(a) ?? 0) + 1);
  };
  const trail = new Map<string, { sensitive: Map<string, { what: string; at?: string; count: number }>; contacts: Map<string, Exposure['contacts'][number]> }>();
  for (const src of await logSources(dirs, { days: opts.days ?? 14, maxFiles: 500 })) {
    for (const file of src.files) {
      for await (const c of readCalls(src, file)) {
        const key = `${c.agent}|${c.session}`;
        if (opts.session && c.session !== opts.session && !c.session.startsWith(opts.session)) continue;
        let s = byId.get(key);
        if (!s) byId.set(key, (s = { agent: c.agent, session: c.session, project: c.project, counts: {}, flagged: 0, events: [], hosts: [], files: [], touched: [], omitted: 0, modes: [], followed: 0 }));
        s.project ??= c.project;
        if (!actionCount.has(key)) actionCount.set(key, 0);
        const ev = describe(c, s.project);
        const rule = ev.flag ? mutedBy(muted, ev.flag, ev.match, ev.at) : undefined;
        if (ev.flag && rule) {
          ev.mutedFlag = ev.flag;
          ev.mutedKey = rule;
          ev.flag = undefined;
        }
        s.counts[c.kind] = (s.counts[c.kind] ?? 0) + 1;
        if (ev.auto) modeCount(key, ev.auto);
        if (ev.flag) s.flagged++;
        if (c.at && (!s.start || c.at < s.start)) s.start = c.at;
        if (c.at && (!s.end || c.at > s.end)) s.end = c.at;
        for (const h of ev.hosts) if (!s.hosts.includes(h) && s.hosts.length < 40) s.hosts.push(h);
        for (const f of ev.files) if (!s.files.includes(f) && s.files.length < 200) s.files.push(f);
        const t = trail.get(key) ?? trail.set(key, { sensitive: new Map(), contacts: new Map() }).get(key)!;
        if (ev.sensitive) {
          const x = t.sensitive.get(ev.sensitive) ?? { what: ev.sensitive, at: c.at, count: 0 };
          x.count++;
          if (c.at && (!x.at || c.at < x.at)) x.at = c.at;
          if (t.sensitive.size < 40) t.sensitive.set(ev.sensitive, x);
        }
        const reached: [string, 'host' | 'tool'][] = [...ev.hosts.map((h): [string, 'host' | 'tool'] => [h, 'host']), ...(c.kind === 'mcp' && c.server ? ([[c.server, 'tool']] as [string, 'tool'][]) : [])];
        for (const [name, type] of reached) {
          const k = `${type}|${name}`;
          const x = t.contacts.get(k) ?? { name, type, count: 0, first: c.at, last: c.at, after: false };
          x.count++;
          if (c.at && (!x.first || c.at < x.first)) x.first = c.at;
          if (c.at && (!x.last || c.at > x.last)) x.last = c.at;
          if (t.contacts.size < 60) t.contacts.set(k, x);
        }
        if ((c.kind === 'read' || c.kind === 'write' || c.kind === 'edit') && !NOT_A_FILE.test(c.name)) {
          const map = (touched.get(key) ?? touched.set(key, new Map()).get(key))!;
          for (const f of filesOf(c)) {
            const t = map.get(f) ?? (map.size < MAX_TOUCHED ? { path: f, read: 0, wrote: 0, edited: 0 } : undefined);
            if (!t) continue;
            map.set(f, t);
            if (c.kind === 'read') t.read++;
            else if (c.kind === 'write') t.wrote++;
            else t.edited++;
          }
        }
        // Keep every prompt and flagged step; cap the rest.
        const own = c.kind === 'prompt' || c.kind === 'response';
        const ck = `${key}|${c.kind}`;
        // Steps the cross-checks below need (instructions from tools, network use, files that steer the agent) are kept too.
        const needed = ev.flag || ev.injected || ev.agentFile || ev.hosts.length > 0;
        const keep = needed || (own ? (counts.get(ck) ?? 0) < (c.kind === 'prompt' ? MAX_PROMPTS : MAX_RESPONSES) : actionCount.get(key)! < MAX_EVENTS);
        if (own) counts.set(ck, (counts.get(ck) ?? 0) + 1);
        else actionCount.set(key, (actionCount.get(key) ?? 0) + (keep ? 1 : 0));
        if (keep) s.events.push({ at: ev.at, kind: ev.kind, text: ev.text, detail: ev.detail, flag: ev.flag, why: ev.why, match: ev.match, mutedFlag: ev.mutedFlag, mutedKey: ev.mutedKey, server: ev.server, output: ev.output, outputHidden: ev.outputHidden, failed: ev.failed, sub: ev.sub, auto: ev.auto, hosts: ev.hosts.length ? ev.hosts.slice(0, 3) : undefined, injected: ev.injected, agentFile: ev.agentFile });
        else s.omitted++;
      }
    }
  }
  const list = [...byId.values()];
  for (const [key, map] of touched) {
    const s = byId.get(key)!;
    s.touched = [...map.values()].sort((a, b) => b.wrote + b.edited - (a.wrote + a.edited) || b.read - a.read || a.path.localeCompare(b.path));
  }
  for (const [key, t] of trail) {
    const s = byId.get(key)!;
    if (!t.sensitive.size && !t.contacts.size) continue;
    const sensitive = [...t.sensitive.values()].sort((a, b) => (a.at ?? '').localeCompare(b.at ?? ''));
    const firstAt = sensitive[0]?.at;
    const contacts = [...t.contacts.values()].map((x) => ({ ...x, after: !!firstAt && !!x.last && x.last >= firstAt })).sort((a, b) => Number(b.after) - Number(a.after) || b.count - a.count);
    s.exposure = { sensitive, contacts };
  }
  for (const [key, m] of modes) byId.get(key)!.modes = [...m.entries()].sort((a, b) => b[1] - a[1]).map(([a]) => a);
  for (const s of list) {
    s.events.sort((a, b) => (a.at ?? '').localeCompare(b.at ?? ''));
    correlate(s, muted);
  }
  return list.sort((a, b) => (b.end ?? '').localeCompare(a.end ?? '')).slice(0, opts.sessions ?? 30);
}

/**
 * Mute rules are strings: a whole kind ("<flag>"), one match of it ("<flag>::match::<text>"), or one step
 * ("<flag>::step::<time>"). Returns the rule that hides this step, if any.
 * shortcut: a step is identified by its timestamp alone, so two flagged steps in the same millisecond share a rule; add the session if that ever happens.
 */
export const matchRule = (flag: string, match: string) => `${flag}::match::${match}`;
export const stepRule = (flag: string, at: string) => `${flag}::step::${at}`;
export function mutedBy(muted: Set<string>, flag: string, match?: string, at?: string): string | undefined {
  return [flag, match && matchRule(flag, match), at && stepRule(flag, at)].find((k) => k && muted.has(k)) || undefined;
}

/** Give a step a flag unless that kind is muted (then keep it as `mutedFlag`, as readActivity does). */
function assign(e: TimelineEvent, muted: Set<string>, flag: string, why: string, match?: string) {
  const rule = mutedBy(muted, flag, match, e.at);
  if (rule) Object.assign(e, { mutedFlag: flag, mutedKey: rule });
  else Object.assign(e, { flag, why, match });
}

const ms = (at?: string) => (at ? Date.parse(at) : NaN);
const normalize = (t: string) => t.replace(/\d+/g, '#').replace(/\s+/g, ' ');

/**
 * Judgements that need the steps in order, made once a session is assembled:
 *  - what happened soon after a tool result carried instructions for the model (a hijack in progress looks like this);
 *  - an agent changing its own instructions or memory after reading outside content;
 *  - loops that hammer one host or one tool.
 * Each of these sets a flag, so they appear in the flagged view and can be muted like any other.
 */
function correlate(s: SessionActivity, muted: Set<string>) {
  let outside: TimelineEvent | undefined;
  let inj: { from: string; left: number } | undefined;
  const repeats = new Map<string, number>();
  const window = new Map<string, number[]>();
  const flaggedOnce = new Set<string>();
  const burst = (key: string, at: number, limit: number, span: number) => {
    const w = (window.get(key) ?? []).filter((t) => at - t <= span);
    w.push(at);
    window.set(key, w);
    return w.length >= limit && !flaggedOnce.has(key) && !!flaggedOnce.add(key);
  };
  for (const e of s.events) {
    if (e.kind === 'prompt') {
      outside = undefined;
      inj = undefined;
      continue;
    }
    if (e.kind === 'fetch' || e.kind === 'search' || e.kind === 'mcp') outside ??= e;
    if (e.injected) {
      inj = { from: e.server ?? 'a tool', left: 25 };
      continue;
    }
    const raw = e.flag ?? e.mutedFlag;
    if (e.agentFile && e.agentFile !== 'mcp-config' && !raw && outside) {
      assign(e, muted, 'Changed the agent’s own instructions after reading outside content', 'Files like CLAUDE.md, AGENTS.md and the memory folder are read at the start of every session, so a change here can quietly steer the agent later. It happened after the agent had read web pages or tool output, which is how a hijack is made to stick.', e.text.replace(/^(Wrote|Edited) /, ''));
    }
    if (inj) {
      inj.left--;
      const acting = !!raw || e.hosts?.length || e.agentFile || e.kind === 'write' || e.kind === 'edit';
      if (inj.left < 0) inj = undefined;
      else if (acting) {
        e.after = inj.from;
        s.followed++;
        if (!e.flag && !e.mutedFlag) assign(e, muted, 'Acted right after instructions in a tool result', `${inj.from} returned text addressed to the AI model just before this step. If the agent followed it, this step is the result. Check it was something you asked for.`);
      }
    }
    if (!e.flag && !e.mutedFlag && e.hosts?.length && e.kind === 'command') {
      const key = `${e.hosts[0]}|${normalize(e.text)}`;
      repeats.set(key, (repeats.get(key) ?? 0) + 1);
      if (repeats.get(key) === 10) assign(e, muted, 'Repeated a network command many times', 'The same command that talks to the network has now run 10 times. A loop like this can hammer a service, hit rate limits or run up a bill.');
    }
    const t = ms(e.at);
    if (!e.flag && !e.mutedFlag && e.hosts?.length && (e.kind === 'command' || e.kind === 'fetch') && !Number.isNaN(t) && burst(`host|${e.hosts[0]}`, t, 30, 60_000)) {
      assign(e, muted, 'Burst of requests to one host', `30 or more requests to ${e.hosts[0]} within a minute. An agent in a loop can overwhelm a service or get your address blocked.`, e.hosts[0]);
    }
    if (!e.flag && !e.mutedFlag && e.kind === 'mcp' && !Number.isNaN(t) && burst(`tool|${e.text.split(' (')[0]}`, t, 40, 300_000)) {
      assign(e, muted, 'Called one tool in a tight loop', `40 or more calls to ${e.text.split(' (')[0]} within five minutes. This is usually a runaway loop, and it can use up quotas or push changes repeatedly.`);
    }
  }
  s.flagged = s.events.filter((e) => e.flag).length;
}

/** Markdown export of sessions, flagged steps first. */
export function activityMarkdown(list: SessionActivity[]): string {
  const out: string[] = [];
  for (const s of list) {
    out.push(`### ${s.agent} · ${s.project ?? 'unknown folder'} · ${s.start?.slice(0, 16).replace('T', ' ') ?? '?'} → ${s.end?.slice(11, 16) ?? '?'}`, '');
    out.push(`Session \`${s.session}\` · ${Object.entries(s.counts).map(([k, n]) => `${n} ${k}`).join(', ')}${s.hosts.length ? ` · contacted ${s.hosts.join(', ')}` : ''}`, '');
    const flagged = s.events.filter((e) => e.flag);
    if (flagged.length) {
      out.push('**Flagged**', '');
      for (const e of flagged) out.push(`- ${e.at?.slice(11, 19) ?? ''} ${e.text} — **${e.flag}**`);
      out.push('');
    }
    out.push('<details><summary>All steps</summary>', '');
    for (const e of s.events) out.push(`- ${e.at?.slice(11, 19) ?? ''} ${e.kind === 'prompt' ? `**Prompt:** ${e.text}` : e.kind === 'response' ? `**Reply:** ${e.text}` : e.text}${e.flag ? ` — **${e.flag}**` : ''}`);
    out.push('', '</details>', '');
    if (s.touched.length) {
      out.push('<details><summary>Files touched</summary>', '');
      for (const t of s.touched) out.push(`- \`${t.path}\` — ${[t.wrote && `created ×${t.wrote}`, t.edited && `edited ×${t.edited}`, t.read && `read ×${t.read}`].filter(Boolean).join(', ')}`);
      out.push('', '</details>', '');
    }
  }
  return out.join('\n');
}
