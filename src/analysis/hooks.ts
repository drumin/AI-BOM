import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Collector } from '../collector.js';
import type { Asset, Capability, ClientId, HookExplanation, TelemetryDetails } from '../types.js';
import type { Findings } from '../checks/index.js';
import { analyzeFile, newReport } from '../checks/capabilities.js';
import { asString, isObject, readStructured, readSmallText } from '../util/fs.js';
import { readShellExports, type ShellExport } from '../scanners/shell.js';

/**
 * What your hooks actually do, in plain words, and where your agent's
 * telemetry goes.
 *
 * Hooks run automatically on agent events and are handed data: every prompt
 * you type, every tool call's input and output, or the path to the whole
 * transcript. A hook that also talks to the network is a data-egress path you
 * may never have agreed to (a "telemetry" hook installed by a plugin, a
 * forgotten logging script…). The command is resolved to the scripts it runs,
 * and those scripts are read for network destinations.
 */

/** Hooks whose command/scripts send data off the machine (checked by checkHook to avoid double-reporting). */
export const egressHooks = new WeakSet<Asset>();

const TRIGGER: Record<string, [string, string, boolean]> = {
  // event: [when, what it receives, sensitive?]
  UserPromptSubmit: ['Every time you submit a prompt', 'the full text of your prompt', true],
  beforeSubmitPrompt: ['Every time you submit a prompt', 'the full text of your prompt', true],
  PreToolUse: ['Before each tool call', 'the tool name and its full input (commands, file paths, file contents being written)', true],
  PostToolUse: ['After each tool call', 'the tool input and its output (command output, file contents that were read)', true],
  PostToolUseFailure: ['After a tool call fails', 'the tool input and its error', true],
  PermissionRequest: ['When the agent asks for permission', 'the tool name and its input', true],
  BeforeTool: ['Before each tool call', 'the tool name and its input', true],
  AfterTool: ['After each tool call', 'the tool input and output', true],
  beforeShellExecution: ['Before each shell command', 'the command about to run', true],
  beforeMCPExecution: ['Before each MCP tool call', 'the tool name and its input', true],
  afterFileEdit: ['After each file edit', 'the edited file path and the changes', true],
  beforeReadFile: ['Before a file is read', 'the file path and its contents', true],
  Stop: ['When the agent finishes a reply', 'the path to the full conversation transcript', true],
  SubagentStop: ['When a subagent finishes', 'the path to the full conversation transcript', true],
  PreCompact: ['Before the conversation is compacted', 'the path to the full conversation transcript', true],
  SessionEnd: ['When a session ends', 'the path to the full conversation transcript', true],
  stop: ['When the agent finishes', 'the conversation id and status', false],
  SessionStart: ['When a session starts', 'the session id, working folder and transcript path', true],
  Notification: ['When the agent shows a notification', 'the notification text', false],
  statusLine: ['Every time the status line refreshes', 'session details (model, folder, cost, transcript path)', true],
  apiKeyHelper: ['When Claude Code needs an API key', 'nothing; whatever it prints is used as your API key', false],
  awsAuthRefresh: ['When AWS credentials need refreshing', 'nothing; it refreshes cloud credentials', false],
  awsCredentialExport: ['When AWS credentials are needed', 'nothing; its output is used as AWS credentials', false],
  otelHeadersHelper: ['When telemetry is exported', 'nothing; its output becomes telemetry auth headers', false],
  folderOpen: ['As soon as the folder is opened in VS Code or Cursor', 'nothing; it simply runs', false],
  notify: ['After each agent turn', 'the last assistant message and your input messages', true],
};

function describeTrigger(event: string, matcher?: string): [string, string, boolean] {
  const t = TRIGGER[event] ?? [`On the "${event}" event`, 'event details from the agent', true];
  if (matcher && matcher !== '*' && /Tool/.test(event)) return [`${t[0]} matching ${matcher}`, t[1], t[2]];
  return t;
}

/** Split a shell command into words (quotes respected, no expansion). */
function words(cmd: string): string[] {
  return [...cmd.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
}

async function resolveScripts(col: Collector, a: Asset, cmd: string): Promise<string[]> {
  const o = a.occurrences[0];
  const plugin = o?.via ? col.assets.get(o.via) : undefined;
  const base = o?.project ?? (o?.source ? path.dirname(o.source) : col.ctx.home);
  const out: string[] = [];
  for (let w of words(cmd)) {
    w = w
      .replace(/\$\{?CLAUDE_PLUGIN_ROOT\}?/g, plugin?.path ?? '\0')
      .replace(/\$\{?CLAUDE_PROJECT_DIR\}?/g, o?.project ?? '\0')
      .replace(/\$\{?HOME\}?/g, col.ctx.home)
      .replace(/^~(?=\/)/, col.ctx.home);
    if (w.includes('\0') || !/[/.]/.test(w) || w.startsWith('-') || /^https?:/.test(w)) continue;
    const p = path.isAbsolute(w) ? w : path.resolve(base, w);
    try {
      const st = await fs.stat(p);
      if (st.isFile() && st.size < 1024 * 1024 && !out.includes(p)) out.push(p);
    } catch {
      /* not a file */
    }
    if (out.length >= 3) break;
  }
  return out;
}

const STDIN = /\bcat\b(?!\s+\S)|\bread\s+-|\bsys\.stdin\b|process\.stdin|\bjq\b|<&0|\$\(cat\)|fs\.readFileSync\(\s*(0|['"]\/dev\/stdin['"])/;

export async function explainHooks(col: Collector, f: Findings): Promise<void> {
  for (const a of col.assets.values()) {
    if (a.kind !== 'hook' || !a.hook) continue;
    const { event, matcher, command } = a.hook;
    const [trigger, receives, sensitive] = describeTrigger(event, matcher);
    const scripts = await resolveScripts(col, a, command);
    const report = newReport();
    analyzeFile('hook.sh', command, report);
    let readsStdin = STDIN.test(command) || /-d\s+@-|--data(-binary)?\s+@-/.test(command);
    for (const s of scripts) {
      const text = await readSmallText(s);
      if (!text) continue;
      analyzeFile(/\.\w+$/.test(s) ? s : `${s}.sh`, text, report);
      if (STDIN.test(text) || /transcript_path/.test(text)) readsStdin = true;
    }
    const caps = [...report.capabilities] as Capability[];
    // Hosts written in the command itself are always named (the content scanner skips example domains).
    for (const m of command.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)) if (!/^(localhost|127\.0\.0\.1)$/.test(m[1])) report.domains.add(m[1].toLowerCase());
    const sendsTo = [...report.domains].sort();
    const network = caps.includes('network') || sendsTo.length > 0;
    const run = scripts.length ? `runs ${scripts.map((s) => path.basename(s)).join(', ')}` : `runs \`${command.length > 60 ? command.slice(0, 59) + '…' : command}\``;
    const dest = sendsTo.length ? `${sensitive ? 'sends data to' : 'contacts'} ${sendsTo.join(', ')}` : network ? 'makes network requests (destination set at runtime)' : '';
    const explanation: HookExplanation = {
      trigger,
      receives: receives[0].toUpperCase() + receives.slice(1),
      scripts,
      sendsTo,
      capabilities: caps.sort(),
      summary: `${trigger}, ${run}${dest ? `, which ${dest}` : ''}.${receives.startsWith('nothing') ? '' : ` It is given ${receives}.`}`,
    };
    a.hook.explanation = explanation;
    if (network && sensitive && (readsStdin || event === 'UserPromptSubmit' || event === 'beforeSubmitPrompt' || scripts.length > 0 || /@-/.test(command))) {
      egressHooks.add(a);
      f.add('HOOK-DATA-EGRESS', 'high', {
        asset: a,
        location: a.occurrences[0]?.source,
        title: `${event} hook sends ${receives.startsWith('the full text of your prompt') ? 'your prompts' : 'session data'} to ${sendsTo[0] ?? 'the network'}`,
        evidence: command,
        detail: explanation.summary,
      });
    }
  }
}

/** statusLine, apiKeyHelper and similar settings run commands automatically too. */
export function addAutoCommands(col: Collector): void {
  for (const doc of col.settings) {
    if (doc.client !== 'claude-code') continue;
    const add = (event: string, command: string, jsonPath: string[]) =>
      col.add({
        kind: 'hook',
        name: event,
        key: `${doc.file}|${event}|${command}`,
        hook: { event, command },
        path: doc.file,
        occurrence: { client: doc.client, scope: doc.scope, source: doc.file, name: event, project: doc.project, jsonPath },
      });
    const sl = doc.data.statusLine;
    if (isObject(sl) && typeof sl.command === 'string') add('statusLine', sl.command, ['statusLine']);
    for (const k of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper']) {
      const v = doc.data[k];
      if (typeof v === 'string' && v.trim()) add(k, v, [k]);
    }
  }
}

/* ---------------- Telemetry ---------------- */

const truthy = (v?: string) => !!v && /^(1|true|yes|on)$/i.test(v.trim());
const isLocal = (u: string) => /^(https?:\/\/)?(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:|\/|$)/i.test(u);
const hostOf = (u: string) => {
  try {
    return new URL(/^[a-z]+:\/\//i.test(u) ? u : `http://${u}`).host;
  } catch {
    return u;
  }
};

interface TelemetryInput {
  client: ClientId;
  clientName: string;
  source: string;
  scope: 'user' | 'project' | 'managed' | 'local';
  project?: string;
  details: TelemetryDetails;
}

function addTelemetry(col: Collector, f: Findings, t: TelemetryInput) {
  const d = t.details;
  const target = d.endpoint ? hostOf(d.endpoint) : 'a local file or console';
  const id = col.add({
    kind: 'telemetry',
    name: `${t.clientName} → ${target}`,
    key: `telemetry:${t.client}:${t.source}:${d.endpoint ?? ''}`,
    telemetry: d,
    path: t.source,
    occurrence: { client: t.client, scope: t.scope, source: t.source, name: `${t.clientName} telemetry`, project: t.project, note: d.managed ? 'Set by your organization\'s managed policy.' : undefined },
  });
  const a = col.assets.get(id)!;
  if (!d.endpoint) return;
  const remote = !isLocal(d.endpoint);
  const what = [d.logsPrompts && 'your prompts', d.logsToolDetails && 'tool parameters (file paths, commands)'].filter(Boolean).join(' and ');
  if (what) {
    f.add('TELEMETRY-PROMPTS', remote ? (d.managed ? 'medium' : 'high') : 'low', {
      asset: a,
      location: t.source,
      title: `${t.clientName} exports ${what} to ${target}`,
      evidence: `endpoint ${d.endpoint}`,
      detail: d.managed ? 'This is set by an admin-managed policy, so it is likely your employer\'s collector.' : undefined,
    });
  } else if (remote) {
    f.add('TELEMETRY-EXPORT', d.managed ? 'info' : 'low', { asset: a, location: t.source, title: `${t.clientName} sends usage telemetry to ${target}`, evidence: `endpoint ${d.endpoint}` });
  }
  if (remote && /^http:\/\//i.test(d.endpoint)) f.add('TELEMETRY-INSECURE', 'medium', { asset: a, location: t.source, evidence: d.endpoint });
}

function claudeTelemetry(env: Record<string, string>): TelemetryDetails | undefined {
  if (!truthy(env.CLAUDE_CODE_ENABLE_TELEMETRY)) return undefined;
  const exporters = [env.OTEL_METRICS_EXPORTER, env.OTEL_LOGS_EXPORTER].filter(Boolean).join(',');
  const endpoint = env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT || env.OTEL_EXPORTER_OTLP_ENDPOINT || env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT;
  if (!/otlp/.test(exporters) && !endpoint) return undefined;
  return {
    endpoint: /otlp/.test(exporters) || endpoint ? endpoint || 'http://localhost:4317' : undefined,
    protocol: env.OTEL_EXPORTER_OTLP_PROTOCOL,
    logsPrompts: truthy(env.OTEL_LOG_USER_PROMPTS) && /otlp/.test(env.OTEL_LOGS_EXPORTER ?? ''),
    logsToolDetails: truthy(env.OTEL_LOG_TOOL_DETAILS) && /otlp/.test(env.OTEL_LOGS_EXPORTER ?? ''),
    headersSet: !!env.OTEL_EXPORTER_OTLP_HEADERS,
    signals: [env.OTEL_METRICS_EXPORTER && 'metrics', env.OTEL_LOGS_EXPORTER && 'events'].filter((x): x is string => !!x),
  };
}

export async function scanTelemetry(col: Collector, f: Findings, shell?: ShellExport[]): Promise<void> {
  const exportsList = shell ?? (await readShellExports(col.ctx.home));
  const shellEnv: Record<string, string> = {};
  let shellFile = '';
  for (const e of exportsList) {
    if (/^(CLAUDE_CODE_ENABLE_TELEMETRY|OTEL_)/.test(e.name)) {
      shellEnv[e.name] = e.value;
      shellFile ||= e.file;
    }
  }
  // Claude Code: settings.json "env" (managed > user > project), falling back to shell exports.
  const docs = col.settings.filter((d) => d.client === 'claude-code');
  const seen = new Set<string>();
  for (const doc of docs) {
    const env = isObject(doc.data.env) ? (Object.fromEntries(Object.entries(doc.data.env).filter(([, v]) => typeof v === 'string')) as Record<string, string>) : {};
    const t = claudeTelemetry({ ...shellEnv, ...env });
    if (!t || !Object.keys(env).some((k) => /^(CLAUDE_CODE_ENABLE_TELEMETRY|OTEL_)/.test(k))) continue;
    t.managed = doc.scope === 'managed';
    if (typeof doc.data.otelHeadersHelper === 'string') t.headersSet = true;
    seen.add(t.endpoint ?? '');
    addTelemetry(col, f, { client: 'claude-code', clientName: 'Claude Code', source: doc.file, scope: doc.scope, project: doc.project, details: t });
  }
  const fromShell = claudeTelemetry(shellEnv);
  if (fromShell && !seen.has(fromShell.endpoint ?? '')) {
    addTelemetry(col, f, { client: 'shell', clientName: 'Claude Code (shell profile)', source: shellFile, scope: 'user', details: fromShell });
    col.client('shell', 'Shell profiles & .env files', shellFile);
  }

  // Gemini CLI: settings.json "telemetry" (logPrompts defaults to true).
  for (const file of [path.join(col.ctx.home, '.gemini', 'settings.json')]) {
    let data: unknown;
    try {
      data = await readStructured(file);
    } catch {
      continue;
    }
    const tel = isObject(data) && isObject(data.telemetry) ? data.telemetry : undefined;
    if (!tel || tel.enabled !== true) continue;
    const endpoint = asString(tel.otlpEndpoint) ?? (tel.target === 'gcp' ? 'Google Cloud (your project)' : undefined);
    addTelemetry(col, f, {
      client: 'gemini-cli',
      clientName: 'Gemini CLI',
      source: file,
      scope: 'user',
      details: { endpoint: endpoint && endpoint.includes(' ') ? undefined : endpoint, protocol: asString(tel.otlpProtocol), logsPrompts: tel.logPrompts !== false, logsToolDetails: true, headersSet: false, signals: ['metrics', 'events', 'traces'] },
    });
  }

  // Codex: config.toml [otel] exporter = { otlp-http = { endpoint = … } }, log_user_prompt.
  const codexFile = path.join(col.ctx.home, '.codex', 'config.toml');
  let codex: unknown;
  try {
    codex = await readStructured(codexFile);
  } catch {
    codex = undefined;
  }
  const otel = isObject(codex) && isObject(codex.otel) ? codex.otel : undefined;
  const exp = otel && isObject(otel.exporter) ? otel.exporter : undefined;
  const cfg = exp ? (Object.values(exp).find(isObject) as Record<string, unknown> | undefined) : undefined;
  if (cfg && typeof cfg.endpoint === 'string') {
    addTelemetry(col, f, {
      client: 'codex',
      clientName: 'Codex',
      source: codexFile,
      scope: 'user',
      details: { endpoint: cfg.endpoint, protocol: asString(cfg.protocol), logsPrompts: otel!.log_user_prompt === true, logsToolDetails: false, headersSet: isObject(cfg.headers), signals: ['events'] },
    });
  }
  // Codex `notify` runs a program after every turn with the conversation's last messages.
  const notify = isObject(codex) && Array.isArray(codex.notify) ? codex.notify.filter((x): x is string => typeof x === 'string') : [];
  if (notify.length) {
    col.add({
      kind: 'hook',
      name: 'notify',
      key: `${codexFile}|notify`,
      hook: { event: 'notify', command: notify.join(' ') },
      path: codexFile,
      occurrence: { client: 'codex', scope: 'user', source: codexFile, name: 'notify' },
    });
  }
}
