import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { createReadStream, promises as fs } from 'node:fs';

/**
 * One reader for the session logs of several coding agents, producing the
 * same normalized "tool call" records for all of them:
 *
 *   Claude Code  <claude dir>/projects/<project>/<session>.jsonl
 *   Codex CLI    ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
 *   Claude Desktop  <app support>/Claude/local-agent-mode-sessions/<user>/<org>/[agent/]local_<id>/audit.jsonl (same records as Claude Code)
 *   Copilot CLI  ~/.copilot/session-state/<session>/events.jsonl
 *   Cline, Roo Code, Kilo Code  <editor>/User/globalStorage/<extension>/tasks/<task>/api_conversation_history.json
 *   Gemini CLI   ~/.gemini/tmp/<project hash>/chats/ (.jsonl journals at any depth, legacy session-*.json); also ~/.cache/.gemini/tmp on macOS
 *
 * Logs are read locally and streamed; nothing is sent anywhere. Result text
 * is only kept for MCP calls (for the injection audit) and never stored.
 */

export type AgentId = 'claude-code' | 'codex' | 'gemini-cli' | 'claude-desktop' | 'copilot-cli' | 'cline';
export type CallKind = 'prompt' | 'response' | 'mcp' | 'command' | 'write' | 'edit' | 'read' | 'fetch' | 'search' | 'skill' | 'agent' | 'other';

export interface Call {
  agent: AgentId;
  session: string;
  file: string;
  at?: string;
  project?: string;
  kind: CallKind;
  /** Tool name as the agent calls it. */
  name: string;
  /** MCP only: server as written in the agent's config (not normalized) and tool name. */
  server?: string;
  tool?: string;
  input: Record<string, unknown>;
  /** MCP only: result text, for the audit. */
  result?: string;
  /** Prompts and responses: what the user typed / what the agent answered (clipped; redacted by the caller before display). */
  text?: string;
  /** Commands only: what the command printed (head and tail, unredacted; the caller redacts it). */
  output?: string;
  /** Commands only: the tool reported an error. */
  failed?: boolean;
  /** Set when a subagent made this call: the subagent's id. */
  sub?: string;
  /** How tool calls were approved: Claude Code's permission mode (auto, bypassPermissions, …) or Codex's approval policy. */
  mode?: string;
  /** How the agent was started (cli, claude-vscode, sdk-cli: headless). */
  entry?: string;
}

export interface LogOptions {
  days?: number;
  maxFiles?: number;
  /** Only these agents. */
  agents?: AgentId[];
}

const MAX_FILE = 256 * 1024 * 1024;

async function listFiles(root: string, match: (name: string, full: string) => boolean, depth: number, days: number, max: number): Promise<string[]> {
  const cutoff = Date.now() - days * 86_400_000;
  const out: { file: string; mtime: number }[] = [];
  const visit = async (dir: string, d: number) => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory() && d < depth) await visit(p, d + 1);
      else if (e.isFile() && match(e.name, p)) {
        try {
          const st = await fs.stat(p);
          if (st.mtimeMs >= cutoff && st.size <= MAX_FILE) out.push({ file: p, mtime: st.mtimeMs });
        } catch {
          /* vanished */
        }
      }
    }
  };
  await visit(root, 0);
  return out.sort((a, b) => b.mtime - a.mtime).slice(0, max).map((x) => x.file);
}

export function resultText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((c) => (c && typeof c === 'object' && typeof (c as { text?: unknown }).text === 'string' ? (c as { text: string }).text : typeof c === 'string' ? c : '')).join('\n');
  if (content && typeof content === 'object') {
    const o = content as Record<string, unknown>;
    if (Array.isArray(o.content)) return resultText(o.content);
    if (typeof o.output === 'string') return o.output;
  }
  return '';
}

const MAX_PROMPT = 4000;
const MAX_RESPONSE = 6000;
const MAX_OUTPUT = 1200;

/** Keep the start and the end of long output: the command's own echo and its final lines (errors, totals). */
function trimOutput(text: string): string {
  const t = text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').trim();
  return t.length <= MAX_OUTPUT ? t : `${t.slice(0, 850)}\n… ${t.length - 1150} characters omitted …\n${t.slice(-300)}`;
}

/** A text block: Claude `{type:'text',text}`, or a bare Gemini part `{text}`. */
function textPart(b: unknown): string {
  if (!b || typeof b !== 'object') return typeof b === 'string' ? b : '';
  const o = b as { type?: unknown; text?: unknown };
  return (o.type === undefined || o.type === 'text') && typeof o.text === 'string' ? o.text : '';
}

function textBlocks(content: unknown): string {
  return Array.isArray(content)
    ? content.map(textPart).filter(Boolean).join('\n\n').trim()
    : typeof content === 'string' ? content.trim() : '';
}

/** What the user typed, from a message's content (a string, or blocks with text). Undefined for tool output and system-injected text. */
function userText(content: unknown): string | undefined {
  const raw = typeof content === 'string' ? content : Array.isArray(content) ? content.map(textPart).join('\n') : '';
  let t = raw.trim();
  if (!t || /^(<local-command|<system-reminder|Caveat:|\[Request interrupted)/.test(t)) return undefined;
  const cmd = t.match(/^<command-name>\s*(\S+)\s*<\/command-name>(?:[\s\S]*?<command-args>([\s\S]*?)<\/command-args>)?/);
  if (cmd) t = `${cmd[1]}${cmd[2]?.trim() ? ` ${cmd[2].trim()}` : ''}`;
  return t.slice(0, MAX_PROMPT);
}

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const parseArgs = (v: unknown): Record<string, unknown> => {
  if (typeof v === 'string') {
    try {
      return obj(JSON.parse(v));
    } catch {
      return { raw: v };
    }
  }
  return obj(v);
};

/* ---------------- Claude Code ---------------- */

const CLAUDE_KIND: Record<string, CallKind> = {
  Bash: 'command', BashOutput: 'other', Write: 'write', Edit: 'edit', MultiEdit: 'edit', NotebookEdit: 'edit', Read: 'read',
  WebFetch: 'fetch', WebSearch: 'search', Skill: 'skill', Task: 'agent', Agent: 'agent', Glob: 'read', Grep: 'read',
};

async function* readClaude(file: string, agent: AgentId = 'claude-code'): AsyncGenerator<Call> {
  // Subagent transcripts live next to the session they belong to: <session>/subagents/agent-<id>.jsonl.
  const isSub = /[\\/]subagents[\\/]/.test(file);
  // Claude Desktop keeps each session in its own folder as audit.jsonl; a `local_ditto_` folder is a delegated background agent.
  const desktop = agent === 'claude-desktop';
  const dispatch = desktop && path.basename(path.dirname(file)).startsWith('local_ditto_');
  const session = isSub ? path.basename(path.dirname(path.dirname(file))) : desktop ? path.basename(path.dirname(file)) : path.basename(file, '.jsonl');
  const subOfFile = isSub ? path.basename(file, '.jsonl').replace(/^agent-/, '') : undefined;
  let mode: string | undefined;
  let entry: string | undefined = desktop ? (dispatch ? 'claude-desktop-dispatch' : 'claude-desktop') : undefined;
  const pending = new Map<string, Call>();
  const rl = readline.createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    const hasUse = line.includes('"tool_use"');
    const hasResult = line.includes('"tool_result"');
    if (!hasUse && !hasResult) {
      if (/"role"\s*:\s*"assistant"/.test(line)) {
        try {
          const d = JSON.parse(line) as { type?: string; isSidechain?: boolean; timestamp?: string; cwd?: string; message?: { content?: unknown } };
          const text = d.type === 'assistant' && !d.isSidechain ? textBlocks(d.message?.content) : '';
          if (text) yield { agent, session, file, at: d.timestamp, project: d.cwd, kind: 'response', name: 'response', input: {}, text: text.slice(0, MAX_RESPONSE) };
        } catch {
          /* partial line */
        }
        continue;
      }
      if (!/"role"\s*:\s*"user"/.test(line)) continue;
      try {
        const d = JSON.parse(line) as { type?: string; isMeta?: boolean; isSidechain?: boolean; timestamp?: string; cwd?: string; permissionMode?: string; entrypoint?: string; message?: { content?: unknown } };
        if (typeof d.permissionMode === 'string') mode = d.permissionMode;
        if (typeof d.entrypoint === 'string' && !desktop) entry = d.entrypoint;
        const text = d.type === 'user' && !d.isMeta && !d.isSidechain ? userText(d.message?.content) : undefined;
        if (text) yield { agent, session, file, at: d.timestamp, project: d.cwd, kind: 'prompt', name: 'prompt', input: {}, text, mode, entry };
      } catch {
        /* partial line */
      }
      continue;
    }
    if (!hasUse) {
      // Only MCP results are kept; skip parsing the (often huge) other result lines.
      const ids = [...line.matchAll(/"tool_use_id"\s*:\s*"([^"]+)"/g)].map((m) => m[1]);
      if (!ids.some((id) => ['mcp', 'command'].includes(pending.get(id)?.kind ?? ''))) {
        for (const id of ids) {
          const c = pending.get(id);
          if (c) {
            pending.delete(id);
            yield c;
          }
        }
        continue;
      }
    }
    let d: { timestamp?: string; cwd?: string; isSidechain?: boolean; agentId?: string; permissionMode?: string; entrypoint?: string; message?: { content?: unknown } };
    try {
      d = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof d.permissionMode === 'string') mode = d.permissionMode;
    if (typeof d.entrypoint === 'string' && !desktop) entry = d.entrypoint;
    const content = d.message?.content;
    if (!Array.isArray(content)) continue;
    for (const b of content as Record<string, unknown>[]) {
      if (b?.type === 'text' && typeof b.text === 'string' && b.text.trim() && (d as { type?: string; isSidechain?: boolean }).type === 'assistant' && !(d as { isSidechain?: boolean }).isSidechain) {
        yield { agent, session, file, at: d.timestamp, project: d.cwd, kind: 'response', name: 'response', input: {}, text: b.text.trim().slice(0, MAX_RESPONSE), mode, entry };
      } else if (b?.type === 'tool_use' && typeof b.name === 'string') {
        const name = b.name;
        const m = name.match(/^mcp__(.+?)__(.+)$/);
        const c: Call = {
          agent,
          session,
          file,
          at: d.timestamp,
          project: d.cwd,
          kind: m ? 'mcp' : CLAUDE_KIND[name] ?? 'other',
          name,
          server: m?.[1],
          tool: m?.[2],
          input: obj(b.input),
          sub: subOfFile ?? (d.isSidechain ? d.agentId ?? 'subagent' : undefined),
          mode,
          entry,
        };
        if (typeof b.id === 'string') pending.set(b.id, c);
        else yield c;
      } else if (b?.type === 'tool_result' && typeof b.tool_use_id === 'string') {
        const c = pending.get(b.tool_use_id);
        if (!c) continue;
        pending.delete(b.tool_use_id);
        if (c.kind === 'mcp') c.result = resultText(b.content);
        else if (c.kind === 'command') {
          c.output = trimOutput(resultText(b.content));
          if (b.is_error === true) c.failed = true;
        }
        yield c;
      }
    }
  }
  for (const c of pending.values()) yield c;
}

/* ---------------- Codex CLI ---------------- */

const CODEX_KIND: Record<string, CallKind> = { shell: 'command', exec_command: 'command', local_shell: 'command', container_exec: 'command', apply_patch: 'edit', web_search: 'search', view_image: 'read', read_file: 'read' };

async function* readCodex(file: string): AsyncGenerator<Call> {
  let session = path.basename(file, '.jsonl');
  let cwd: string | undefined;
  let approval: string | undefined;
  const pending = new Map<string, Call>();
  const rl = readline.createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let d: Record<string, unknown>;
    try {
      d = JSON.parse(line);
    } catch {
      continue;
    }
    const at = typeof d.timestamp === 'string' ? d.timestamp : undefined;
    const p = obj(d.payload ?? d);
    if (d.type === 'session_meta' || p.type === 'session_meta') {
      if (typeof p.id === 'string') session = p.id;
      if (typeof p.cwd === 'string') cwd = p.cwd;
      continue;
    }
    if (p.type === 'turn_context') {
      if (typeof p.cwd === 'string') cwd = p.cwd;
      if (typeof p.approval_policy === 'string') approval = p.approval_policy;
    }
    if (p.type === 'agent_message' && typeof p.message === 'string' && p.message.trim()) {
      yield { agent: 'codex', session, file, at, project: cwd, kind: 'response', name: 'response', input: {}, text: p.message.trim().slice(0, MAX_RESPONSE) };
      continue;
    }
    if (p.type === 'user_message' && typeof p.message === 'string' && p.message.trim()) {
      yield { agent: 'codex', session, file, at, project: cwd, kind: 'prompt', name: 'prompt', input: {}, text: p.message.trim().slice(0, MAX_PROMPT), mode: approval };
      continue;
    }
    if (p.type === 'function_call' || p.type === 'custom_tool_call' || p.type === 'local_shell_call') {
      const name = typeof p.name === 'string' ? p.name : p.type === 'local_shell_call' ? 'local_shell' : 'tool';
      const input = p.type === 'local_shell_call' ? obj(p.action) : parseArgs(p.arguments ?? p.input);
      const m = name.match(/^(?:mcp__)?([\w-]+?)__([\w-]+)$/);
      const c: Call = { agent: 'codex', session, file, at, project: cwd, kind: CODEX_KIND[name] ?? (m ? 'mcp' : 'other'), name, server: m?.[1], tool: m?.[2], input, mode: approval };
      const id = typeof p.call_id === 'string' ? p.call_id : undefined;
      if (id) pending.set(id, c);
      else yield c;
    } else if ((p.type === 'function_call_output' || p.type === 'custom_tool_call_output') && typeof p.call_id === 'string') {
      const c = pending.get(p.call_id);
      if (!c) continue;
      pending.delete(p.call_id);
      if (c.kind === 'mcp') c.result = resultText(p.output);
      else if (c.kind === 'command') {
        const raw = resultText(p.output);
        let out = raw;
        try {
          const j = JSON.parse(raw) as { output?: unknown; metadata?: { exit_code?: unknown } };
          if (typeof j.output === 'string') out = j.output;
          if (typeof j.metadata?.exit_code === 'number' && j.metadata.exit_code !== 0) c.failed = true;
        } catch {
          /* plain text */
        }
        c.output = trimOutput(out);
      }
      yield c;
    } else if (p.type === 'mcp_tool_call_begin' || p.type === 'mcp_tool_call_end') {
      const inv = obj(p.invocation);
      const id = typeof p.call_id === 'string' ? p.call_id : undefined;
      if (p.type === 'mcp_tool_call_begin' && typeof inv.server === 'string' && typeof inv.tool === 'string') {
        const c: Call = { agent: 'codex', session, file, at, project: cwd, kind: 'mcp', name: `${inv.server}__${inv.tool}`, server: inv.server, tool: inv.tool, input: parseArgs(inv.arguments) };
        if (id) pending.set(`mcp:${id}`, c);
        else yield c;
      } else if (p.type === 'mcp_tool_call_end' && id) {
        const c = pending.get(`mcp:${id}`);
        if (!c) continue;
        pending.delete(`mcp:${id}`);
        c.result = resultText(obj(p.result).Ok ?? p.result);
        yield c;
      }
    }
  }
  for (const c of pending.values()) yield c;
}

/* ---------------- Gemini CLI ---------------- */

const GEMINI_KIND: Record<string, CallKind> = {
  run_shell_command: 'command', write_file: 'write', replace: 'edit', read_file: 'read', read_many_files: 'read', list_directory: 'read',
  glob: 'read', search_file_content: 'read', web_fetch: 'fetch', google_web_search: 'search', save_memory: 'other',
};

/** A Gemini CLI conversation: the legacy `session-*.json` snapshot or the newer append-only `.jsonl` journal. */
async function loadGemini(file: string): Promise<{ sessionId?: string; kind?: string; messages: Record<string, unknown>[] } | undefined> {
  try {
    const st = await fs.stat(file);
    if (st.size > 64 * 1024 * 1024) return undefined;
    const text = await fs.readFile(file, 'utf8');
    if (!file.endsWith('.jsonl')) {
      const data = obj(JSON.parse(text));
      return { sessionId: typeof data.sessionId === 'string' ? data.sessionId : undefined, kind: typeof data.kind === 'string' ? data.kind : undefined, messages: (Array.isArray(data.messages) ? data.messages : []).map(obj) };
    }
    // Journal: a metadata record, messages (rewritten as tool calls finish, so later copies win), `$set`
    // updates that may carry a checkpoint of messages, and `$rewindTo` markers. Abandoned branches stay:
    // what the agent did matters even if the conversation was rewound.
    const meta: Record<string, unknown> = {};
    const byId = new Map<string, Record<string, unknown>>();
    const loose: Record<string, unknown>[] = [];
    const add = (m: Record<string, unknown>) => {
      if (typeof m.id === 'string') byId.set(m.id, { ...(byId.get(m.id) ?? {}), ...m });
      else loose.push(m);
    };
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let rec: Record<string, unknown>;
      try {
        rec = obj(JSON.parse(line));
      } catch {
        continue;
      }
      if ('$rewindTo' in rec) continue;
      if (typeof rec.id === 'string') {
        add(rec);
        continue;
      }
      const update = obj(rec.$set ?? rec);
      for (const [k, v] of Object.entries(update)) if (k !== 'messages') meta[k] = v;
      for (const m of Array.isArray(update.messages) ? update.messages : []) add(obj(m));
    }
    return { sessionId: typeof meta.sessionId === 'string' ? meta.sessionId : undefined, kind: typeof meta.kind === 'string' ? meta.kind : undefined, messages: [...loose, ...byId.values()] };
  } catch {
    return undefined;
  }
}

/** Project folder for a Gemini chat file: `<tmp>/<hash>/.project_root`, or the `projects.json` registry beside `tmp`. */
const geminiProjects = new Map<string, string | undefined>();
async function geminiProject(file: string): Promise<string | undefined> {
  const m = file.match(/^(.*[\\/]tmp)[\\/]([^\\/]+)[\\/]chats[\\/]/);
  if (!m) return undefined;
  const [, root, hash] = m;
  const key = `${root}|${hash}`;
  if (geminiProjects.has(key)) return geminiProjects.get(key);
  let found: string | undefined;
  try {
    found = (await fs.readFile(path.join(root, hash, '.project_root'), 'utf8')).trim() || undefined;
  } catch {
    /* no marker */
  }
  if (!found) {
    try {
      const reg = obj(JSON.parse(await fs.readFile(path.join(path.dirname(root), 'projects.json'), 'utf8')));
      const projects = obj(reg.projects ?? reg);
      found = Object.entries(projects).find(([, h]) => h === hash)?.[0];
    } catch {
      /* no registry */
    }
  }
  geminiProjects.set(key, found);
  return found;
}

async function* readGemini(file: string): AsyncGenerator<Call> {
  const data = await loadGemini(file);
  if (!data) return;
  const own = data.sessionId ?? path.basename(file).replace(/\.jsonl?$/, '');
  // A subagent's journal sits in a folder named for the session that started it.
  const parent = data.kind === 'subagent' && path.basename(path.dirname(file)) !== 'chats' ? path.basename(path.dirname(file)) : undefined;
  const session = parent ?? own;
  const sub = parent ? own : undefined;
  const project = await geminiProject(file);
  for (const msg of data.messages) {
    const when = typeof msg.timestamp === 'string' ? msg.timestamp : undefined;
    if (msg.type === 'user' && !sub) {
      const text = userText(msg.content);
      if (text) yield { agent: 'gemini-cli', session, file, at: when, project, kind: 'prompt', name: 'prompt', input: {}, text };
    }
    if (msg.type === 'gemini' && !sub) {
      const text = textBlocks(msg.content);
      if (text) yield { agent: 'gemini-cli', session, file, at: when, project, kind: 'response', name: 'response', input: {}, text: text.slice(0, MAX_RESPONSE) };
    }
    for (const t of (Array.isArray(msg.toolCalls) ? msg.toolCalls : []).map(obj)) {
      const name = typeof t.name === 'string' ? t.name : 'tool';
      // MCP tools are named `<server>__<tool>`, and `mcp_<server>__<tool>` in current releases.
      const m = name.match(/^(?:mcp_)?([\w-]+?)__([\w-]+)$/);
      const builtin = GEMINI_KIND[name];
      const c: Call = {
        agent: 'gemini-cli',
        session,
        file,
        at: typeof t.timestamp === 'string' ? t.timestamp : when,
        project,
        kind: builtin ?? 'mcp',
        name,
        server: builtin ? undefined : m?.[1],
        tool: builtin ? undefined : m?.[2] ?? name,
        input: obj(t.args),
        sub,
      };
      const res = Array.isArray(t.result) ? t.result.map((r) => obj(obj(obj(r).functionResponse).response).output ?? '').join('\n') : resultText(t.result);
      if (builtin === 'command') {
        if (typeof res === 'string' && res) c.output = trimOutput(res);
        if (t.status === 'error') c.failed = true;
      }
      if (!builtin) c.result = typeof res === 'string' ? res : '';
      yield c;
    }
  }
}

/* ---------------- GitHub Copilot CLI ---------------- */

const COPILOT_KIND: Record<string, CallKind> = {
  bash: 'command', shell: 'command', powershell: 'command', run_command: 'command', read_bash: 'other', write_bash: 'other',
  view: 'read', read_file: 'read', read: 'read', grep: 'read', glob: 'read', search: 'read', list_dir: 'read', ls: 'read',
  create: 'write', write_file: 'write', edit: 'edit', str_replace: 'edit', str_replace_editor: 'edit', apply_patch: 'edit',
  web_fetch: 'fetch', fetch: 'fetch', web_search: 'search', task: 'agent', skill: 'skill',
};

/** Session state in `<session>/events.jsonl`: user and assistant messages, tool requests, and tool start/complete events. */
async function* readCopilot(file: string): AsyncGenerator<Call> {
  let session = path.basename(path.dirname(file));
  let cwd: string | undefined;
  const pending = new Map<string, Call>();
  const make = (name: string, args: Record<string, unknown>, at?: string): Call => {
    // Built-in tools use underscores (`str_replace_editor`); MCP tools are `<server>-<tool>`.
    const mcp = !COPILOT_KIND[name] && /^[A-Za-z0-9_.]+-.+/.test(name) ? name.match(/^([A-Za-z0-9_.]+?)-(.+)$/) : null;
    return { agent: 'copilot-cli', session, file, at, project: cwd, kind: COPILOT_KIND[name] ?? (mcp ? 'mcp' : 'other'), name, server: mcp?.[1], tool: mcp?.[2], input: args };
  };
  const rl = readline.createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let rec: Record<string, unknown>;
    try {
      rec = obj(JSON.parse(line));
    } catch {
      continue;
    }
    const data = obj(rec.data);
    const at = typeof rec.timestamp === 'string' ? rec.timestamp : undefined;
    switch (rec.type) {
      case 'session.start':
      case 'session.resume':
        if (typeof data.sessionId === 'string') session = data.sessionId;
        if (typeof obj(data.context).cwd === 'string') cwd = obj(data.context).cwd as string;
        break;
      case 'user.message': {
        const text = typeof data.content === 'string' ? data.content.trim() : '';
        if (text) yield { agent: 'copilot-cli', session, file, at, project: cwd, kind: 'prompt', name: 'prompt', input: {}, text: text.slice(0, MAX_PROMPT) };
        break;
      }
      case 'assistant.message': {
        const text = typeof data.content === 'string' ? data.content.trim() : '';
        if (text) yield { agent: 'copilot-cli', session, file, at, project: cwd, kind: 'response', name: 'response', input: {}, text: text.slice(0, MAX_RESPONSE) };
        for (const r of (Array.isArray(data.toolRequests) ? data.toolRequests : []).map(obj)) {
          const id = typeof r.toolCallId === 'string' ? r.toolCallId : undefined;
          const c = make(typeof r.name === 'string' ? r.name : 'tool', parseArgs(r.arguments), at);
          if (id) pending.set(id, c);
          else yield c;
        }
        break;
      }
      case 'tool.execution_start': {
        const id = typeof data.toolCallId === 'string' ? data.toolCallId : undefined;
        if (id && !pending.has(id)) pending.set(id, make(typeof data.toolName === 'string' ? data.toolName : 'tool', parseArgs(data.arguments), at));
        else if (id && data.arguments) pending.get(id)!.input = parseArgs(data.arguments);
        break;
      }
      case 'tool.execution_complete': {
        const id = typeof data.toolCallId === 'string' ? data.toolCallId : undefined;
        const c = id ? pending.get(id) : undefined;
        if (!c) break;
        if (id) pending.delete(id);
        const out = resultText(obj(data.result).content ?? data.result);
        if (c.kind === 'mcp') c.result = out;
        else if (c.kind === 'command') {
          c.output = trimOutput(out);
          if (data.success === false) c.failed = true;
        }
        yield c;
        break;
      }
    }
  }
  for (const c of pending.values()) yield c;
}

/* ---------------- Cline, Roo Code, Kilo Code ---------------- */

const CLINE_TOOL: Record<string, CallKind> = {
  execute_command: 'command', read_file: 'read', write_to_file: 'write', replace_in_file: 'edit', apply_diff: 'edit', insert_content: 'edit',
  search_files: 'read', list_files: 'read', list_code_definition_names: 'read', browser_action: 'fetch', new_task: 'agent', use_mcp_tool: 'mcp', access_mcp_resource: 'mcp',
};

const xmlField = (block: string, field: string) => block.match(new RegExp(`<${field}>([\\s\\S]*?)</${field}>`))?.[1]?.trim();

/**
 * A task is `api_conversation_history.json`: the model conversation, with tools called as XML blocks in the
 * assistant's text. The log has no per-message times, so steps take the task's start time (the task folder is
 * named for it) and keep their order.
 */
async function* readCline(file: string): AsyncGenerator<Call> {
  let messages: Record<string, unknown>[];
  try {
    const st = await fs.stat(file);
    if (st.size > 64 * 1024 * 1024) return;
    messages = (JSON.parse(await fs.readFile(file, 'utf8')) as unknown[]).map(obj);
  } catch {
    return;
  }
  const task = path.basename(path.dirname(file));
  const started = /^\d{12,14}$/.test(task) ? new Date(Number(task)).toISOString() : (await fs.stat(file).catch(() => undefined))?.mtime.toISOString();
  const text = (m: Record<string, unknown>) => (typeof m.content === 'string' ? m.content : Array.isArray(m.content) ? m.content.map(textPart).join('\n') : '');
  // Collected first: a command's output arrives in the message after it.
  const out: Call[] = [];
  let last: Call | undefined;
  for (const m of messages) {
    const t = text(m);
    if (m.role === 'user') {
      const task_ = t.match(/^<task>\s*([\s\S]*?)\s*<\/task>/);
      const feedback = t.match(/^\[([a-z_]+)[^\]]*\] Result:\s*([\s\S]*)$/);
      if (task_) out.push({ agent: 'cline', session: task, file, at: started, kind: 'prompt', name: 'prompt', input: {}, text: task_[1].slice(0, MAX_PROMPT) });
      else if (feedback && last?.kind === 'command' && feedback[1] === 'execute_command') {
        last.output = trimOutput(feedback[2].replace(/^Command executed\.?\s*(Output:)?\s*/i, ''));
      } else if (!feedback && t.trim() && !/^<(environment_details|feedback)/.test(t.trim()) && messages.indexOf(m) > 0) {
        const fb = t.match(/<feedback>\s*([\s\S]*?)\s*<\/feedback>/)?.[1];
        const typed = fb ?? (t.startsWith('<') ? undefined : t.trim());
        if (typed) out.push({ agent: 'cline', session: task, file, at: started, kind: 'prompt', name: 'prompt', input: {}, text: typed.slice(0, MAX_PROMPT) });
      }
      continue;
    }
    if (m.role !== 'assistant') continue;
    // Narration is the text outside the tool block; attempt_completion's result is the final reply.
    const done = xmlField(t, 'result');
    const narration = t.replace(/<(\w+)>[\s\S]*?<\/\1>/g, (all, name: string) => (CLINE_TOOL[name] || name === 'attempt_completion' || name === 'ask_followup_question' ? '' : all)).trim();
    if (narration) out.push({ agent: 'cline', session: task, file, at: started, kind: 'response', name: 'response', input: {}, text: narration.slice(0, MAX_RESPONSE) });
    if (/<attempt_completion>/.test(t) && done) out.push({ agent: 'cline', session: task, file, at: started, kind: 'response', name: 'response', input: {}, text: done.slice(0, MAX_RESPONSE) });
    for (const name of Object.keys(CLINE_TOOL)) {
      for (const block of t.matchAll(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, 'g'))) {
        const body = block[1];
        const kind = CLINE_TOOL[name];
        const input: Record<string, unknown> = {};
        for (const f of ['command', 'path', 'regex', 'url', 'action', 'server_name', 'tool_name', 'uri']) {
          const v = xmlField(body, f);
          if (v !== undefined) input[f] = v;
        }
        const args = xmlField(body, 'arguments');
        if (args) {
          try {
            Object.assign(input, { arguments: JSON.parse(args) });
          } catch {
            input.arguments = args;
          }
        }
        if (input.path) input.file_path = input.path;
        const c: Call = { agent: 'cline', session: task, file, at: started, kind, name, input, server: kind === 'mcp' ? (input.server_name as string | undefined) : undefined, tool: kind === 'mcp' ? (input.tool_name as string | undefined) ?? (input.uri as string | undefined) : undefined };
        if (kind === 'fetch' && !input.url) c.kind = 'other';
        last = c;
        out.push(c);
      }
    }
  }
  for (const c of out) yield c;
}

/* ---------------- Entry point ---------------- */

export interface LogSource {
  agent: AgentId;
  files: string[];
}

export async function logSources(dirs: { claudeDir: string; home: string }, opts: LogOptions = {}): Promise<LogSource[]> {
  const days = opts.days ?? 90;
  const max = opts.maxFiles ?? 3000;
  const want = (a: AgentId) => !opts.agents || opts.agents.includes(a);
  const out: LogSource[] = [];
  if (want('claude-code')) out.push({ agent: 'claude-code', files: await listFiles(path.join(dirs.claudeDir, 'projects'), (n) => n.endsWith('.jsonl'), 3, days, max) });
  if (want('codex')) out.push({ agent: 'codex', files: await listFiles(path.join(dirs.home, '.codex', 'sessions'), (n) => n.endsWith('.jsonl'), 4, days, max) });
  if (want('claude-desktop')) {
    const roots = [path.join(dirs.home, 'Library', 'Application Support', 'Claude', 'local-agent-mode-sessions'), path.join(dirs.home, 'AppData', 'Roaming', 'Claude', 'local-agent-mode-sessions')];
    // <user>/<org>/local_<id>/audit.jsonl, and one level deeper for delegated agents (<user>/<org>/agent/local_ditto_<id>/audit.jsonl).
    out.push({ agent: 'claude-desktop', files: (await Promise.all(roots.map((r) => listFiles(r, (n) => n === 'audit.jsonl', 4, days, max)))).flat() });
  }
  if (want('copilot-cli')) {
    const root = path.join(process.env.COPILOT_HOME && path.resolve(dirs.home) === path.resolve(os.homedir()) ? process.env.COPILOT_HOME : path.join(dirs.home, '.copilot'), 'session-state');
    out.push({ agent: 'copilot-cli', files: await listFiles(root, (n) => n === 'events.jsonl', 2, days, max) });
  }
  if (want('cline')) {
    const editors = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];
    const exts = ['saoudrizwan.claude-dev', 'rooveterinaryinc.roo-cline', 'kilocode.kilo-code'];
    const bases = [path.join(dirs.home, 'Library', 'Application Support'), path.join(dirs.home, '.config'), path.join(dirs.home, 'AppData', 'Roaming')];
    const roots = bases.flatMap((b) => editors.flatMap((e) => exts.map((x) => path.join(b, e, 'User', 'globalStorage', x, 'tasks'))));
    out.push({ agent: 'cline', files: (await Promise.all(roots.map((r) => listFiles(r, (n) => n === 'api_conversation_history.json', 2, days, max)))).flat() });
  }
  if (want('gemini-cli')) {
    const homes = [process.env.GEMINI_CLI_HOME && path.resolve(dirs.home) === path.resolve(os.homedir()) ? process.env.GEMINI_CLI_HOME : dirs.home];
    const roots = homes.flatMap((h) => [path.join(h, '.gemini', 'tmp'), ...(process.platform === 'darwin' || dirs.home !== os.homedir() ? [path.join(h, '.cache', '.gemini', 'tmp')] : [])]);
    // Chat journals (`chats/**/*.jsonl`) and older `session-*.json` snapshots; a snapshot is dropped once its journal exists.
    const accept = (n: string, full: string) => (/[\\/]chats[\\/]/.test(full) && /\.jsonl?$/.test(n)) || n === 'checkpoint.json';
    const found = (await Promise.all(roots.map((r) => listFiles(r, accept, 3, days, max)))).flat();
    const journals = new Set(found.filter((f) => f.endsWith('.jsonl')).map((f) => f.slice(0, -1)));
    out.push({ agent: 'gemini-cli', files: found.filter((f) => !journals.has(f)) });
  }
  return out;
}

export async function* readCalls(src: LogSource, file: string): AsyncGenerator<Call> {
  if (src.agent === 'claude-code' || src.agent === 'claude-desktop') yield* readClaude(file, src.agent);
  else if (src.agent === 'copilot-cli') yield* readCopilot(file);
  else if (src.agent === 'cline') yield* readCline(file);
  else if (src.agent === 'codex') yield* readCodex(file);
  else yield* readGemini(file);
}
