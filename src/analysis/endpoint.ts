import { execFile } from 'node:child_process';
import type { Collector } from '../collector.js';
import type { Asset } from '../types.js';
import type { Findings } from '../checks/index.js';
import { redactText } from '../util/secrets.js';

/**
 * What is running on this computer right now: which AI model servers are listening for connections, and
 * which programs look like MCP servers. Read with the system's own `ps` and `lsof` (nothing is started,
 * nothing is sent anywhere). It finds what config files cannot: a model server you launched by hand or
 * in a container, or an MCP server some other program started.
 */
export interface EndpointSnapshot {
  processes: { pid: number; command: string }[];
  listeners: { pid: number; address: string; port: number }[];
}

export type EndpointReader = () => Promise<EndpointSnapshot | undefined>;

const run = (cmd: string, args: string[]): Promise<string | undefined> =>
  new Promise((resolve) => {
    execFile(cmd, args, { timeout: 5000, maxBuffer: 8 * 1024 * 1024, windowsHide: true }, (err, stdout) => resolve(err && !stdout ? undefined : stdout));
  });

export function parsePs(text: string): EndpointSnapshot['processes'] {
  return text.split('\n').flatMap((line) => {
    const m = line.match(/^\s*(\d+)\s+(.+)$/);
    return m ? [{ pid: Number(m[1]), command: m[2].trim() }] : [];
  });
}

/** `lsof -F pn` output: `p<pid>` then one `n<address>:<port>` per socket. */
export function parseLsof(text: string): EndpointSnapshot['listeners'] {
  const out: EndpointSnapshot['listeners'] = [];
  let pid = 0;
  for (const line of text.split('\n')) {
    if (line.startsWith('p')) pid = Number(line.slice(1));
    else if (line.startsWith('n')) {
      const m = line.slice(1).match(/^(.*):(\d+)$/);
      if (m) out.push({ pid, address: m[1], port: Number(m[2]) });
    }
  }
  return out;
}

/** The live reader. Not available on Windows, where the check is skipped and reported as not covered. */
export const liveEndpoint: EndpointReader = async () => {
  if (process.platform === 'win32') return undefined;
  const [ps, lsof] = await Promise.all([run('ps', ['-axo', 'pid=,command=']), run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-Fpn'])]);
  if (ps === undefined) return undefined;
  return { processes: parsePs(ps), listeners: lsof ? parseLsof(lsof) : [] };
};

interface Service {
  id: 'ollama' | 'llama-cpp' | 'vllm' | 'localai' | 'open-webui' | 'lm-studio' | 'gpt4all' | 'comfyui' | 'koboldcpp';
  name: string;
  re: RegExp;
}

const SERVICES: Service[] = [
  { id: 'ollama', name: 'Ollama', re: /(^|[/\s])ollama(\.app)?(\/|\s|$)|\bOllama\b/ },
  { id: 'llama-cpp', name: 'llama.cpp', re: /\bllama-server\b|llama\.cpp/ },
  { id: 'vllm', name: 'vLLM', re: /\bvllm\b/ },
  { id: 'localai', name: 'LocalAI', re: /\blocal-ai\b|\blocalai\b/i },
  { id: 'open-webui', name: 'Open WebUI', re: /open[-_]webui/i },
  { id: 'lm-studio', name: 'LM Studio', re: /LM Studio|lm-studio|\blms\s+server\b/ },
  { id: 'gpt4all', name: 'GPT4All', re: /gpt4all/i },
  { id: 'comfyui', name: 'ComfyUI', re: /comfyui/i },
  { id: 'koboldcpp', name: 'KoboldCpp', re: /koboldcpp/i },
];

/** Ports only AI model servers use by default. */
const AI_PORTS: Record<number, string> = { 11434: 'Ollama', 1234: 'LM Studio', 4891: 'GPT4All', 1337: 'Jan', 8188: 'ComfyUI' };

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|\[?::1\]?|localhost)$/;
const isExposed = (address: string) => !LOOPBACK.test(address);

/** A program started by npx, uvx, node, python… whose name is an MCP server's. Flags like `--mcp-config` don't count. */
const MCP_PROCESS = /\b(?:npx|uvx|bunx|pnpm dlx|yarn dlx|node|python3?|deno|bun)\b[^\n]*?(?<![-\w])(@modelcontextprotocol\/[\w.-]+|mcp-server-[\w.-]+|[\w.-]+-mcp(?:-server)?|mcp_server_\w+|fastmcp)(?![\w-])/i;

const describeAddress = (a: string, port: number) => `${/^(\*|0\.0\.0\.0|\[?::\]?)$/.test(a) ? 'every network interface' : a}:${port}`;

/** Tokens that identify an inventoried MCP server inside a process's command line. */
function tokensOf(a: Asset): string[] {
  const m = a.mcp;
  if (!m) return [];
  const t = [m.package?.name, ...(m.args ?? []).filter((x) => !x.startsWith('-')), m.command?.split('/').pop()];
  return t.filter((x): x is string => !!x && x.length >= 4).map((x) => x.replace(/@[\w.^~-]+$/, '').toLowerCase());
}

export function analyzeEndpoint(col: Collector, f: Findings, snap: EndpointSnapshot): void {
  const byPid = new Map(snap.processes.map((p) => [p.pid, p.command]));
  const seen = new Set<string>();
  for (const l of snap.listeners) {
    const command = byPid.get(l.pid) ?? '';
    const svc = SERVICES.find((s) => s.re.test(command));
    const label = svc?.name ?? AI_PORTS[l.port];
    if (!label || (!svc && !AI_PORTS[l.port])) continue;
    const key = `${svc?.id ?? label}|${l.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const id = svc ? `app:${svc.id}` : `app:port-${l.port}`;
    const name = svc ? label : `${label}-style server on port ${l.port}`;
    const existing = [...col.assets.values()].find((a) => a.kind === 'app' && a.name.toLowerCase() === label.toLowerCase());
    const where = describeAddress(l.address, l.port);
    const assetId =
      existing?.id ??
      col.add({ kind: 'app', name, key: id, path: undefined, app: {}, occurrence: { client: 'applications', scope: 'user', source: `listening on ${where}`, name, note: 'Found running, by the port it listens on' } });
    col.client('applications', 'Applications');
    if (isExposed(l.address)) {
      const a = col.assets.get(assetId);
      f.add('MODEL-SERVER-EXPOSED', 'medium', {
        asset: a,
        location: `listening on ${where}`,
        title: `${name} is reachable from other computers`,
        evidence: `${label}: listening on ${where}`,
        detail: 'Model servers like this usually have no login. Anyone on the same network can send it prompts, load models and use your hardware.',
      });
    }
  }
  const listed = [...col.assets.values()].filter((a) => a.kind === 'mcp-server').flatMap(tokensOf);
  const shown = new Set<string>();
  for (const p of snap.processes) {
    if (!MCP_PROCESS.test(p.command) || /\b(ai-bom|vitest)\b/.test(p.command)) continue;
    const lower = p.command.toLowerCase();
    if (listed.some((t) => lower.includes(t))) continue;
    // A launcher and the program it starts are one server.
    const key = (MCP_PROCESS.exec(p.command)?.[1] ?? '').toLowerCase();
    if (shown.has(key) || shown.size >= 5) continue;
    shown.add(key);
    f.add('MCP-UNLISTED-RUNNING', 'low', {
      location: 'running processes',
      title: `A program that looks like an MCP server is running: ${key}`,
      evidence: redactText(p.command).slice(0, 160),
      detail: 'No config file AI-BOM reads lists it. It may have been started by an app whose config AI-BOM doesn’t cover, by a script, or by hand.',
    });
  }
}
