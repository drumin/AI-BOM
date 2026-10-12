import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import type { Asset, DeclaredTool } from './types.js';
import { INJECTION } from './checks/index.js';
import { scanHidden } from './analysis/hidden.js';
import { redactText } from './util/secrets.js';
import { dataDir, readJsonFile, writeJsonFile } from './util/store.js';
import { VERSION } from './scan.js';

/**
 * Live inspection, in a sandbox, on request only.
 *
 * Reading code says what a server *should* expose; asking it says what it
 * *does* expose. The server is started once, isolated:
 *   macOS  sandbox-exec: no network, no writes to your home, no reads of
 *          credential folders (~/.ssh, ~/.aws, keychains, browser data…)
 *   Linux  bwrap: no network, an empty home folder, read-only system;
 *          or `unshare` (network isolation only) when bwrap is missing
 * with an empty HOME, none of your environment variables or secrets, and a
 * 20-second limit. AI-BOM then asks it for tools/list over MCP and stops it.
 */

export type SandboxKind = 'sandbox-exec' | 'bwrap' | 'unshare';

export interface InspectResult {
  at: string;
  assetId: string;
  name: string;
  sandbox: SandboxKind;
  /** What was run inside the sandbox (redacted). */
  command: string;
  ok: boolean;
  error?: string;
  serverInfo?: { name?: string; version?: string };
  tools: { name: string; description?: string; schemaChars: number }[];
  /** Tools the running server exposes that reading its code didn't find. */
  liveOnly: string[];
  /** Tools found in code that the running server didn't list. */
  staticOnly: string[];
  /** Tools whose runtime description differs from the one in code (computed at runtime). */
  changedDescriptions: string[];
  /** Hidden characters / instruction text in live descriptions. */
  poisoned: string[];
  /** Signs it tried to reach the network while starting. */
  networkAttempts: string[];
  stderrTail: string;
}

const has = (bin: string) => {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [bin], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

export function availableSandbox(): SandboxKind | undefined {
  if (process.platform === 'darwin' && has('sandbox-exec')) return 'sandbox-exec';
  if (process.platform === 'linux') {
    if (has('bwrap')) return 'bwrap';
    if (has('unshare')) {
      try {
        execFileSync('unshare', ['-rn', 'true'], { stdio: 'ignore' });
        return 'unshare';
      } catch {
        /* user namespaces disabled */
      }
    }
  }
  return undefined;
}

/** The command that runs the server's code directly from disk (no npx/uvx download). */
export async function localCommand(a: Asset, home: string): Promise<{ command: string; args: string[] } | undefined> {
  const m = a.mcp;
  if (!m?.command || m.url) return undefined;
  const expand = (s: string) => s.replace(/^~(?=\/)/, home);
  const dir = m.sourceDir ? expand(m.sourceDir) : undefined;
  const pkg = m.package;
  const extraArgs = () => {
    const args = m.args ?? [];
    const i = args.findIndex((x) => pkg && (x === pkg.name || x.startsWith(`${pkg.name}@`) || x.startsWith(`${pkg.name}==`)));
    return i >= 0 ? args.slice(i + 1) : [];
  };
  if (pkg?.ecosystem === 'npm' && dir) {
    try {
      const pj = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
      const bin = typeof pj.bin === 'string' ? pj.bin : pj.bin && typeof pj.bin === 'object' ? (Object.values(pj.bin)[0] as string) : pj.main ?? 'index.js';
      return { command: process.execPath, args: [path.join(dir, bin), ...extraArgs()] };
    } catch {
      return undefined;
    }
  }
  if (pkg?.ecosystem === 'pypi' && dir) {
    const sp = dir.slice(0, dir.lastIndexOf('site-packages') + 'site-packages'.length);
    const env = path.resolve(sp, '..', '..', '..');
    const script = path.join(env, 'bin', pkg.name);
    try {
      await fs.access(script);
      return { command: script, args: extraArgs() };
    } catch {
      return { command: path.join(env, 'bin', 'python'), args: ['-m', path.basename(dir).replace(/\.py$/, ''), ...extraArgs()] };
    }
  }
  if (!pkg || pkg.ecosystem === 'local' || pkg.ecosystem === 'binary') return { command: expand(m.command), args: (m.args ?? []).map(expand) };
  return undefined;
}

const SECRET_DIRS = ['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.config/gh', '.config/gcloud', 'Library/Keychains', 'Library/Application Support/Google/Chrome', 'Library/Application Support/Firefox', 'Library/Cookies'];

function wrap(kind: SandboxKind, cmd: { command: string; args: string[] }, fakeHome: string, realHome: string, readable: string[]): { command: string; args: string[] } {
  if (kind === 'sandbox-exec') {
    const q = (p: string) => JSON.stringify(p);
    const profile = [
      '(version 1)',
      '(allow default)',
      '(deny network*)',
      '(allow network* (local unix))',
      `(deny file-write* (subpath ${q(realHome)}))`,
      `(allow file-write* (subpath ${q(fakeHome)}))`,
      ...SECRET_DIRS.map((d) => `(deny file-read* (subpath ${q(path.join(realHome, d))}))`),
    ].join('\n');
    return { command: 'sandbox-exec', args: ['-p', profile, cmd.command, ...cmd.args] };
  }
  if (kind === 'bwrap') {
    const binds = readable.flatMap((r) => ['--ro-bind', r, r]);
    return {
      command: 'bwrap',
      args: ['--ro-bind', '/', '/', '--tmpfs', realHome, ...binds, '--bind', fakeHome, fakeHome, '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp', '--unshare-net', '--unshare-pid', '--die-with-parent', '--new-session', cmd.command, ...cmd.args],
    };
  }
  return { command: 'unshare', args: ['-rn', cmd.command, ...cmd.args] };
}

/** How long to keep a server alive after its tool list arrives, to catch start-up network attempts. */
const SETTLE_MS = 400;

const NETWORK_ERR = /(ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ENETUNREACH|getaddrinfo|Network is unreachable|Temporary failure in name resolution|Name or service not known|nodename nor servname|NameResolutionError|ConnectError|fetch failed)[^\n]{0,120}/gi;

/** Run the server in the sandbox and list its tools. */
export async function inspectLive(a: Asset, home: string, staticTools: DeclaredTool[] = a.mcp?.tools ?? [], timeoutMs = 20_000): Promise<InspectResult> {
  const kind = availableSandbox();
  const base: InspectResult = { at: new Date().toISOString(), assetId: a.id, name: a.name, sandbox: kind ?? 'unshare', command: '', ok: false, tools: [], liveOnly: [], staticOnly: [], changedDescriptions: [], poisoned: [], networkAttempts: [], stderrTail: '' };
  if (!kind) return { ...base, error: 'No sandbox is available (macOS sandbox-exec, or bwrap/unshare on Linux). Nothing was run.' };
  const local = await localCommand(a, home);
  if (!local) return { ...base, error: 'Its code is not on this machine (remote server, or never run). Nothing was run.' };
  const fakeHome = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-bom-sandbox-'));
  const readable = a.mcp?.sourceDir ? [path.resolve(a.mcp.sourceDir.replace(/^~(?=\/)/, home), a.mcp.package?.ecosystem === 'npm' ? '../..' : '../../../..')] : [];
  const w = wrap(kind, local, fakeHome, home, readable.filter((r) => r.startsWith(home)));
  base.command = redactText([local.command, ...local.args].join(' ')).replace(home, '~');
  base.sandbox = kind;

  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: fakeHome, TMPDIR: fakeHome, LANG: 'C.UTF-8', NO_COLOR: '1' };
  const child = spawn(w.command, w.args, { env, cwd: fakeHome, stdio: ['pipe', 'pipe', 'pipe'], detached: process.platform !== 'win32' });
  let stderr = '';
  let buf = '';
  const waiting = new Map<number, (msg: Record<string, unknown>) => void>();
  child.stderr.on('data', (d) => (stderr = (stderr + d).slice(-20_000)));
  child.stdout.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as Record<string, unknown>;
        if (typeof msg.id === 'number') waiting.get(msg.id)?.(msg);
      } catch {
        /* not JSON-RPC (logging on stdout) */
      }
    }
  });
  const exited = new Promise<number | null>((r) => child.on('close', (code) => r(code)));
  child.on('error', () => {});
  const send = (msg: object) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', ...msg }) + '\n');
  const request = (id: number, method: string, params: object): Promise<Record<string, unknown>> =>
    Promise.race<Record<string, unknown>>([
      new Promise<Record<string, unknown>>((resolve) => {
        waiting.set(id, resolve);
        send({ id, method, params });
      }),
      exited.then(() => ({ error: { message: 'The server exited.' } })),
      new Promise<Record<string, unknown>>((resolve) => setTimeout(() => resolve({ error: { message: `No answer within ${timeoutMs / 1000}s.` } }), timeoutMs)),
    ]);
  try {
    const init = await request(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'ai-bom-inspect', version: VERSION } });
    if (init.error) throw new Error((init.error as { message?: string }).message ?? 'initialize failed');
    base.serverInfo = (init.result as { serverInfo?: { name?: string; version?: string } })?.serverInfo;
    send({ method: 'notifications/initialized' });
    const tools: InspectResult['tools'] = [];
    let cursor: string | undefined;
    for (let page = 0, id = 2; page < 10; page++, id++) {
      const res = await request(id, 'tools/list', cursor ? { cursor } : {});
      if (res.error) throw new Error((res.error as { message?: string }).message ?? 'tools/list failed');
      const r = res.result as { tools?: { name: string; description?: string; inputSchema?: unknown }[]; nextCursor?: string };
      for (const t of r.tools ?? []) tools.push({ name: String(t.name), description: typeof t.description === 'string' ? t.description : undefined, schemaChars: JSON.stringify(t.inputSchema ?? {}).length });
      cursor = r.nextCursor;
      if (!cursor) break;
    }
    base.tools = tools;
    base.ok = true;
    // A server that phones home does it at start-up, and a blocked attempt takes a few ms to fail and print.
    // Killing the moment the tool list arrives can beat that, so let stderr settle first.
    await new Promise((r) => setTimeout(r, SETTLE_MS));
  } catch (e) {
    base.error = (e as Error).message;
  } finally {
    try {
      if (child.pid && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
      else child.kill('SIGKILL');
    } catch {
      /* already gone */
    }
    await Promise.race([exited, new Promise((r) => setTimeout(r, 1000))]);
    await fs.rm(fakeHome, { recursive: true, force: true });
  }
  base.networkAttempts = [...new Set([...stderr.matchAll(NETWORK_ERR)].map((m) => redactText(m[0].trim())))].slice(0, 5);
  base.stderrTail = redactText(stderr.split('\n').filter(Boolean).slice(-8).join('\n')).replaceAll(fakeHome, '~').slice(-1500);
  const st = new Map(staticTools.map((t) => [t.name, t]));
  const live = new Map(base.tools.map((t) => [t.name, t]));
  if (base.ok) {
    base.liveOnly = [...live.keys()].filter((n) => !st.has(n));
    base.staticOnly = staticTools.length ? [...st.keys()].filter((n) => !live.has(n)) : [];
    base.changedDescriptions = [...live.keys()].filter((n) => st.has(n) && st.get(n)!.description !== undefined && (st.get(n)!.description ?? '').trim() !== (live.get(n)!.description ?? '').trim());
    base.poisoned = base.tools.filter((t) => scanHidden(`${t.name} ${t.description ?? ''}`) || INJECTION.some((re) => re.test(t.description ?? ''))).map((t) => t.name);
  }
  return base;
}

/* ---------------- Stored results ---------------- */

const file = () => path.join(dataDir(), 'inspections.json');

export async function saveInspection(r: InspectResult): Promise<void> {
  const all = (await readJsonFile<Record<string, InspectResult>>(file())) ?? {};
  all[r.assetId] = r;
  await writeJsonFile(file(), all);
}

export async function loadInspections(): Promise<Record<string, InspectResult>> {
  return (await readJsonFile<Record<string, InspectResult>>(file())) ?? {};
}
