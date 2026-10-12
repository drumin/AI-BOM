import path from 'node:path';
import type { McpServerDetails, PackageRef, Transport } from './types.js';
import { asString, asStringArray, asStringRecord, isObject } from './util/fs.js';

/**
 * Normalize the common MCP server entry shapes used across clients:
 *   { command, args, env }                      (Claude, Cursor, Windsurf, Gemini...)
 *   { type|transport: "http"|"sse", url, headers }
 *   { serverUrl } (Windsurf) / { httpUrl } (Gemini)
 * Client-specific shapes (Zed, Goose, opencode, Continue) are adapted by
 * their scanners before being passed here.
 */
export function normalizeMcpEntry(entry: unknown): { details: McpServerDetails; enabled: boolean } | undefined {
  if (!isObject(entry)) return undefined;
  let command = asString(entry.command);
  let args = asStringArray(entry.args) ?? [];
  // `ai-bom fix` wraps servers as: ai-bom-secrets NAME=service … -- <real command>. Look through the wrapper.
  let keychainEnv: string[] | undefined;
  if (command && path.basename(command) === 'ai-bom-secrets') {
    const sep = args.indexOf('--');
    if (sep >= 0 && sep + 1 < args.length) {
      keychainEnv = args.slice(0, sep).map((a) => a.split('=')[0]);
      command = args[sep + 1];
      args = args.slice(sep + 2);
    }
  }
  const url = asString(entry.url) ?? asString(entry.serverUrl) ?? asString(entry.httpUrl) ?? asString(entry.uri);
  const typeRaw = (asString(entry.type) ?? asString(entry.transport) ?? '').toLowerCase();
  const env = asStringRecord(entry.env) ?? asStringRecord(entry.environment);
  const headers = asStringRecord(entry.headers) ?? asStringRecord(entry.http_headers);

  if (!command && !url) return undefined;

  let transport: Transport = 'unknown';
  if (command) transport = 'stdio';
  else if (typeRaw.includes('sse')) transport = 'sse';
  else if (url) transport = typeRaw === 'stdio' ? 'unknown' : 'http';

  const details: McpServerDetails = { transport };
  if (command) {
    details.command = command;
    details.args = args;
    const pkg = detectPackage(command, args);
    if (pkg) details.package = pkg;
    const remote = detectRemoteProxy(args);
    if (remote) details.remoteUrl = remote;
  }
  if (url) details.url = url;
  if (keychainEnv?.length) details.keychainEnv = keychainEnv;
  if (env && Object.keys(env).length) details.env = env;
  if (headers && Object.keys(headers).length) details.headers = headers;

  const disabled = entry.disabled === true || entry.enabled === false || entry.isActive === false;
  return { details, enabled: !disabled };
}

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;

/** Split `name@version`, respecting npm scopes (`@scope/name@1.2.3`). */
export function splitNpmSpec(spec: string): { name: string; version?: string } {
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec };
}

function firstPositional(args: string[], flagsWithValue: Set<string>): { value?: string; index: number } {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') return { value: args[i + 1], index: i + 1 };
    if (a.startsWith('-')) {
      if (!a.includes('=') && flagsWithValue.has(a)) i++;
      continue;
    }
    return { value: a, index: i };
  }
  return { index: -1 };
}

const NPX_FLAGS = new Set(['-p', '--package', '-c', '--call', '--registry', '--cache', '--userconfig']);
const UVX_FLAGS = new Set(['--from', '--with', '--python', '-p', '--index-url', '--extra-index-url', '--index', '--with-requirements', '--directory']);
const DOCKER_RUN_FLAGS = new Set([
  '-e', '--env', '-v', '--volume', '--mount', '-p', '--publish', '--name', '--network', '--net', '-w', '--workdir',
  '-u', '--user', '--env-file', '--entrypoint', '-l', '--label', '--platform', '--add-host', '--cap-add', '--cap-drop',
  '-h', '--hostname', '--memory', '-m', '--cpus', '--pull', '--restart', '--device', '--security-opt', '--ipc', '--pid',
  '--tmpfs', '--ulimit', '--runtime', '--gpus', '--dns', '--log-driver',
]);

export function detectPackage(command: string, args: string[]): PackageRef | undefined {
  const bin = path.basename(command).replace(/\.(cmd|exe)$/i, '');

  // npm family: npx, bunx, pnpm dlx, yarn dlx, npm exec
  let npmArgs: string[] | undefined;
  if (bin === 'npx' || bin === 'bunx') npmArgs = args;
  else if ((bin === 'pnpm' || bin === 'yarn') && args[0] === 'dlx') npmArgs = args.slice(1);
  else if (bin === 'npm' && (args[0] === 'exec' || args[0] === 'x')) npmArgs = args.slice(1);
  if (npmArgs) {
    const pIdx = npmArgs.findIndex((a) => a === '-p' || a === '--package');
    const eqPkg = npmArgs.find((a) => a.startsWith('--package='));
    const spec = pIdx >= 0 ? npmArgs[pIdx + 1] : eqPkg ? eqPkg.split('=')[1] : firstPositional(npmArgs, NPX_FLAGS).value;
    if (spec) {
      const { name, version } = splitNpmSpec(spec);
      return { ecosystem: 'npm', name, version, pinned: !!version && EXACT_SEMVER.test(version), runner: bin };
    }
  }

  // Python: uvx, uv tool run, pipx run
  let pyArgs: string[] | undefined;
  if (bin === 'uvx') pyArgs = args;
  else if (bin === 'uv' && args[0] === 'tool' && args[1] === 'run') pyArgs = args.slice(2);
  else if (bin === 'pipx' && args[0] === 'run') pyArgs = args.slice(1);
  if (pyArgs) {
    const fromIdx = pyArgs.indexOf('--from');
    const spec = fromIdx >= 0 ? pyArgs[fromIdx + 1] : firstPositional(pyArgs, UVX_FLAGS).value;
    if (spec) {
      if (/^(git\+|https?:)/.test(spec)) {
        return { ecosystem: 'pypi', name: spec, pinned: /@[0-9a-f]{40}$/.test(spec), runner: bin };
      }
      const m = spec.match(/^([A-Za-z0-9._\-[\]]+)\s*(==|>=|<=|~=|@|>|<)?\s*([^\s]*)$/);
      const name = m ? m[1] : spec;
      const op = m?.[2];
      const version = m?.[3] || undefined;
      return { ecosystem: 'pypi', name, version, pinned: (op === '==' || op === '@') && !!version && version !== 'latest', runner: bin };
    }
  }

  // Containers
  if ((bin === 'docker' || bin === 'podman') && args[0] === 'run') {
    const { value: image } = firstPositional(args.slice(1), DOCKER_RUN_FLAGS);
    if (image) {
      const digest = image.includes('@sha256:');
      const lastSegment = image.split('/').pop() ?? image;
      const tag = digest ? image.split('@')[1] : lastSegment.includes(':') ? lastSegment.split(':').pop() : undefined;
      const name = digest ? image.split('@')[0] : tag ? image.slice(0, image.length - tag.length - 1) : image;
      return { ecosystem: 'docker', name, version: tag, pinned: digest, runner: bin };
    }
  }

  // Local scripts run by an interpreter
  if (['node', 'python', 'python3', 'deno', 'bun', 'ruby'].includes(bin)) {
    const script = args.find((a) => !a.startsWith('-') && a !== 'run');
    if (script) return { ecosystem: 'local', name: script, pinned: true, runner: bin };
  }
  if (bin === 'uv' && args[0] === 'run') {
    const script = firstPositional(args.slice(1), new Set(['--directory', '--with', '--python', '--project'])).value;
    if (script) return { ecosystem: 'local', name: script, pinned: true, runner: 'uv' };
  }

  if (['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh'].includes(bin)) return undefined;
  return { ecosystem: 'binary', name: command, pinned: true };
}

/** `npx mcp-remote https://...` and similar proxies bridge stdio to a remote server. */
export function detectRemoteProxy(args: string[]): string | undefined {
  const joined = args.join(' ');
  if (!/mcp-remote|supergateway|mcp-proxy/.test(joined)) return undefined;
  return args.find((a) => /^https?:\/\//.test(a));
}

/**
 * Identity used to merge the same server configured in multiple clients.
 * Name is deliberately excluded: people name the same server differently.
 */
export function mcpIdentity(d: McpServerDetails, home: string): string {
  const norm = (s: string) => s.split(home).join('~');
  if (d.url) return `url:${d.url.split('?')[0].replace(/\/$/, '')}`;
  if (d.package && d.package.ecosystem !== 'binary' && d.package.ecosystem !== 'local') {
    // Include args other than the package spec so two differently-configured
    // filesystem servers stay distinct.
    const rest = (d.args ?? []).filter((a) => !a.includes(d.package!.name) && a !== '-y' && a !== '--yes');
    return `pkg:${d.package.ecosystem}:${d.package.name}:${d.package.version ?? ''}:${norm(rest.join(' '))}`;
  }
  return `cmd:${norm(d.command ?? '')} ${norm((d.args ?? []).join(' '))}`;
}
