import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Asset, DeclaredTool, Inventory } from './types.js';
import { applyChanges, type Op, type Snapshot } from './fix/index.js';
import { getAt, hasAt, readJsonDoc } from './fix/jsonedit.js';
import { ensureLauncher, launcherPath, serviceName, type SecretStore } from './fix/keychain.js';
import { defaultContext } from './collector.js';
import { normalizeMcpEntry } from './mcp.js';
import { pinnedArgs } from './vulns/fix.js';
import { compareVersions } from './vulns/semver.js';
import { vet, type Spec, type VetResult } from './vet.js';
import { fetchPypi, type BytesFetch } from './pkgfetch.js';

/**
 * Safe add: write a vetted, pinned MCP server into the AI tools you choose,
 * with its secrets in the keychain. Safe upgrade: show exactly what changes
 * between the pinned version and the latest (tools, descriptions, hosts,
 * install scripts, advisories), then pin the new version. Both go through
 * snapshots, so `ai-bom undo` reverts them.
 */

export interface Target {
  id: string;
  name: string;
  file: (ctx: ReturnType<typeof defaultContext>, project?: string) => string;
  key: string;
  /** Config entry shape for this tool. */
  stdio: (command: string, args: string[], env?: Record<string, string>) => Record<string, unknown>;
  remote: (url: string) => Record<string, unknown> | undefined;
  /** Folder whose existence means the tool is installed. */
  detect: (ctx: ReturnType<typeof defaultContext>) => string;
}

const stdio = (type?: string) => (command: string, args: string[], env?: Record<string, string>) => ({ ...(type ? { type } : {}), command, args, ...(env && Object.keys(env).length ? { env } : {}) });

export const TARGETS: Target[] = [
  { id: 'claude-code', name: 'Claude Code', file: (c, p) => (p ? path.join(p, '.mcp.json') : c.claudeState), key: 'mcpServers', stdio: stdio('stdio'), remote: (url) => ({ type: 'http', url }), detect: (c) => c.claudeDir },
  { id: 'claude-desktop', name: 'Claude Desktop', file: (c) => path.join(c.appSupport, 'Claude', 'claude_desktop_config.json'), key: 'mcpServers', stdio: stdio(), remote: () => undefined, detect: (c) => path.join(c.appSupport, 'Claude') },
  { id: 'cursor', name: 'Cursor', file: (c, p) => path.join(p ?? c.home, '.cursor', 'mcp.json'), key: 'mcpServers', stdio: stdio(), remote: (url) => ({ url }), detect: (c) => path.join(c.home, '.cursor') },
  { id: 'vscode', name: 'VS Code', file: (c, p) => (p ? path.join(p, '.vscode', 'mcp.json') : path.join(c.appSupport, 'Code', 'User', 'mcp.json')), key: 'servers', stdio: stdio('stdio'), remote: (url) => ({ type: 'http', url }), detect: (c) => path.join(c.appSupport, 'Code') },
  { id: 'windsurf', name: 'Windsurf', file: (c) => path.join(c.home, '.codeium', 'windsurf', 'mcp_config.json'), key: 'mcpServers', stdio: stdio(), remote: (url) => ({ serverUrl: url }), detect: (c) => path.join(c.home, '.codeium', 'windsurf') },
  { id: 'gemini-cli', name: 'Gemini CLI', file: (c, p) => path.join(p ?? c.home, '.gemini', 'settings.json'), key: 'mcpServers', stdio: stdio(), remote: (url) => ({ httpUrl: url }), detect: (c) => path.join(c.home, '.gemini') },
];

export async function installedTargets(home?: string): Promise<Target[]> {
  const ctx = defaultContext({ home });
  const out: Target[] = [];
  for (const t of TARGETS) {
    try {
      await fs.access(t.detect(ctx));
      out.push(t);
    } catch {
      /* not installed */
    }
  }
  return out;
}

export interface AddPlan {
  ops: Extract<Op, { type: 'json' }>[];
  writes: { target: string; file: string; entry: Record<string, unknown> }[];
  skipped: string[];
}

/** Plan the config edits. Secrets are only referenced by keychain name here. */
export async function planAdd(
  result: VetResult,
  opts: { name: string; targets: string[]; project?: string; home?: string; secretNames?: string[]; force?: boolean; mcpRemoteVersion?: string },
): Promise<AddPlan> {
  const ctx = defaultContext({ home: opts.home });
  const plan: AddPlan = { ops: [], writes: [], skipped: [] };
  const services = Object.fromEntries((opts.secretNames ?? []).map((k) => [k, serviceName(`add/${opts.name}`, k)]));
  for (const id of opts.targets) {
    const t = TARGETS.find((x) => x.id === id);
    if (!t) throw new Error(`Unknown tool "${id}". Choose from: ${TARGETS.map((x) => x.id).join(', ')}`);
    const file = t.file(ctx, opts.project);
    let entry: Record<string, unknown> | undefined;
    if (result.entry.url) {
      entry = t.remote(result.entry.url);
      // Claude Desktop only runs local servers: bridge with a pinned mcp-remote.
      if (!entry && opts.mcpRemoteVersion) entry = t.stdio('npx', ['-y', `mcp-remote@${opts.mcpRemoteVersion}`, result.entry.url]);
      if (!entry) {
        plan.skipped.push(`${t.name}: can't add a remote server here.`);
        continue;
      }
    } else {
      let command = result.entry.command!;
      let args = result.entry.args!;
      if (Object.keys(services).length) {
        args = [...Object.entries(services).map(([k, s]) => `${k}=${s}`), '--', command, ...args];
        command = launcherPath();
      }
      entry = t.stdio(command, args);
    }
    let data: unknown = {};
    try {
      data = (await readJsonDoc(file)).data;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    const p = [t.key, opts.name];
    if (hasAt(data, p) && !opts.force) {
      plan.skipped.push(`${t.name}: "${opts.name}" already exists in ${file} (use --force to replace).`);
      continue;
    }
    const before = hasAt(data, p) ? { present: true as const, value: getAt(data, p) } : { present: false as const };
    // Create the containing map if needed, in one op.
    if (!hasAt(data, [t.key])) plan.ops.push({ type: 'json', file, path: [t.key], before: { present: false }, after: { present: true, value: { [opts.name]: entry } } });
    else plan.ops.push({ type: 'json', file, path: p, before, after: { present: true, value: entry } });
    plan.writes.push({ target: t.name, file, entry });
  }
  return plan;
}

export async function applyAdd(plan: AddPlan, name: string, secrets: Record<string, string>, store?: SecretStore): Promise<Snapshot | undefined> {
  if (!plan.ops.length) return undefined;
  if (Object.keys(secrets).length) {
    if (!store || !(await store.available())) throw new Error('No keychain tool found for the secrets.');
    for (const [k, v] of Object.entries(secrets)) await store.set(serviceName(`add/${name}`, k), v);
    await ensureLauncher();
  }
  return applyChanges(`Add ${name}`, 'pin-version', plan.ops);
}

/* ---------------- Upgrade ---------------- */

export interface UpgradeCandidate {
  assetId: string;
  name: string;
  ecosystem: 'npm' | 'pypi';
  package: string;
  current: string;
  latest: string;
}

/** Servers whose pinned (or cached) version is behind the latest release. Needs the registries. */
export async function upgradeCandidates(inv: Inventory, fetchImpl?: BytesFetch): Promise<UpgradeCandidate[]> {
  const out: UpgradeCandidate[] = [];
  await Promise.all(
    inv.assets.map(async (a) => {
      const p = a.mcp?.package;
      if (!p || (p.ecosystem !== 'npm' && p.ecosystem !== 'pypi')) return;
      const current = p.pinned ? p.version : [...(p.installedVersions ?? [])].sort(compareVersions).pop();
      if (!current) return;
      let latest = p.latestVersion;
      if (!latest) {
        try {
          const res = await (fetchImpl ?? (fetch as unknown as BytesFetch))(p.ecosystem === 'npm' ? `https://registry.npmjs.org/${p.name.replace('/', '%2F')}/latest` : `https://pypi.org/pypi/${encodeURIComponent(p.name)}/json`);
          if (res.ok) {
            const d = (await res.json()) as { version?: string; info?: { version?: string } };
            latest = d.version ?? d.info?.version;
          }
        } catch {
          return;
        }
      }
      if (latest && compareVersions(latest, current) > 0) out.push({ assetId: a.id, name: a.name, ecosystem: p.ecosystem, package: p.name, current, latest });
    }),
  );
  return out.sort((x, y) => x.name.localeCompare(y.name));
}

export interface UpgradeDiff {
  candidate: UpgradeCandidate;
  toolsAdded: string[];
  toolsRemoved: string[];
  descriptionsChanged: string[];
  newHosts: string[];
  newMismatches: string[];
  installScripts: string[];
  newFindings: { severity: string; title: string }[];
  fixedFindings: { severity: string; title: string }[];
  verdict: VetResult['verdict'];
}

const hostsOf = (tools: DeclaredTool[]) => new Set(tools.flatMap((t) => t.behavior?.hosts ?? []));

export async function diffUpgrade(c: UpgradeCandidate, opts: { fetchImpl?: BytesFetch; online?: boolean } = {}): Promise<UpgradeDiff> {
  const spec = (version: string): Spec => ({ kind: c.ecosystem, name: c.package, version });
  const [before, after] = await Promise.all([vet(spec(c.current), opts), vet(spec(c.latest), opts)]);
  try {
    const bt = new Map(before.tools.map((t) => [t.name, t]));
    const at = new Map(after.tools.map((t) => [t.name, t]));
    const bh = hostsOf(before.tools);
    const key = (f: { ruleId: string; title: string }) => `${f.ruleId}|${f.title.replace(before.version ?? '', '').replace(after.version ?? '', '')}`;
    const bf = new Set(before.findings.map(key));
    const af = new Set(after.findings.map(key));
    return {
      candidate: c,
      toolsAdded: [...at.keys()].filter((n) => !bt.has(n)),
      toolsRemoved: [...bt.keys()].filter((n) => !at.has(n)),
      descriptionsChanged: [...at.keys()].filter((n) => bt.has(n) && (bt.get(n)!.description ?? '') !== (at.get(n)!.description ?? '')),
      newHosts: [...hostsOf(after.tools)].filter((h) => !bh.has(h)),
      newMismatches: after.tools.filter((t) => t.behavior?.verdict === 'mismatch' && bt.get(t.name)?.behavior?.verdict !== 'mismatch').map((t) => `${t.name}: ${t.behavior!.reasons.join('; ')}`),
      installScripts: after.trust?.installScripts ?? [],
      newFindings: after.findings.filter((f) => !bf.has(key(f))).map((f) => ({ severity: f.severity, title: f.title })),
      fixedFindings: before.findings.filter((f) => !af.has(key(f))).map((f) => ({ severity: f.severity, title: f.title })),
      verdict: after.verdict,
    };
  } finally {
    await before.cleanup();
    await after.cleanup();
  }
}

/** Pin every editable config entry of the server to `version`, as one snapshot. */
export async function applyUpgrade(asset: Asset, version: string, home: string): Promise<Snapshot> {
  const expand = (p: string) => (p.startsWith('~/') ? path.join(home, p.slice(2)) : p);
  const ops: Extract<Op, { type: 'json' }>[] = [];
  for (const o of asset.occurrences) {
    if (!o.jsonPath || o.via || !/\.(json|jsonc)$/i.test(o.source)) continue;
    const file = expand(o.source);
    const doc = await readJsonDoc(file);
    const entry = getAt(doc.data, o.jsonPath) as Record<string, unknown> | undefined;
    const norm = normalizeMcpEntry(entry);
    if (!entry || !norm || !Array.isArray(entry.args)) continue;
    const next = pinnedArgs(norm.details, version);
    if (!next) continue;
    const raw = entry.args as string[];
    const sep = typeof entry.command === 'string' && path.basename(entry.command) === 'ai-bom-secrets' ? raw.indexOf('--') : -1;
    const value = sep >= 0 ? [...raw.slice(0, sep + 2), ...next] : next;
    ops.push({ type: 'json', file, path: [...o.jsonPath, 'args'], before: { present: true, value: raw }, after: { present: true, value } });
  }
  if (!ops.length) throw new Error('No config entry of this server can be edited automatically.');
  return applyChanges(`Upgrade ${asset.name} to ${version}`, 'pin-version', ops);
}

/** Latest mcp-remote, to bridge remote servers into Claude Desktop pinned. */
export async function latestMcpRemote(fetchImpl?: BytesFetch): Promise<string | undefined> {
  try {
    const res = await (fetchImpl ?? (fetch as unknown as BytesFetch))('https://registry.npmjs.org/mcp-remote/latest');
    return res.ok ? ((await res.json()) as { version?: string }).version : undefined;
  } catch {
    return undefined;
  }
}

export { fetchPypi };
