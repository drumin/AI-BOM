import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Asset, DeclaredTool, Finding, McpServerDetails, TrustInfo } from './types.js';
import { Collector, defaultContext } from './collector.js';
import { Findings, runChecks } from './checks/index.js';
import { analyzeTools } from './analysis/tools.js';
import { assessTrust } from './trust/index.js';
import { checkBundled, checkOsv, mergeHits, type Fetch } from './vulns/index.js';
import { loadCachedFeed, mergeAdvisories } from './feed/index.js';
import { normalizeMcpEntry } from './mcp.js';
import { fetchNpm, fetchPypi, type BytesFetch, type FetchedPackage } from './pkgfetch.js';
import { verdictOf, type Verdict } from './preflight.js';
import { checkDependencies, type DepReport } from './deps.js';

/**
 * Vet an MCP server BEFORE it is added: download the exact package version
 * (never install or run it), read its tool code, and run the same checks a
 * scan would, plus advisories, trust signals and its dependencies.
 */

export interface Spec {
  kind: 'npm' | 'pypi' | 'remote';
  name: string;
  version?: string;
  url?: string;
}

export function parseSpec(input: string): Spec {
  const s = input.trim();
  if (/^https?:\/\//.test(s)) return { kind: 'remote', name: new URL(s).hostname.split('.').slice(-2, -1)[0] || 'remote', url: s };
  const py = s.match(/^(?:pypi:|uvx\s+)([A-Za-z0-9._-]+)(?:==([\w.+-]+))?$/);
  if (py) return { kind: 'pypi', name: py[1], version: py[2] };
  const npm = s.replace(/^(npm:|npx\s+(-y\s+)?)/, '');
  const at = npm.lastIndexOf('@');
  if (at > 0) return { kind: 'npm', name: npm.slice(0, at), version: npm.slice(at + 1) };
  return { kind: 'npm', name: npm };
}

export interface VetResult {
  spec: Spec;
  version?: string;
  latest?: string;
  /** Config entry to write (stdio command or remote URL). */
  entry: { command?: string; args?: string[]; url?: string };
  verdict: Verdict;
  findings: Finding[];
  tools: DeclaredTool[];
  trust?: TrustInfo;
  deps?: DepReport;
  sourceDir?: string;
  cleanup: () => Promise<void>;
}

/** The short name a config entry gets by default: "@scope/server-github" → "github". */
export const defaultName = (spec: Spec) =>
  spec.kind === 'remote' ? spec.name : spec.name.replace(/^@[^/]+\//, '').replace(/^(mcp[-_]server[-_]|server[-_])/, '').replace(/[-_]mcp([-_]server)?$/, '').replace(/[^A-Za-z0-9_-]/g, '-') || spec.name;

export async function vet(input: string | Spec, opts: { fetchImpl?: BytesFetch; online?: boolean } = {}): Promise<VetResult> {
  const spec = typeof input === 'string' ? parseSpec(input) : input;
  const fetchImpl = opts.fetchImpl ?? (fetch as unknown as BytesFetch);
  let pkg: FetchedPackage | undefined;
  let entry: VetResult['entry'];
  if (spec.kind === 'npm') {
    pkg = await fetchNpm(spec.name, spec.version, fetchImpl);
    entry = { command: 'npx', args: ['-y', `${spec.name}@${pkg.version}`] };
  } else if (spec.kind === 'pypi') {
    pkg = await fetchPypi(spec.name, spec.version, fetchImpl);
    entry = { command: 'uvx', args: [`${spec.name}==${pkg.version}`] };
  } else entry = { url: spec.url };

  // An empty scan context: nothing from your machine is read.
  const empty = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-bom-vet-'));
  const col = new Collector(defaultContext({ home: empty, platform: process.platform, systemRoot: empty }));
  const norm = normalizeMcpEntry(entry.url ? { url: entry.url } : entry)!;
  const details: McpServerDetails = { ...norm.details, sourceDir: pkg?.dir };
  const id = col.add({ kind: 'mcp-server', name: defaultName(spec), mcp: details, occurrence: { client: 'generic', scope: 'user', source: 'ai-bom add', name: defaultName(spec) } });
  const a = col.assets.get(id) as Asset;
  const f = new Findings();
  await analyzeTools(col, f, (p) => (pkg && p.startsWith(pkg.dir) ? `${spec.name}/${path.relative(pkg.dir, p)}` : p));
  const online = opts.online !== false;
  await assessTrust(col, f, { online, fetchImpl: fetchImpl as unknown as Fetch });
  const advisories = mergeAdvisories(await loadCachedFeed());
  let hits = checkBundled([a], advisories);
  if (online && pkg) hits = mergeHits(hits, (await checkOsv([a], fetchImpl as unknown as Fetch)).hits);
  let deps: DepReport | undefined;
  if (pkg) {
    deps = await checkDependencies(pkg, { online, fetchImpl: fetchImpl as unknown as Fetch, advisories });
    for (const d of deps.vulnerable) f.add('DEP-VULN', d.severity, { asset: a, location: `${spec.name}@${pkg.version}`, title: `${d.id} in dependency ${d.name}@${d.version}`, evidence: `${d.name}@${d.version}: ${d.summary}`, references: d.references });
  }
  const findings = (await runChecks(col, hits, f)).filter((x) => x.ruleId !== 'MCP-UNPINNED');
  // Source paths were already made relative by the tilde function; keep only the package-relative part.
  for (const x of findings) if (x.location && pkg && x.location.startsWith(pkg.dir)) x.location = `${spec.name}/${path.relative(pkg.dir, x.location)}`;
  await fs.rm(empty, { recursive: true, force: true });
  return {
    spec,
    version: pkg?.version,
    latest: pkg?.latest,
    entry,
    verdict: verdictOf(findings),
    findings,
    tools: a.mcp?.tools ?? [],
    trust: a.trust,
    deps,
    sourceDir: pkg?.dir,
    cleanup: async () => {
      await pkg?.cleanup();
    },
  };
}
