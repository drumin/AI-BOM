import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Severity } from './types.js';
import type { Fetch } from './vulns/index.js';
import type { Advisory } from './vulns/advisories.js';
import { compareVersions, inRange } from './vulns/semver.js';
import { normalizePypi } from './vulns/installed.js';
import { listDir } from './util/fs.js';

/**
 * What an MCP server pulls in: its dependency tree, their licenses, and known
 * vulnerabilities in them. Installed servers are read from disk (the npx
 * cache's node_modules, or the uv/pipx environment's site-packages), which is
 * exactly what runs. A package being vetted before install is resolved one
 * level deep from the registry.
 */

export interface DepPackage {
  name: string;
  version: string;
  license?: string;
}

export interface VulnerableDep {
  name: string;
  version: string;
  id: string;
  severity: Severity;
  summary: string;
  references?: string[];
}

export interface DepReport {
  ecosystem: 'npm' | 'pypi';
  /** 'installed' = the full resolved tree on disk; 'direct' = registry resolution of direct dependencies only. */
  scope: 'installed' | 'direct';
  total: number;
  packages: DepPackage[];
  vulnerable: VulnerableDep[];
  licenses: Record<string, number>;
  /** Strong-copyleft or missing licenses worth knowing about. */
  licenseNotes: string[];
  error?: string;
}

const COPYLEFT = /\b(AGPL|GPL|SSPL|EUPL|OSL)\b/i;

function licenseOf(pkg: Record<string, unknown>): string | undefined {
  const l = pkg.license ?? (Array.isArray(pkg.licenses) ? (pkg.licenses[0] as { type?: string })?.type : undefined);
  return typeof l === 'string' ? l : typeof (l as { type?: string })?.type === 'string' ? (l as { type: string }).type : undefined;
}

/** All packages in a node_modules tree (including nested node_modules). */
async function npmTree(nodeModules: string, out: Map<string, DepPackage>, depth = 0): Promise<void> {
  if (depth > 6 || out.size > 5000) return;
  for (const entry of await listDir(nodeModules)) {
    if (entry.startsWith('.')) continue;
    const names = entry.startsWith('@') ? (await listDir(path.join(nodeModules, entry))).map((n) => `${entry}/${n}`) : [entry];
    for (const n of names) {
      const dir = path.join(nodeModules, n);
      try {
        const pkg = JSON.parse(await fs.readFile(path.join(dir, 'package.json'), 'utf8'));
        if (typeof pkg.version === 'string') out.set(`${n}@${pkg.version}`, { name: n, version: pkg.version, license: licenseOf(pkg) });
      } catch {
        continue;
      }
      await npmTree(path.join(dir, 'node_modules'), out, depth + 1);
    }
  }
}

async function pyEnv(sitePackages: string, out: Map<string, DepPackage>): Promise<void> {
  for (const d of await listDir(sitePackages)) {
    const m = d.match(/^(.+?)-(\d[^-]*)\.dist-info$/);
    if (!m) continue;
    let license: string | undefined;
    try {
      const meta = await fs.readFile(path.join(sitePackages, d, 'METADATA'), 'utf8');
      license = meta.match(/^License-Expression:\s*(.+)$/m)?.[1] ?? meta.match(/^License:\s*(.{1,60})$/m)?.[1] ?? meta.match(/^Classifier: License :: (?:OSI Approved :: )?(.+)$/m)?.[1];
    } catch {
      /* no metadata */
    }
    out.set(`${m[1]}@${m[2]}`, { name: normalizePypi(m[1]), version: m[2], license: license?.trim() });
  }
}

/** The package root on disk for an installed server's code directory. */
function installRoots(sourceDir: string): { ecosystem: 'npm' | 'pypi'; root: string; self?: string } | undefined {
  const parts = sourceDir.split(path.sep);
  const nm = parts.lastIndexOf('node_modules');
  if (nm >= 0) return { ecosystem: 'npm', root: parts.slice(0, nm + 1).join(path.sep), self: parts.slice(nm + 1).join('/') };
  const sp = parts.lastIndexOf('site-packages');
  if (sp >= 0) return { ecosystem: 'pypi', root: parts.slice(0, sp + 1).join(path.sep) };
  return undefined;
}

/** Minimal npm range check: exact, ^, ~, >=, <, x-ranges and || alternatives. */
export function satisfies(version: string, range: string): boolean {
  return range.split('||').some((alt) =>
    alt.trim().split(/\s+/).filter(Boolean).every((c) => {
      const m = c.match(/^(\^|~|>=|<=|>|<|=)?v?([\d.x*]+)(?:-[\w.]+)?$/);
      if (!m) return c === '*' || c === 'latest' || c === '';
      const [, op = '=', base] = m;
      const parts = base.split('.').map((p) => (p === 'x' || p === '*' ? undefined : Number(p)));
      const v = version.split(/[.+-]/).map(Number);
      const lo = parts.map((p) => p ?? 0).join('.');
      const cmp = compareVersions(version, lo);
      if (op === '>=') return cmp >= 0;
      if (op === '>') return cmp > 0;
      if (op === '<') return cmp < 0;
      if (op === '<=') return cmp <= 0;
      if (op === '^') {
        if (cmp < 0) return false;
        const i = parts.findIndex((p) => p !== 0 && p !== undefined);
        const lock = i < 0 ? parts.length : i;
        return parts.slice(0, lock + 1).every((p, j) => p === undefined || v[j] === p);
      }
      if (op === '~') return cmp >= 0 && v[0] === parts[0] && (parts[1] === undefined || v[1] === parts[1]);
      return parts.every((p, j) => p === undefined || v[j] === p);
    }),
  );
}

async function resolveDirect(meta: Record<string, unknown>, fetchImpl: Fetch): Promise<DepPackage[]> {
  const deps = { ...(meta.dependencies as Record<string, string> | undefined) };
  const out: DepPackage[] = [];
  await Promise.all(
    Object.entries(deps).slice(0, 80).map(async ([name, range]) => {
      try {
        const res = await fetchImpl(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/vnd.npm.install-v1+json' } });
        if (!res.ok) return;
        const doc = (await res.json()) as { versions?: Record<string, unknown>; 'dist-tags'?: Record<string, string> };
        const latest = doc['dist-tags']?.latest;
        const best = latest && satisfies(latest, range) ? latest : Object.keys(doc.versions ?? {}).filter((v) => !v.includes('-') && satisfies(v, range)).sort(compareVersions).pop();
        if (best) out.push({ name, version: best });
      } catch {
        /* skip */
      }
    }),
  );
  return out;
}

const OSV_SEV: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

async function osv(ecosystem: 'npm' | 'pypi', pkgs: DepPackage[], fetchImpl: Fetch): Promise<{ vulns: VulnerableDep[]; error?: string }> {
  const list = pkgs.slice(0, 1000);
  if (!list.length) return { vulns: [] };
  let batch: { results?: { vulns?: { id: string }[] }[] };
  try {
    const res = await fetchImpl('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: list.map((p) => ({ package: { name: p.name, ecosystem: ecosystem === 'npm' ? 'npm' : 'PyPI' }, version: p.version })) }),
    });
    if (!res.ok) return { vulns: [], error: `OSV returned HTTP ${res.status}` };
    batch = (await res.json()) as typeof batch;
  } catch (e) {
    return { vulns: [], error: `Could not reach OSV.dev: ${(e as Error).message}` };
  }
  const out: VulnerableDep[] = [];
  const hits: { p: DepPackage; id: string }[] = [];
  (batch.results ?? []).forEach((r, i) => r.vulns?.forEach((v) => hits.push({ p: list[i], id: v.id })));
  const details = new Map<string, { summary?: string; database_specific?: { severity?: string }; references?: { url: string }[] }>();
  for (const id of [...new Set(hits.map((h) => h.id))].slice(0, 60)) {
    try {
      const res = await fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
      if (res.ok) details.set(id, (await res.json()) as never);
    } catch {
      /* keep the id */
    }
  }
  for (const h of hits) {
    const d = details.get(h.id);
    out.push({ name: h.p.name, version: h.p.version, id: h.id, severity: OSV_SEV[d?.database_specific?.severity?.toUpperCase() ?? ''] ?? (h.id.startsWith('MAL-') ? 'critical' : 'medium'), summary: d?.summary ?? h.id, references: d?.references?.map((r) => r.url).slice(0, 3) });
  }
  return { vulns: out };
}

function summarize(ecosystem: 'npm' | 'pypi', scope: DepReport['scope'], pkgs: DepPackage[], vulns: VulnerableDep[], advisories: Advisory[], error?: string): DepReport {
  // Bundled/feed advisories apply to dependencies too (e.g. mcp-remote pulled in by another server).
  for (const p of pkgs) {
    for (const a of advisories) {
      if (a.ecosystem !== ecosystem || (ecosystem === 'pypi' ? normalizePypi(a.package) !== normalizePypi(p.name) : a.package !== p.name)) continue;
      if (a.malicious || inRange(p.version, a)) if (!vulns.some((v) => v.id === a.id && v.name === p.name)) vulns.push({ name: p.name, version: p.version, id: a.id, severity: a.malicious ? 'critical' : a.severity, summary: a.summary, references: a.references });
    }
  }
  const licenses: Record<string, number> = {};
  for (const p of pkgs) licenses[p.license ?? 'unknown'] = (licenses[p.license ?? 'unknown'] ?? 0) + 1;
  const licenseNotes: string[] = [];
  const copyleft = pkgs.filter((p) => p.license && COPYLEFT.test(p.license) && !/LGPL/i.test(p.license));
  if (copyleft.length) licenseNotes.push(`${copyleft.length} dependenc${copyleft.length === 1 ? 'y' : 'ies'} under a strong copyleft license (${[...new Set(copyleft.map((p) => p.license))].join(', ')}): ${copyleft.slice(0, 4).map((p) => p.name).join(', ')}`);
  const unknown = pkgs.filter((p) => !p.license);
  if (unknown.length && scope === 'installed') licenseNotes.push(`${unknown.length} dependenc${unknown.length === 1 ? 'y has' : 'ies have'} no declared license`);
  return { ecosystem, scope, total: pkgs.length, packages: pkgs.sort((a, b) => a.name.localeCompare(b.name)), vulnerable: vulns, licenses, licenseNotes, error };
}

/** Dependencies of an installed server, read from the environment it runs in. */
export async function installedDependencies(sourceDir: string, advisories: Advisory[], opts: { online?: boolean; fetchImpl?: Fetch } = {}): Promise<DepReport | undefined> {
  const r = installRoots(sourceDir);
  if (!r) return undefined;
  const map = new Map<string, DepPackage>();
  if (r.ecosystem === 'npm') await npmTree(r.root, map);
  else await pyEnv(r.root, map);
  // The server itself is not its own dependency.
  const pkgs = [...map.values()].filter((p) => p.name !== r.self);
  if (!pkgs.length) return undefined;
  const online = opts.online && opts.fetchImpl ? await osv(r.ecosystem, pkgs, opts.fetchImpl) : { vulns: [] as VulnerableDep[] };
  return summarize(r.ecosystem, 'installed', pkgs, online.vulns, advisories, online.error);
}

/** Dependencies of a downloaded (not installed) package. */
export async function checkDependencies(pkg: { ecosystem: 'npm' | 'pypi'; meta: Record<string, unknown> }, opts: { online?: boolean; fetchImpl?: Fetch; advisories?: Advisory[] } = {}): Promise<DepReport> {
  let pkgs: DepPackage[] = [];
  if (pkg.ecosystem === 'npm' && opts.online !== false && opts.fetchImpl) pkgs = await resolveDirect(pkg.meta, opts.fetchImpl);
  if (pkg.ecosystem === 'pypi') {
    const req = Array.isArray(pkg.meta.requires_dist) ? (pkg.meta.requires_dist as string[]).filter((r) => !/extra\s*==/.test(r)) : [];
    pkgs = req.map((r) => ({ name: normalizePypi(r.split(/[\s;<>=!~[(]/)[0]), version: '' })).filter((p) => p.name);
  }
  const withVersions = pkgs.filter((p) => p.version);
  const online = opts.online !== false && opts.fetchImpl ? await osv(pkg.ecosystem, withVersions, opts.fetchImpl) : { vulns: [] as VulnerableDep[] };
  return summarize(pkg.ecosystem, 'direct', pkgs, online.vulns, opts.advisories ?? [], online.error);
}
