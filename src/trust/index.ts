import type { Collector } from '../collector.js';
import type { Asset, TrustInfo } from '../types.js';
import type { Findings } from '../checks/index.js';
import { checkable, type Fetch } from '../vulns/index.js';
import { normalizePypi } from '../vulns/installed.js';
import { shortHash } from '../util/hash.js';
import { readJsonFile, writeJsonFile } from '../util/store.js';

/**
 * Trust signals for the packages MCP servers run.
 *
 * Offline:  lookalike (typosquat) names, and "rug pulls": tool descriptions
 *           that changed since the last scan.
 * Online:   npm / PyPI metadata (age, maintainers, source repository, build
 *           provenance, install scripts, deprecation, license) and whether
 *           the server is listed in the official MCP Registry. Only package
 *           names are sent.
 */

/** Widely used MCP packages; a name one or two edits away from one of these is suspicious. */
export const WELL_KNOWN = [
  '@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-gitlab', '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-slack', '@modelcontextprotocol/server-memory', '@modelcontextprotocol/server-puppeteer', '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-google-maps', '@modelcontextprotocol/server-everything', '@modelcontextprotocol/server-sequential-thinking', '@modelcontextprotocol/server-gdrive',
  '@modelcontextprotocol/server-sentry', '@modelcontextprotocol/inspector', '@playwright/mcp', '@upstash/context7-mcp', '@notionhq/notion-mcp-server',
  '@sentry/mcp-server', '@stripe/mcp', '@supabase/mcp-server-supabase', '@cloudflare/mcp-server-cloudflare', '@anthropic-ai/claude-code', '@browserbasehq/mcp',
  'mcp-remote', 'firecrawl-mcp', 'exa-mcp-server', 'tavily-mcp', 'figma-developer-mcp', '@wonderwhy-er/desktop-commander', '@executeautomation/playwright-mcp-server',
  'mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite', 'mcp-server-qdrant', 'awslabs.core-mcp-server', 'mcp-atlassian', 'mcp-server-kubernetes',
  'postmark-mcp', 'github-mcp-server', 'linear-mcp-server', 'mcp-obsidian',
];

export function levenshtein(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

export function lookalike(name: string): string | undefined {
  const n = name.toLowerCase();
  if (WELL_KNOWN.includes(n)) return undefined;
  for (const w of WELL_KNOWN) {
    if (n.length < 6) continue;
    const d = levenshtein(n, w, 2);
    if (d > 0 && d <= (w.length > 12 ? 2 : 1)) return w;
    // Same package name under a different scope: @modelcontextprotoco1/server-github
    const [ws, wn] = w.startsWith('@') ? w.split('/') : ['', w];
    const [ns, nn] = n.startsWith('@') ? n.split('/') : ['', n];
    if (ws && ns && wn === nn && ns !== ws && levenshtein(ns, ws, 3) <= 3) return w;
  }
  return undefined;
}

/* ---------------- Rug pulls ---------------- */

interface ToolHashes {
  version: 1;
  servers: Record<string, Record<string, string>>;
}

export async function checkToolChanges(col: Collector, f: Findings, file: string): Promise<void> {
  const stored = (await readJsonFile<ToolHashes>(file)) ?? { version: 1, servers: {} };
  const next: ToolHashes = { version: 1, servers: { ...stored.servers } };
  for (const a of col.assets.values()) {
    const tools = a.mcp?.tools;
    if (a.kind !== 'mcp-server' || !tools?.length) continue;
    const now = Object.fromEntries(tools.map((t) => [t.name, shortHash(t.name, t.description ?? '')]));
    const before = stored.servers[a.id];
    next.servers[a.id] = now;
    if (!before) continue;
    const changed = Object.keys(now).filter((n) => before[n] && before[n] !== now[n]);
    const added = Object.keys(now).filter((n) => !before[n]);
    if (!changed.length && !added.length) continue;
    const list = [...changed.map((n) => `${n} (description changed)`), ...added.map((n) => `${n} (new)`)];
    a.trust = { ...(a.trust ?? { level: 'unknown', notes: [] }), toolsChanged: list };
    f.add('TRUST-TOOLS-CHANGED', changed.length ? 'medium' : 'low', { asset: a, location: a.occurrences[0]?.source, evidence: list.slice(0, 6).join(', ') });
  }
  try {
    await writeJsonFile(file, next);
  } catch {
    /* read-only home: skip */
  }
}

/* ---------------- Registry metadata ---------------- */

interface NpmDoc {
  time?: Record<string, string>;
  maintainers?: unknown[];
  repository?: { url?: string } | string;
  license?: string;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, { scripts?: Record<string, string>; deprecated?: string; license?: string; dist?: { attestations?: unknown }; repository?: { url?: string } | string }>;
}

async function npmTrust(name: string, version: string | undefined, fetchImpl: Fetch): Promise<Partial<TrustInfo> | undefined> {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/json' } });
  if (!res.ok) return undefined;
  const d = (await res.json()) as NpmDoc;
  const v = version && d.versions?.[version] ? version : d['dist-tags']?.latest;
  const meta = v ? d.versions?.[v] : undefined;
  const repo = meta?.repository ?? d.repository;
  const scripts = Object.keys(meta?.scripts ?? {}).filter((s) => ['preinstall', 'install', 'postinstall'].includes(s));
  return {
    createdAt: d.time?.created,
    lastPublishAt: v ? d.time?.[v] : d.time?.modified,
    maintainers: Array.isArray(d.maintainers) ? d.maintainers.length : undefined,
    repository: typeof repo === 'string' ? repo : repo?.url?.replace(/^git\+/, '').replace(/\.git$/, ''),
    license: meta?.license ?? d.license,
    provenance: !!meta?.dist?.attestations,
    installScripts: scripts.length ? scripts : undefined,
    deprecated: meta?.deprecated,
  };
}

async function pypiTrust(name: string, fetchImpl: Fetch): Promise<Partial<TrustInfo> | undefined> {
  const res = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(normalizePypi(name))}/json`);
  if (!res.ok) return undefined;
  const d = (await res.json()) as { info?: { license?: string; project_urls?: Record<string, string>; home_page?: string; yanked?: boolean; yanked_reason?: string }; releases?: Record<string, { upload_time_iso_8601?: string }[]>; urls?: { upload_time_iso_8601?: string }[] };
  const times = Object.values(d.releases ?? {}).flat().map((r) => r.upload_time_iso_8601).filter((t): t is string => !!t).sort();
  const urls = d.info?.project_urls ?? {};
  const repo = Object.entries(urls).find(([k, u]) => /source|repo|code|github|gitlab/i.test(k) || /github\.com|gitlab\.com/.test(u))?.[1] ?? (/(github|gitlab)\.com/.test(d.info?.home_page ?? '') ? d.info?.home_page : undefined);
  return {
    createdAt: times[0],
    lastPublishAt: d.urls?.[0]?.upload_time_iso_8601 ?? times[times.length - 1],
    repository: repo,
    license: d.info?.license || undefined,
    deprecated: d.info?.yanked ? d.info.yanked_reason || 'yanked' : undefined,
  };
}

interface RegistryServer {
  server?: { name?: string; repository?: { url?: string }; packages?: { registryType?: string; registry_type?: string; identifier?: string; name?: string }[]; remotes?: { url?: string }[] };
}

async function registryListing(a: Asset, fetchImpl: Fetch): Promise<TrustInfo['officialRegistry']> {
  const p = a.mcp?.package;
  // A local proxy (mcp-remote) is judged by the server it connects to.
  const remote = a.mcp?.remoteUrl ?? a.mcp?.url;
  const remoteHost = remote ? new URL(remote).hostname : undefined;
  const terms = new Set<string>();
  if (remoteHost) terms.add(remoteHost.split('.').slice(-2, -1)[0]);
  if (!remoteHost && p && checkable(p)) {
    const [scope, bare] = p.name.startsWith('@') ? [p.name.slice(1).split('/')[0], p.name.split('/')[1]] : ['', p.name];
    if (!/^(mcp|server|mcp-server)$/.test(bare)) terms.add(bare);
    if (scope) terms.add(scope);
  }
  for (const term of [...terms].slice(0, 2)) {
    const res = await fetchImpl(`https://registry.modelcontextprotocol.io/v0/servers?search=${encodeURIComponent(term)}&limit=100`);
    if (!res.ok) continue;
    const d = (await res.json()) as { servers?: RegistryServer[] };
    for (const s of d.servers ?? []) {
      const srv = s.server;
      if (!srv?.name) continue;
      const pkgMatch = !remoteHost && p && srv.packages?.some((x) => (x.identifier ?? x.name)?.toLowerCase() === p.name.toLowerCase());
      const remoteMatch = remoteHost && srv.remotes?.some((r) => {
        try {
          return !!r.url && new URL(r.url).hostname === remoteHost;
        } catch {
          return false;
        }
      });
      if (pkgMatch || remoteMatch) return { name: srv.name, url: srv.repository?.url };
    }
  }
  return undefined;
}

const DAY = 86_400_000;

function level(t: TrustInfo): TrustInfo['level'] {
  if (t.lookalikeOf || t.deprecated) return 'poor';
  const bad = [t.installScripts?.length, t.createdAt && Date.now() - Date.parse(t.createdAt) < 30 * DAY, t.repository === undefined && t.createdAt, t.toolsChanged?.length].filter(Boolean).length;
  const good = [t.officialRegistry, t.provenance, t.repository, (t.maintainers ?? 0) > 1, t.createdAt && Date.now() - Date.parse(t.createdAt) > 180 * DAY].filter(Boolean).length;
  if (bad >= 2) return 'poor';
  if (bad === 1) return 'mixed';
  return good >= 2 ? 'good' : good ? 'mixed' : 'unknown';
}

export async function assessTrust(col: Collector, f: Findings, opts: { online?: boolean; fetchImpl?: Fetch }): Promise<string[]> {
  const errors: string[] = [];
  const jobs: Promise<void>[] = [];
  for (const a of col.assets.values()) {
    if (a.kind !== 'mcp-server' || !a.mcp) continue;
    const p = a.mcp.package;
    const t: TrustInfo = { ...(a.trust ?? { level: 'unknown', notes: [] }), notes: [...(a.trust?.notes ?? [])] };
    if (checkable(p)) {
      const look = lookalike(p.name);
      if (look) {
        t.lookalikeOf = look;
        f.add('TRUST-TYPOSQUAT', 'high', { asset: a, location: a.occurrences[0]?.source, evidence: `${p.name} ≈ ${look}` });
      }
    }
    a.trust = t;
    if (!opts.online || !opts.fetchImpl) continue;
    const fetchImpl = opts.fetchImpl;
    jobs.push(
      (async () => {
        try {
          const meta = checkable(p) ? (p.ecosystem === 'npm' ? await npmTrust(p.name, p.pinned ? p.version : undefined, fetchImpl) : await pypiTrust(p.name, fetchImpl)) : undefined;
          if (meta) Object.assign(t, meta);
          if (checkable(p) || a.mcp!.url || a.mcp!.remoteUrl) t.officialRegistry = await registryListing(a, fetchImpl).catch(() => undefined);
        } catch (e) {
          errors.push(`Trust lookup for ${a.name}: ${(e as Error).message}`);
        }
        const loc = a.occurrences[0]?.source;
        if (t.installScripts?.length) f.add('TRUST-INSTALL-SCRIPTS', 'medium', { asset: a, location: loc, evidence: `${p!.name}: ${t.installScripts.join(', ')}` });
        if (t.createdAt && Date.now() - Date.parse(t.createdAt) < 30 * DAY) f.add('TRUST-NEW-PACKAGE', 'medium', { asset: a, location: loc, evidence: `${p!.name}: first published ${t.createdAt.slice(0, 10)}` });
        if (t.deprecated) f.add('TRUST-DEPRECATED', 'medium', { asset: a, location: loc, evidence: `${p!.name}: ${t.deprecated.slice(0, 140)}` });
        if (checkable(p) && meta_hasNoRepo(t)) f.add('TRUST-NO-REPO', 'low', { asset: a, location: loc, evidence: p.name });
      })(),
    );
  }
  await Promise.all(jobs);
  for (const a of col.assets.values()) {
    if (!a.trust) continue;
    const t = a.trust;
    t.notes = [
      t.officialRegistry && `Listed in the official MCP Registry as ${t.officialRegistry.name} (the publisher proved they own that name)`,
      t.provenance && 'Published with build provenance',
      t.maintainers !== undefined && `${t.maintainers} maintainer${t.maintainers === 1 ? '' : 's'}`,
      t.createdAt && `First published ${t.createdAt.slice(0, 10)}`,
      t.lastPublishAt && `This version published ${t.lastPublishAt.slice(0, 10)}`,
      t.license && `License: ${t.license}`,
      t.lookalikeOf && `Name looks like ${t.lookalikeOf}`,
      t.installScripts?.length && `Runs install scripts: ${t.installScripts.join(', ')}`,
      t.deprecated && `Deprecated: ${t.deprecated}`,
      t.toolsChanged?.length && `Tools changed since last scan: ${t.toolsChanged.join(', ')}`,
    ].filter((x): x is string => typeof x === 'string');
    t.level = level(t);
    if (t.level === 'unknown' && !t.notes.length) delete a.trust;
  }
  return errors;
}

const meta_hasNoRepo = (t: TrustInfo) => t.createdAt !== undefined && !t.repository;
