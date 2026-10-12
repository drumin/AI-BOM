import type { Asset, PackageRef, Severity } from '../types.js';
import { ADVISORIES, type Advisory } from './advisories.js';
import { compareVersions, fixedFor, inRange, parseVersion } from './semver.js';

/** Where the version we checked came from, i.e. how sure we are the call runs it. */
export type VersionSource = 'pinned' | 'installed' | 'latest' | 'unknown';

export interface VulnHit {
  assetId: string;
  id: string;
  aliases: string[];
  severity: Severity;
  cvss?: { score: number; version?: string; vector?: string };
  malicious: boolean;
  summary: string;
  references: string[];
  /** Version the call runs that is affected ("any" when unknown). */
  version: string;
  versionSource: VersionSource;
  /** First version that is not affected, when known. */
  fixedVersion?: string;
  source: 'bundled' | 'osv' | 'nvd';
  /** Every source that reported it (after merging). */
  sources?: ('bundled' | 'osv' | 'nvd')[];
  /** `possible` = matched by product description only; shown as "verify", never as critical. */
  confidence: 'confirmed' | 'possible';
  cwe?: string[];
}

export type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

export const checkable = (p?: PackageRef): p is PackageRef & { ecosystem: 'npm' | 'pypi' } =>
  !!p && (p.ecosystem === 'npm' || p.ecosystem === 'pypi') && !/^(git\+|https?:|\.|\/)/.test(p.name);

/**
 * The versions a call can actually run, most certain first:
 * an exact pin; otherwise copies cached on disk (npx/uvx may reuse them) and the latest release.
 */
export function versionCandidates(p: PackageRef): { version: string; source: VersionSource }[] {
  if (p.pinned && p.version && parseVersion(p.version)) return [{ version: p.version, source: 'pinned' }];
  const out: { version: string; source: VersionSource }[] = [];
  const installed = [...(p.installedVersions ?? [])].filter((v) => parseVersion(v)).sort(compareVersions);
  for (const v of installed) out.push({ version: v, source: 'installed' });
  if (p.latestVersion && !installed.includes(p.latestVersion)) out.push({ version: p.latestVersion, source: 'latest' });
  return out;
}

const SOURCE_RANK: Record<VersionSource, number> = { pinned: 0, installed: 1, latest: 2, unknown: 3 };

/** Pick the most relevant affected candidate: pinned, then an installed copy, then latest. */
export function firstAffected(
  cands: { version: string; source: VersionSource }[],
  isAffected: (v: string) => boolean | undefined,
): { version: string; source: VersionSource } | undefined {
  return [...cands].sort((a, b) => SOURCE_RANK[a.source] - SOURCE_RANK[b.source]).find((c) => isAffected(c.version));
}

/** Offline check against the bundled advisory list. */
export function checkBundled(assets: Asset[], advisories: Advisory[] = ADVISORIES): VulnHit[] {
  const hits: VulnHit[] = [];
  for (const a of assets) {
    const p = a.mcp?.package;
    if (!checkable(p)) continue;
    const cands = versionCandidates(p);
    for (const adv of advisories) {
      if (adv.ecosystem !== p.ecosystem || adv.package !== p.name) continue;
      const hit = firstAffected(cands, (v) => inRange(v, adv));
      // Without any known version only malicious packages are reported: every
      // release after the takeover is affected and they are pulled from registries.
      if (!hit && !(cands.length === 0 && adv.malicious)) continue;
      hits.push({
        assetId: a.id,
        id: adv.id,
        aliases: [],
        severity: adv.severity,
        cvss: adv.cvss,
        malicious: !!adv.malicious,
        summary: adv.summary,
        references: adv.references,
        version: hit?.version ?? 'any',
        versionSource: hit?.source ?? 'unknown',
        fixedVersion: fixedFor(adv.fixed, hit?.version ?? p.latestVersion ?? p.installedVersions?.[0]),
        source: 'bundled',
        confidence: 'confirmed',
      });
    }
  }
  return hits;
}

export async function withTimeout<T>(ms: number, fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fn(ctl.signal);
  } finally {
    clearTimeout(t);
  }
}

/**
 * The version `npx pkg` / `uvx pkg` would fetch today: the latest release.
 * Returns null when the package no longer exists (typical for removed malware).
 */
export async function resolveLatest(p: PackageRef, fetchImpl: Fetch): Promise<string | null | undefined> {
  const url =
    p.ecosystem === 'npm'
      ? `https://registry.npmjs.org/${p.name.replace('/', '%2f')}/latest`
      : `https://pypi.org/pypi/${encodeURIComponent(p.name)}/json`;
  try {
    const res = await withTimeout(8000, (signal) => fetchImpl(url, { signal }));
    if (res.status === 404) return null;
    if (!res.ok) return undefined;
    const body = (await res.json()) as { version?: string; info?: { version?: string } };
    return p.ecosystem === 'npm' ? body.version : body.info?.version;
  } catch {
    return undefined;
  }
}

/** Fill in `latestVersion` for every unpinned npm/PyPI package. */
export async function resolveLatestVersions(assets: Asset[], fetchImpl: Fetch): Promise<void> {
  await Promise.all(
    assets.map(async (a) => {
      const p = a.mcp?.package;
      if (!checkable(p) || p.pinned) return;
      const latest = await resolveLatest(p, fetchImpl);
      if (latest) p.latestVersion = latest;
    }),
  );
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  references?: { url: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: { ranges?: { type: string; events: { introduced?: string; fixed?: string }[] }[] }[];
}

function osvSeverity(v: OsvVuln): Severity {
  if (v.id.startsWith('MAL-')) return 'critical';
  const s = v.database_specific?.severity?.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'medium';
}

function osvFixed(v: OsvVuln): string | undefined {
  const fixed = (v.affected ?? []).flatMap((a) => a.ranges ?? []).flatMap((r) => r.events).map((e) => e.fixed).filter(Boolean) as string[];
  return fixed.sort(compareVersions).pop();
}

export interface OnlineResult {
  hits: VulnHit[];
  packages: number;
  error?: string;
}

/** OSV.dev lookup for every version a call can run. Only names and versions are sent. */
export async function checkOsv(assets: Asset[], fetchImpl: Fetch): Promise<OnlineResult> {
  const queries: { asset: Asset; version?: string; source: VersionSource; body: Record<string, unknown> }[] = [];
  for (const a of assets) {
    const p = a.mcp?.package;
    if (!checkable(p)) continue;
    const pkg = { name: p.name, ecosystem: p.ecosystem === 'npm' ? 'npm' : 'PyPI' };
    const cands = versionCandidates(p);
    if (!cands.length) queries.push({ asset: a, source: 'unknown', body: { package: pkg } });
    for (const c of cands) queries.push({ asset: a, version: c.version, source: c.source, body: { package: pkg, version: c.version } });
  }
  const packages = new Set(queries.map((q) => q.asset.id)).size;
  if (!queries.length) return { hits: [], packages: 0 };

  let batch: { results?: { vulns?: { id: string }[] }[] };
  try {
    const res = await withTimeout(15000, (signal) =>
      fetchImpl('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: queries.map((q) => q.body) }),
        signal,
      }),
    );
    if (!res.ok) return { hits: [], packages, error: `OSV returned HTTP ${res.status}` };
    batch = (await res.json()) as typeof batch;
  } catch (e) {
    return { hits: [], packages, error: `Could not reach OSV.dev: ${(e as Error).message}` };
  }

  const ids = new Set<string>();
  (batch.results ?? []).forEach((r) => r.vulns?.forEach((v) => ids.add(v.id)));
  const details = new Map<string, OsvVuln>();
  const idList = [...ids].slice(0, 200);
  for (let i = 0; i < idList.length; i += 8) {
    await Promise.all(
      idList.slice(i, i + 8).map(async (id) => {
        try {
          const res = await withTimeout(10000, (signal) => fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal }));
          if (res.ok) details.set(id, (await res.json()) as OsvVuln);
        } catch {
          /* keep the id without details */
        }
      }),
    );
  }

  const hits: VulnHit[] = [];
  (batch.results ?? []).forEach((r, i) => {
    const q = queries[i];
    for (const { id } of r.vulns ?? []) {
      const v = details.get(id) ?? { id };
      hits.push({
        assetId: q.asset.id,
        id,
        aliases: v.aliases ?? [],
        severity: osvSeverity(v),
        malicious: id.startsWith('MAL-'),
        summary: v.summary ?? v.details?.split('\n')[0] ?? 'Known vulnerability',
        references: [`https://osv.dev/vulnerability/${id}`, ...(v.references ?? []).slice(0, 3).map((x) => x.url)],
        version: q.version ?? 'any',
        versionSource: q.source,
        fixedVersion: osvFixed(v),
        source: 'osv',
        confidence: 'confirmed',
        cwe: v.database_specific?.cwe_ids,
      });
    }
  });
  return { hits, packages };
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Merge hits from all sources into one per (asset, vulnerability). The same
 * issue reported by the bundled list, OSV (GHSA id + CVE alias) and NVD
 * (CVE id) becomes one finding carrying the best data from each.
 */
export function mergeHits(...sources: VulnHit[][]): VulnHit[] {
  const groups: VulnHit[][] = [];
  const keyToGroup = new Map<string, number>();
  for (const h of sources.flat()) {
    const keys = [h.id, ...h.aliases].map((k) => `${h.assetId}|${k.toUpperCase()}`);
    let gi = keys.map((k) => keyToGroup.get(k)).find((x) => x !== undefined);
    if (gi === undefined) {
      gi = groups.length;
      groups.push([]);
    }
    groups[gi].push(h);
    for (const k of keys) keyToGroup.set(k, gi);
  }
  return groups.map((g) => {
    const by = (s: VulnHit['source']) => g.find((h) => h.source === s);
    const primary = by('bundled') ?? by('osv') ?? g[0];
    const best = [...g].sort((a, b) => SOURCE_RANK[a.versionSource] - SOURCE_RANK[b.versionSource])[0];
    const cve = [primary.id, ...g.flatMap((h) => [h.id, ...h.aliases])].find((x) => x.startsWith('CVE-'));
    return {
      ...primary,
      // Lead with the CVE id people search for; keep the others as aliases.
      id: cve ?? primary.id,
      aliases: [...new Set(g.flatMap((h) => [h.id, ...h.aliases]))].filter((x) => x !== (cve ?? primary.id)),
      severity: g.map((h) => h.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0],
      cvss: by('nvd')?.cvss ?? g.find((h) => h.cvss)?.cvss,
      malicious: g.some((h) => h.malicious),
      references: [...new Set(g.flatMap((h) => h.references))].slice(0, 6),
      version: best.version,
      versionSource: best.versionSource,
      fixedVersion: g.map((h) => h.fixedVersion).find(Boolean),
      confidence: g.some((h) => h.confidence === 'confirmed') ? 'confirmed' : 'possible',
      cwe: [...new Set(g.flatMap((h) => h.cwe ?? []))],
      sources: [...new Set(g.map((h) => h.source))],
    };
  });
}
