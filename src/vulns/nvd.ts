import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Asset, Severity } from '../types.js';
import { checkable, firstAffected, versionCandidates, withTimeout, type Fetch, type OnlineResult, type VulnHit } from './index.js';
import { compareVersions, parseVersion, versionScheme as scheme } from './semver.js';

/**
 * NIST National Vulnerability Database lookup (CVE API 2.0).
 *
 * Every MCP package is searched by name. A CVE counts as *confirmed* only
 * when the package name appears in its description or in its CPE product
 * data; a match on a product-style phrase alone ("Filesystem MCP Server")
 * is reported as *possible* because many unrelated projects share names.
 * Affected versions come from CPE ranges first, then from phrases such as
 * "prior to 0.1.16" in the description.
 */

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const TTL_MS = 24 * 3600_000;

/** Only the fields we use are cached. */
export interface NvdCve {
  id: string;
  status?: string;
  description: string;
  cvss?: { score: number; severity?: string; version: string; vector?: string };
  cwe: string[];
  ranges: CpeRange[];
  references: string[];
}

export interface CpeRange {
  product: string;
  version?: string;
  startIncl?: string;
  startExcl?: string;
  endIncl?: string;
  endExcl?: string;
}

interface CacheFile {
  version: 1;
  entries: Record<string, { fetchedAt: number; cves: NvdCve[] }>;
}

export interface NvdOptions {
  apiKey?: string;
  cacheFile?: string;
  /** Injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  maxTerms?: number;
}

/* ---------- parsing ---------- */

interface RawCvss {
  type?: string;
  baseSeverity?: string;
  cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
}
interface RawCve {
  id: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, RawCvss[] | undefined>;
  weaknesses?: { description?: { lang: string; value: string }[] }[];
  configurations?: { nodes?: { cpeMatch?: RawCpeMatch[] }[] }[];
  references?: { url: string }[];
}
interface RawCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

export function parseNvd(body: unknown): NvdCve[] {
  const list = ((body as { vulnerabilities?: { cve: RawCve }[] })?.vulnerabilities ?? []).map((v) => v.cve).filter(Boolean);
  return list
    .filter((c) => c.vulnStatus !== 'Rejected')
    .map((c) => {
      let cvss: NvdCve['cvss'];
      for (const [key, version] of [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']] as const) {
        const ms = c.metrics?.[key];
        if (!ms?.length) continue;
        const m = ms.find((x) => x.type === 'Primary') ?? ms[0];
        if (m.cvssData?.baseScore === undefined) continue;
        cvss = { score: m.cvssData.baseScore, severity: m.cvssData.baseSeverity ?? m.baseSeverity, version, vector: m.cvssData.vectorString };
        break;
      }
      const ranges: CpeRange[] = [];
      for (const cfg of c.configurations ?? [])
        for (const node of cfg.nodes ?? [])
          for (const m of node.cpeMatch ?? []) {
            if (!m.vulnerable || !m.criteria) continue;
            const parts = m.criteria.split(':'); // cpe:2.3:a:vendor:product:version:...
            ranges.push({
              product: (parts[4] ?? '').toLowerCase(),
              version: parts[5] && parts[5] !== '*' && parts[5] !== '-' ? parts[5] : undefined,
              startIncl: m.versionStartIncluding,
              startExcl: m.versionStartExcluding,
              endIncl: m.versionEndIncluding,
              endExcl: m.versionEndExcluding,
            });
          }
      return {
        id: c.id,
        status: c.vulnStatus,
        description: c.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
        cvss,
        cwe: [...new Set((c.weaknesses ?? []).flatMap((w) => (w.description ?? []).map((d) => d.value)).filter((v) => v.startsWith('CWE-')))],
        ranges,
        references: (c.references ?? []).map((r) => r.url).slice(0, 5),
      };
    });
}

/* ---------- matching ---------- */

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const token = (s: string) => new RegExp(`(^|[^a-z0-9_/@.-])${esc(s.toLowerCase())}($|[^a-z0-9_-])`, 'i');
const unscoped = (name: string) => name.replace(/^@[^/]+\//, '');
const MCP_CONTEXT = /\b(mcp|model context protocol)\b/i;
/** "filesystem MCP server" as one phrase (or "MCP filesystem server"), not just the words somewhere in the text. */
function phrase(term: string): RegExp {
  const product = term.replace(/\s+MCP server$/i, '').split(/[\s_-]+/).map(esc).join('[\\s_-]+');
  return new RegExp(`\\b${product}[\\s_-]+(?:mcp[\\s_-]+)?server\\b|\\bmcp[\\s_-]+(?:server[\\s_-]+)?${product}\\b`, 'i');
}

/** Search terms for a package: its name(s), plus a product phrase for official `server-*` packages. */
export function searchTerms(name: string): { term: string; strength: 'strong' | 'weak' }[] {
  const out: { term: string; strength: 'strong' | 'weak' }[] = [{ term: unscoped(name), strength: 'strong' }];
  const m = unscoped(name).match(/^(?:mcp-)?server-(.+)$|^(.+)-mcp(?:-server)?$|^mcp-server-(.+)$/);
  const product = m?.[1] ?? m?.[2] ?? m?.[3];
  if (product) out.push({ term: `${product.replace(/[-_]/g, ' ')} MCP server`, strength: 'weak' });
  return out;
}

export function matchStrength(cve: NvdCve, name: string): 'strong' | 'weak' | undefined {
  const desc = cve.description;
  const short = unscoped(name);
  if (token(name).test(desc)) return 'strong';
  // Short names are only trusted when distinctive (contain "mcp") or the CVE is about MCP.
  if (short !== name && token(short).test(desc) && (short.includes('mcp') || MCP_CONTEXT.test(desc))) return 'strong';
  if (short === name && token(short).test(desc) && (short.includes('mcp') || MCP_CONTEXT.test(desc))) return 'strong';
  const products = new Set([short, short.replace(/-/g, '_')].map((x) => x.toLowerCase()));
  if (cve.ranges.some((r) => products.has(r.product)) && (short.includes('mcp') || MCP_CONTEXT.test(desc))) return 'strong';
  const t = searchTerms(name).find((x) => x.strength === 'weak');
  if (t && MCP_CONTEXT.test(desc) && phrase(t.term).test(desc)) {
    // NVD already tied this CVE to a different product: it is about that one, not this package.
    const named = cve.ranges.map((r) => r.product);
    if (named.length && !named.some((p) => products.has(p))) return undefined;
    return 'weak';
  }
  return undefined;
}


export function versionsFromDescription(desc: string, forVersion?: string): { fixed?: string; lastAffected?: string } {
  // A version, optionally followed by more: "0.6.4 or 2025.7.01", "1.2, 1.3 and 2.0".
  const V = String.raw`v?\d[\w.-]*`;
  const LIST = String.raw`(${V}(?:\s*(?:,|and|or)\s*${V})*)`;
  const grab = (re: RegExp) =>
    [...desc.matchAll(re)]
      .flatMap((m) => m[1].split(/\s*(?:,|\band\b|\bor\b)\s*/))
      .map((v) => v.replace(/^v/, '').replace(/[.,;)]+$/, ''))
      .filter((v) => parseVersion(v));
  const fixed = [
    ...grab(new RegExp(String.raw`\b(?:prior to|before|earlier than|below)\s+(?:versions?\s+)?${LIST}`, 'gi')),
    ...grab(new RegExp(String.raw`\b(?:fixed|patched|addressed|resolved|remediated)\s+in\s+(?:versions?\s+)?${LIST}`, 'gi')),
    ...grab(new RegExp(String.raw`\bupgrade\s+to\s+(?:versions?\s+)?${V.replace('v?', 'v?(')})`, 'gi')),
  ];
  const last = [
    ...grab(new RegExp(String.raw`\b(?:through|up to and including|up to)\s+(?:versions?\s+)?${LIST}`, 'gi')),
    ...grab(new RegExp(String.raw`\bversions?\s+(${V})\s+(?:and|or)\s+(?:earlier|below|prior|older)`, 'gi')),
  ];
  const pick = (vs: string[]) => {
    const same = forVersion ? vs.filter((v) => scheme(v) === scheme(forVersion)) : vs;
    return same.sort(compareVersions).pop();
  };
  return { fixed: pick(fixed), lastAffected: pick(last) };
}

/** true / false when the CVE's data says so for `version`, undefined when it can't tell. */
export function isAffected(cve: NvdCve, name: string, version: string): { affected?: boolean; fixed?: string } {
  const products = new Set([unscoped(name), unscoped(name).replace(/-/g, '_')].map((x) => x.toLowerCase()));
  const own = cve.ranges.filter((r) => products.has(r.product));
  const ranges = own.length ? own : cve.ranges.length && cve.ranges.every((r) => r.product === cve.ranges[0].product) ? cve.ranges : [];
  if (ranges.length) {
    const hit = ranges.some((r) => {
      if (r.version) return compareVersions(version, r.version) === 0;
      if (r.startIncl && compareVersions(version, r.startIncl) < 0) return false;
      if (r.startExcl && compareVersions(version, r.startExcl) <= 0) return false;
      if (r.endExcl && compareVersions(version, r.endExcl) >= 0) return false;
      if (r.endIncl && compareVersions(version, r.endIncl) > 0) return false;
      return !!(r.startIncl || r.startExcl || r.endExcl || r.endIncl);
    });
    const fixed = ranges.map((r) => r.endExcl).filter((v): v is string => !!v && scheme(v) === scheme(version)).sort(compareVersions).pop();
    return { affected: hit, fixed };
  }
  const d = versionsFromDescription(cve.description, version);
  if (d.fixed) return { affected: compareVersions(version, d.fixed) < 0, fixed: d.fixed };
  if (d.lastAffected) return { affected: compareVersions(version, d.lastAffected) <= 0 };
  return {};
}

function toSeverity(cvss?: NvdCve['cvss']): Severity {
  const s = cvss?.severity?.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  if (cvss) return cvss.score >= 9 ? 'critical' : cvss.score >= 7 ? 'high' : cvss.score >= 4 ? 'medium' : 'low';
  return 'medium';
}

/* ---------- fetching ---------- */

async function loadCache(file?: string): Promise<CacheFile> {
  if (!file) return { version: 1, entries: {} };
  try {
    const c = JSON.parse(await fs.readFile(file, 'utf8')) as CacheFile;
    if (c.version === 1 && c.entries) return c;
  } catch {
    /* empty cache */
  }
  return { version: 1, entries: {} };
}

async function saveCache(file: string | undefined, cache: CacheFile) {
  if (!file) return;
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(cache), { mode: 0o600 });
    await fs.rename(tmp, file);
  } catch {
    /* cache is an optimization */
  }
}

export async function checkNvd(assets: Asset[], fetchImpl: Fetch, opts: NvdOptions = {}): Promise<OnlineResult> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.now ?? Date.now;
  // NVD allows 5 requests per rolling 30 s without an API key, 50 with one.
  const spacing = opts.apiKey ? 700 : 6500;
  const cache = await loadCache(opts.cacheFile);

  const targets = assets.filter((a) => checkable(a.mcp?.package));
  const names = [...new Set(targets.map((a) => a.mcp!.package!.name))];
  const terms = [...new Set(names.flatMap((n) => searchTerms(n).map((t) => t.term)))].slice(0, opts.maxTerms ?? 40);

  let error: string | undefined;
  let first = true;
  for (const term of terms) {
    const hit = cache.entries[term];
    if (hit && now() - hit.fetchedAt < TTL_MS) continue;
    if (!first) await sleep(spacing);
    first = false;
    const url = `${API}?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=100`;
    const headers: Record<string, string> = opts.apiKey ? { apiKey: opts.apiKey } : {};
    try {
      let res = await withTimeout(20000, (signal) => fetchImpl(url, { headers, signal }));
      if (res.status === 403 || res.status === 429) {
        // Rate limited: wait out the window once.
        await sleep(30000);
        res = await withTimeout(20000, (signal) => fetchImpl(url, { headers, signal }));
      }
      if (!res.ok) {
        error = `NVD returned HTTP ${res.status}`;
        break;
      }
      cache.entries[term] = { fetchedAt: now(), cves: parseNvd(await res.json()) };
    } catch (e) {
      error = `Could not reach the NVD: ${(e as Error).message}`;
      break;
    }
  }
  await saveCache(opts.cacheFile, cache);

  const hits: VulnHit[] = [];
  for (const a of targets) {
    const p = a.mcp!.package!;
    const cves = new Map<string, NvdCve>();
    for (const t of searchTerms(p.name)) for (const c of cache.entries[t.term]?.cves ?? []) cves.set(c.id, c);
    const cands = versionCandidates(p);
    for (const cve of cves.values()) {
      const strength = matchStrength(cve, p.name);
      if (!strength) continue;
      const known = cands.map((c) => ({ ...c, r: isAffected(cve, p.name, c.version) }));
      const affected = firstAffected(known, (v) => known.find((k) => k.version === v)?.r.affected === true);
      const allUnaffected = known.length > 0 && known.every((k) => k.r.affected === false);
      if (allUnaffected) continue;
      const fixed = known.map((k) => k.r.fixed).find(Boolean) ?? versionsFromDescription(cve.description).fixed;
      const confirmed = strength === 'strong' && !!affected;
      hits.push({
        assetId: a.id,
        id: cve.id,
        aliases: [],
        severity: confirmed ? toSeverity(cve.cvss) : strength === 'strong' ? 'medium' : 'low',
        cvss: cve.cvss && { score: cve.cvss.score, version: cve.cvss.version, vector: cve.cvss.vector },
        malicious: false,
        summary: cve.description.length > 400 ? `${cve.description.slice(0, 397)}…` : cve.description,
        references: [`https://nvd.nist.gov/vuln/detail/${cve.id}`, ...cve.references.slice(0, 2)],
        version: affected?.version ?? 'any',
        versionSource: affected?.source ?? 'unknown',
        fixedVersion: fixed,
        source: 'nvd',
        confidence: confirmed ? 'confirmed' : 'possible',
        cwe: cve.cwe,
      });
    }
  }
  return { hits, packages: names.length, error };
}
