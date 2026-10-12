import os from 'node:os';
import path from 'node:path';
import { promises as fs, realpathSync } from 'node:fs';
import { Collector, defaultContext, type ScanContext } from './collector.js';
import { Findings, rollupRisk, runChecks } from './checks/index.js';
import { analyzeTools } from './analysis/tools.js';
import { addAutoCommands, explainHooks, scanTelemetry } from './analysis/hooks.js';
import { analyzeReach } from './analysis/reach.js';
import { checkShadowing } from './analysis/shadowing.js';
import { analyzeEndpoint, liveEndpoint, type EndpointReader } from './analysis/endpoint.js';
import { contextCost } from './analysis/context.js';
import { installedDependencies } from './deps.js';
import { loadInspections } from './inspect.js';
import { assessTrust, checkToolChanges } from './trust/index.js';
import { feedAgeHours, loadCachedFeed, mergeAdvisories, updateFeed, type BytesFetch } from './feed/index.js';
import { applySessions, readSessions } from './sessions.js';
import { applyTriage, loadTriage } from './triage.js';
import { fixKindsFor } from './fix/index.js';
import { PROJECT_MARKERS, scanners } from './scanners/index.js';
import { applyUsage } from './scanners/claude-code.js';
import { addSkillFolder } from './scanners/common.js';
import type { Asset, Inventory } from './types.js';
import { discoverProjects, isDir, isObject, mtime, readStructured } from './util/fs.js';
import { DEFAULT_CONNECTORS_FILE, loadConnectors } from './connectors.js';
import { checkable, checkBundled, checkOsv, mergeHits, resolveLatestVersions, type Fetch, type VulnHit } from './vulns/index.js';
import { checkNvd } from './vulns/nvd.js';
import { indexInstalled, installedVersions } from './vulns/installed.js';
import { dataDir } from './util/store.js';
import { recordScan } from './state.js';
import { computeScore } from './score.js';
import { redactArgs, redactRecord, redactText, redactUrl } from './util/secrets.js';

export const VERSION = '0.3.0';

/** The standing blind spots, plus whatever this scan switched off. */
function coverageGaps(found: { what: string; why: string }[], opts: ScanOptions, unreadable: number): { what: string; why: string }[] {
  const gaps = [...found];
  if (unreadable) gaps.push({ what: `${unreadable} config file${unreadable === 1 ? '' : 's'}`, why: 'They exist but could not be read (permissions or a syntax error), so what they hold is not in this inventory.' });
  if (opts.sessionLogs === false) gaps.push({ what: 'Agent session logs', why: 'Turned off for this scan, so usage, activity and the checks on what tools were called with were skipped.' });
  if (opts.toolAnalysis === false) gaps.push({ what: 'Tool code analysis', why: 'Turned off for this scan, so tools were not compared with what their code does.' });
  if (!opts.online) gaps.push({ what: 'Online vulnerability and publisher lookups', why: 'Off by default so package names stay on this computer. Only bundled advisories were checked; run with --online to add the rest.' });
  gaps.push(
    { what: 'Containers, WSL and other computers', why: 'AI-BOM reads this computer’s own files and processes. An agent inside a container, a WSL distribution or a remote machine has its own home folder and is not seen.' },
    { what: 'Cloud-hosted and scheduled agents', why: 'Agents that run in the cloud or on a schedule leave nothing here except what their apps store, so they only appear if you register them as connectors.' },
  );
  return gaps;
}

export interface ScanOptions {
  home?: string;
  platform?: NodeJS.Platform;
  systemRoot?: string;
  /** Explicit project directories to scan. */
  projects?: string[];
  /** Directories to sweep for projects containing AI config. */
  discover?: string[];
  /** Also scan projects Claude Code remembers in ~/.claude.json (default true). */
  knownProjects?: boolean;
  /** Claude Code config dir override ($CLAUDE_CONFIG_DIR). */
  claudeConfigDir?: string;
  /** Include the list of every location checked (for `ai-bom doctor`). */
  trace?: boolean;
  /** Also sweep common code folders (~/Projects, ~/code, ~/Developer…) for projects with AI config. */
  autoDiscover?: boolean;
  /** Where the previous scan is stored for "new since last scan"; undefined disables history. */
  historyFile?: string;
  /** Compare with the history file without overwriting it (dashboard rescans). */
  historyReadOnly?: boolean;
  /** Keep absolute home paths instead of rewriting them to "~". */
  keepHomePaths?: boolean;
  /** Registry of cloud connectors; undefined disables it. */
  connectorsFile?: string;
  /** Query OSV.dev and package registries for known vulnerabilities (sends package names + versions only). */
  online?: boolean;
  /** Injectable fetch for tests. */
  fetchImpl?: Fetch;
  /** NVD API key (optional; raises the rate limit from 5 to 50 requests / 30 s). */
  nvdApiKey?: string;
  /** Where NVD responses are cached for 24 h; undefined disables the cache. */
  nvdCacheFile?: string;
  /** Injectable delay for tests (NVD rate limiting). */
  sleep?: (ms: number) => Promise<void>;
  /** Triage decisions (accept / snooze / false positive); undefined disables triage. */
  triageFile?: string;
  /** Read Claude Code session logs for usage and the tool-call audit (default true). */
  sessionLogs?: boolean;
  /**
   * Read the running processes and open ports. By default this happens only when scanning this computer's own
   * home folder, since a scan of another home would be mixed with the live state of this machine.
   */
  endpoint?: EndpointReader | false;
  /** Read MCP servers' code on disk to compare each tool with its description (default true). */
  toolAnalysis?: boolean;
  /** Scan only `projects` (pre-flight checks): no user-level config, connectors, logs or history. */
  projectOnly?: boolean;
  /** Skill folders (holding SKILL.md) outside the usual locations, scanned as part of a project (pre-flight checks). */
  extraSkillDirs?: { dir: string; project: string }[];
  /** Use the signed advisory feed cached in ~/.ai-bom/feed (default true); with --online it is refreshed daily. */
  feed?: boolean;
  /** Injectable fetch for feed downloads (tests). */
  feedFetch?: BytesFetch;
  /** Append a counts-only summary of this scan to the scan history, labelled with this source. */
  recordAs?: string;
  /** Where tool-description hashes are kept to spot servers that change their tools ("rug pulls"). */
  toolHashesFile?: string;
}

export { DEFAULT_CONNECTORS_FILE };
export const DEFAULT_NVD_CACHE = path.join(dataDir(), 'cache', 'nvd.json');

export const DEFAULT_HISTORY_FILE = path.join(dataDir(), 'last-scan.json');

/** Folders people commonly keep repositories in; swept with `autoDiscover` (depth 3). */
export const AUTO_DISCOVER_DIRS = ['Projects', 'projects', 'code', 'Code', 'dev', 'Developer', 'src', 'repos', 'git', 'GitHub', 'workspace', 'Workspace', 'work'];
const MAX_PROJECTS = 1000;

async function resolveProjects(ctx: ScanContext, opts: ScanOptions): Promise<string[]> {
  const set = new Set<string>();
  for (const p of opts.projects ?? []) set.add(path.resolve(p));
  for (const root of opts.discover ?? []) {
    for (const p of await discoverProjects(path.resolve(root), PROJECT_MARKERS)) set.add(p);
  }
  if (opts.knownProjects !== false && !opts.projectOnly) {
    try {
      const state = await readStructured(ctx.claudeState);
      if (isObject(state) && isObject(state.projects)) for (const p of Object.keys(state.projects)) set.add(p);
    } catch {
      /* reported by the Claude Code scanner */
    }
  }
  if (opts.autoDiscover && !opts.projectOnly) {
    // On a case-insensitive disk (macOS default) `Projects` and `projects` are the same folder: sweep it once.
    const swept = new Set<string>();
    for (const dir of AUTO_DISCOVER_DIRS) {
      const root = path.join(ctx.home, dir);
      if (!(await isDir(root))) continue;
      let canonical = root;
      try {
        canonical = realpathSync.native(root);
      } catch {
        /* keep the plain path */
      }
      if (swept.has(canonical)) continue;
      swept.add(canonical);
      for (const p of await discoverProjects(root, PROJECT_MARKERS, 3)) set.add(p);
    }
  }
  // Home is also a project: Claude Code run from ~ reads ~/.mcp.json and ~/CLAUDE.md as project config.
  // The collector drops home-project entries that duplicate user-level config.
  if (!opts.projectOnly) set.add(ctx.home);
  const out: string[] = [];
  for (const p of set) if (await isDir(p)) out.push(p);
  return out.sort().slice(0, MAX_PROJECTS);
}

export async function scan(opts: ScanOptions = {}): Promise<Inventory> {
  const ctx = defaultContext({ home: opts.home, platform: opts.platform, systemRoot: opts.systemRoot, claudeConfigDir: opts.claudeConfigDir });
  ctx.projects = await resolveProjects(ctx, opts);
  const col = new Collector(ctx);

  for (const s of opts.projectOnly ? [] : scanners) {
    try {
      await s.scanUser?.(col);
    } catch (e) {
      col.error(s.id, `Scanner failed: ${(e as Error).message}`);
    }
  }
  for (const x of opts.extraSkillDirs ?? []) {
    col.project(x.project);
    await addSkillFolder(col, x.dir, { client: 'generic', scope: 'project', project: x.project });
    col.client('generic', 'Cross-tool (AGENTS.md)');
  }
  for (const dir of ctx.projects) {
    col.project(dir);
    for (const s of scanners) {
      try {
        await s.scanProject?.(col, dir);
      } catch (e) {
        col.error(dir, `${s.id} scanner failed: ${(e as Error).message}`);
      }
    }
  }
  if (opts.connectorsFile && !opts.projectOnly) await addCloudConnectors(col, opts.connectorsFile);
  addAutoCommands(col);
  const early = new Findings();
  if (!opts.projectOnly) await scanTelemetry(col, early);
  col.finalizeChildren();
  applyUsage(col);
  await stampModified(col);

  // Known vulnerabilities. What version does each call really run? An exact pin,
  // or for unpinned calls the copies cached on disk (offline) and the latest release (online).
  const assetList = [...col.assets.values()];
  const installed = await indexInstalled(ctx.home);
  for (const a of assetList) {
    const p = a.mcp?.package;
    if (checkable(p) && !p.pinned) {
      const v = installedVersions(installed, p.ecosystem, p.name);
      if (v.length) p.installedVersions = v;
    }
  }
  let feedError: string | undefined;
  if (opts.online && opts.feed !== false) {
    const age = await feedAgeHours();
    if (age === undefined || age > 24) {
      const r = await updateFeed(opts.feedFetch);
      if (r.status === 'error') feedError = r.message;
    }
  }
  const feed = opts.feed === false ? undefined : await loadCachedFeed();
  const advisories = mergeAdvisories(feed);
  let vulnHits: VulnHit[];
  let vulnCheck: Inventory['vulnCheck'];
  if (opts.online) {
    const fetchImpl = opts.fetchImpl ?? (fetch as unknown as Fetch);
    await resolveLatestVersions(assetList, fetchImpl);
    const [osv, nvd] = await Promise.all([
      checkOsv(assetList, fetchImpl),
      checkNvd(assetList, fetchImpl, { apiKey: opts.nvdApiKey, cacheFile: opts.nvdCacheFile, sleep: opts.sleep }),
    ]);
    vulnHits = mergeHits(checkBundled(assetList, advisories), osv.hits, nvd.hits);
    vulnCheck = {
      checkedAt: new Date().toISOString(),
      packages: Math.max(osv.packages, nvd.packages),
      sources: ['OSV.dev', 'NVD'],
      errors: [osv.error, nvd.error, feedError].filter((e): e is string => !!e),
    };
  } else {
    vulnHits = checkBundled(assetList, advisories);
  }
  // Behavior analysis: each tool's code vs. its description, and what the session logs show.
  const f = early;
  if (opts.toolAnalysis !== false) await analyzeTools(col, f, (p) => p);
  await explainHooks(col, f);
  // Results of sandboxed live inspections the user ran (ai-bom inspect).
  const inspections = await loadInspections();
  for (const a of col.assets.values()) {
    const r = inspections[a.id];
    if (!r || !a.mcp) continue;
    a.mcp.live = { at: r.at, sandbox: r.sandbox, ok: r.ok, error: r.error, tools: r.tools.length, liveOnly: r.liveOnly, changedDescriptions: r.changedDescriptions, networkAttempts: r.networkAttempts };
    const known = new Set((a.mcp.tools ?? []).map((t) => t.name));
    const hadStatic = known.size > 0;
    for (const t of r.tools) if (!known.has(t.name)) (a.mcp.tools ??= []).push({ name: t.name, description: t.description });
    const loc = a.occurrences[0]?.source;
    if (hadStatic && r.liveOnly.length) f.add('LIVE-HIDDEN-TOOLS', 'medium', { asset: a, location: loc, evidence: r.liveOnly.slice(0, 8).join(', ') });
    if (r.changedDescriptions.length) f.add('LIVE-DYNAMIC-DESCRIPTIONS', 'medium', { asset: a, location: loc, evidence: r.changedDescriptions.slice(0, 8).join(', ') });
    for (const n of r.tools.filter((t) => ((r as { poisoned?: string[] }).poisoned ?? []).includes(t.name))) f.add('MCP-TOOL-POISONING', 'high', { asset: a, location: loc, evidence: `${n.name}: ${(n.description ?? '').slice(0, 160)}`, detail: 'Seen in the live, sandboxed run.' });
    if (r.networkAttempts.length) f.add('LIVE-NETWORK-AT-START', 'medium', { asset: a, location: loc, evidence: r.networkAttempts[0] });
  }
  // Dependencies of servers whose code is on disk: exactly what runs.
  if (opts.toolAnalysis !== false) {
    const onlineFetch = opts.online ? (opts.fetchImpl ?? (fetch as unknown as Fetch)) : undefined;
    const seen = new Map<string, Awaited<ReturnType<typeof installedDependencies>>>();
    for (const a of col.assets.values()) {
      const dir = a.mcp?.sourceDir;
      if (!dir) continue;
      if (!seen.has(dir)) seen.set(dir, await installedDependencies(dir, advisories, { online: !!onlineFetch, fetchImpl: onlineFetch }).catch(() => undefined));
      const r = seen.get(dir);
      if (!r) continue;
      a.deps = { ecosystem: r.ecosystem, scope: r.scope, total: r.total, vulnerable: r.vulnerable.slice(0, 30), licenses: r.licenses, licenseNotes: r.licenseNotes };
      for (const v of r.vulnerable) f.add('DEP-VULN', v.severity, { asset: a, location: dir, title: `${v.id} in ${v.name}@${v.version} (used by ${a.name})`, evidence: `${v.name}@${v.version}: ${v.summary}`, advisory: v.id, references: v.references });
      for (const n of r.licenseNotes.filter((x) => /copyleft/.test(x))) f.add('DEP-LICENSE', 'low', { asset: a, location: dir, evidence: n });
      if (r.error && vulnCheck) vulnCheck.errors.push(`Dependencies of ${a.name}: ${r.error}`);
    }
  }
  if (opts.toolHashesFile) await checkToolChanges(col, f, opts.toolHashesFile);
  const trustErrors = await assessTrust(col, f, { online: opts.online, fetchImpl: opts.online ? (opts.fetchImpl ?? (fetch as unknown as Fetch)) : undefined });
  if (vulnCheck && trustErrors.length) vulnCheck.errors.push(...trustErrors.slice(0, 5));
  checkShadowing(col, f);
  const gaps: { what: string; why: string }[] = [];
  const reader = opts.endpoint === false ? undefined : opts.endpoint ?? (opts.home === undefined && !opts.projectOnly ? liveEndpoint : undefined);
  if (reader) {
    const snap = await reader().catch(() => undefined);
    if (snap) analyzeEndpoint(col, f, snap);
    else gaps.push({ what: 'Running programs and open ports', why: 'The system tools that list them (ps, lsof) are not available here, for example on Windows, so model servers and unlisted MCP servers were not looked for.' });
  } else gaps.push({ what: 'Running programs and open ports', why: 'Skipped for this scan: it was not a scan of this computer’s own home folder.' });
  let sessions: Inventory['sessions'];
  if (opts.sessionLogs !== false && !opts.projectOnly) sessions = applySessions(col, await readSessions(ctx.claudeDir, { home: ctx.home }), f);
  analyzeReach(col, f);
  const context = await contextCost(col, new Set(f.list.filter((x) => x.ruleId === 'USAGE-UNUSED' && x.assetId).map((x) => x.assetId!)));
  const findings = await runChecks(col, vulnHits, f);

  // Only keep projects that actually carry AI assets.
  const usedProjects = new Set<string>();
  for (const a of col.assets.values()) for (const o of a.occurrences) if (o.project) usedProjects.add(o.project);

  let inventory: Inventory = {
    schemaVersion: 1,
    tool: { name: 'ai-bom', version: VERSION },
    scannedAt: new Date().toISOString(),
    host: { platform: ctx.platform, hostname: os.hostname(), user: os.userInfo().username },
    clients: [...col.clients.values()].sort((a, b) => a.name.localeCompare(b.name)),
    projects: [...col.projects.values()].filter((p) => usedProjects.has(p.path)).sort((a, b) => a.path.localeCompare(b.path)),
    assets: [...col.assets.values()].map(sanitizeAsset).sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name)),
    findings,
    errors: col.errors,
    vulnCheck,
    sessions,
    context,
    feed: feed ? { generatedAt: feed.generatedAt, advisories: feed.advisories.length, verified: true } : undefined,
    trace: opts.trace ? col.trace : undefined,
    coverage: { gaps: coverageGaps(gaps, opts, col.errors.length) },
  };

  // Triage, then risk: muted findings don't count toward an asset's risk.
  const triage = opts.triageFile ? applyTriage(findings, await loadTriage(opts.triageFile)) : undefined;
  if (triage) inventory.triage = triage;
  rollupRisk(inventory.assets, findings);
  const assetById = new Map(inventory.assets.map((a) => [a.id, a]));
  for (const f of findings) {
    const kinds = fixKindsFor(inventory, f, f.assetId ? assetById.get(f.assetId) : undefined);
    if (kinds.length) f.fixes = kinds;
  }
  for (const a of inventory.assets) {
    const kinds = fixKindsFor(inventory, undefined, a);
    if (kinds.length) a.fixes = kinds;
  }
  inventory.score = computeScore(inventory);

  if (opts.historyFile) inventory = await applyHistory(inventory, opts.historyFile, !opts.historyReadOnly);
  if (opts.recordAs) await recordScan(inventory, opts.recordAs);
  if (!opts.keepHomePaths) inventory = replaceHome(inventory, ctx.home);
  return inventory;
}

async function addCloudConnectors(col: Collector, file: string) {
  let records;
  try {
    records = await loadConnectors(file);
  } catch (e) {
    col.error(file, (e as Error).message);
    return;
  }
  for (const c of records) {
    const client = `cloud:${c.platform}` as const;
    col.client(client, c.platform, file);
    col.add({
      kind: 'connector',
      name: c.name,
      key: `connector:${c.id}`,
      origin: 'cloud',
      connector: { id: c.id, platform: c.platform, access: c.access, notes: c.notes, addedAt: c.addedAt, reviewedAt: c.reviewedAt },
      occurrence: { client, scope: 'user', source: file, name: c.name, modifiedAt: c.reviewedAt ?? c.addedAt },
    });
  }
}

/** Record when each config file last changed; months-old entries are the forgotten ones. */
async function stampModified(col: Collector) {
  const cache = new Map<string, Promise<string | undefined>>();
  const stat = (p: string) => {
    if (!cache.has(p)) cache.set(p, mtime(p));
    return cache.get(p)!;
  };
  for (const a of col.assets.values()) {
    for (const o of a.occurrences) {
      if (o.modifiedAt) continue;
      // Skills are directories; their SKILL.md changes when the skill does.
      const target = a.kind === 'skill' && a.path && o.source === a.path ? path.join(a.path, 'SKILL.md') : o.source;
      o.modifiedAt = (await stat(target)) ?? (await stat(o.source));
    }
  }
}

/** Strip secret values from everything that will be serialized. */
function sanitizeAsset(a: Asset): Asset {
  const out: Asset = { ...a };
  if (a.mcp) {
    out.mcp = {
      ...a.mcp,
      command: a.mcp.command && redactText(a.mcp.command),
      args: a.mcp.args && redactArgs(a.mcp.args),
      url: a.mcp.url && redactUrl(a.mcp.url),
      remoteUrl: a.mcp.remoteUrl && redactUrl(a.mcp.remoteUrl),
      env: redactRecord(a.mcp.env),
      headers: redactRecord(a.mcp.headers),
    };
    if (out.mcp.package) out.mcp.package = { ...out.mcp.package, name: redactText(out.mcp.package.name) };
  }
  out.occurrences = a.occurrences.map((o) => ({
    ...o,
    env: redactRecord(o.env),
    headers: redactRecord(o.headers),
    url: o.url && redactUrl(o.url),
  }));
  if (a.hook) out.hook = { ...a.hook, command: redactText(a.hook.command) };
  return out;
}

interface HistoryEntry {
  id: string;
  kind: Asset['kind'];
  name: string;
}

async function applyHistory(inv: Inventory, file: string, save: boolean): Promise<Inventory> {
  let previous: HistoryEntry[] | undefined;
  try {
    const data = JSON.parse(await fs.readFile(file, 'utf8'));
    if (Array.isArray(data.assets)) previous = data.assets;
  } catch {
    /* first scan */
  }
  if (previous) {
    const prevIds = new Set(previous.map((p) => p.id));
    const nowIds = new Set(inv.assets.map((a) => a.id));
    for (const a of inv.assets) if (!prevIds.has(a.id)) a.isNew = true;
    inv.removed = previous.filter((p) => !nowIds.has(p.id));
  }
  if (!save) return inv;
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const snapshot = { scannedAt: inv.scannedAt, assets: inv.assets.map((a) => ({ id: a.id, kind: a.kind, name: a.name })) };
    await fs.writeFile(file, JSON.stringify(snapshot, null, 2), { mode: 0o600 });
  } catch (e) {
    inv.errors.push({ file, message: `Could not save scan history: ${(e as Error).message}` });
  }
  return inv;
}

function replaceHome<T>(value: T, home: string): T {
  if (!home || home === '/') return value;
  const escaped = home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(escaped + String.raw`(?=[\/\s"':]|$)`, 'g');
  const sub = (s: string) => s.replace(re, '~');
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return sub(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [sub(k), walk(x)]));
    return v;
  };
  return walk(value) as T;
}
