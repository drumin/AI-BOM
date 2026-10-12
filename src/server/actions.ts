import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { VetResult } from '../vet.js';

const pendingAdds = new Map<string, VetResult>();
import type { FixKind, Inventory } from '../types.js';
import type { ScanOptions } from '../scan.js';
import { applyFix, ConflictError, listSnapshots, planFix, publicPlan, publicSnapshot, undoFix, type FixContext } from '../fix/index.js';
import { defaultSecretStore } from '../fix/keychain.js';
import { clearTriage, defaultTriageFile, setTriage } from '../triage.js';
import { cachedReview, MODEL, reviewInput, reviewWithClaude, reviewWithOllama } from '../review/explain.js';
import { assetSource } from '../review/source.js';
import { toHtml } from '../reports/html.js';
import { toMarkdown } from '../reports/markdown.js';
import { toSarif } from '../reports/sarif.js';
import { HttpError, type ServeOptions } from './serve.js';
import { doctorScan } from '../doctor.js';
import { tilde as tildePath, untildeDeep } from '../util/paths.js';
import { activitySnoozes, loadActivityMutes, loadPreferences, readScans, savePreferences, setActivityMute } from '../state.js';

/** The dashboard's write actions. All run locally; each returns the refreshed inventory. */
export function dashboardActions(d: { opts: ScanOptions; getInventory: () => Promise<Inventory>; rescan: (o: { online?: boolean; record?: boolean }) => Promise<Inventory> }): NonNullable<ServeOptions['actions']> {
  const triageFile = d.opts.triageFile ?? defaultTriageFile();
  const home = d.opts.home ?? os.homedir();
  /** Where Claude Code's settings live for this dashboard: its own home folder, so the demo never touches yours. */
  const claudeDir = d.opts.claudeConfigDir ?? (d.opts.home ? path.join(d.opts.home, '.claude') : undefined);
  const tilde = (p: string) => tildePath(p, home);
  const view = (snap: Parameters<typeof publicSnapshot>[0]) => {
    const p = publicSnapshot(snap);
    return { ...p, files: p.files.map((f) => tilde(f)) };
  };
  const str = (v: unknown) => (typeof v === 'string' && v.length < 600 ? v : undefined);
  const ctx = async (): Promise<FixContext> => ({ home: d.opts.home ?? os.homedir(), inventory: await d.getInventory(), claudeDir: d.opts.claudeConfigDir, secretStore: defaultSecretStore() });
  const target = (b: Record<string, unknown>) => ({ findingId: str(b.findingId), assetId: str(b.assetId) });
  const conflict = async <T>(fn: () => Promise<T>) => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof ConflictError) throw new HttpError(409, e.message);
      throw e;
    }
  };
  const asset = async (b: Record<string, unknown>) => {
    const a = (await d.getInventory()).assets.find((x) => x.id === str(b.assetId));
    if (!a) throw new HttpError(404, 'Asset not found; rescan and try again.');
    return a;
  };

  return {
    'POST /api/triage': async (b) => {
      const f = (await d.getInventory()).findings.find((x) => x.id === str(b.findingId));
      if (!f) throw new HttpError(404, 'Finding not found');
      await setTriage(triageFile, f.id, { status: String(b.status), reason: str(b.reason), until: str(b.until), ruleId: f.ruleId, title: f.title });
      return d.rescan({});
    },
    // Many decisions, one rescan. Unknown ids are reported back, not fatal.
    'POST /api/triage/bulk': async (b) => {
      const ids = (Array.isArray(b.findingIds) ? b.findingIds : []).filter((x): x is string => typeof x === 'string').slice(0, 500);
      if (!['clear', 'accepted', 'snoozed', 'false-positive'].includes(String(b.status))) throw new HttpError(400, 'Unknown triage status');
      const byId = new Map((await d.getInventory()).findings.map((f) => [f.id, f]));
      const done: string[] = [];
      for (const id of ids) {
        const f = byId.get(id);
        if (!f) continue;
        if (b.status === 'clear') await clearTriage(triageFile, id);
        else await setTriage(triageFile, id, { status: String(b.status), reason: str(b.reason), until: str(b.until), ruleId: f.ruleId, title: f.title });
        done.push(id);
      }
      return { done, failed: ids.length - done.length, inventory: await d.rescan({}) };
    },
    'DELETE /api/triage/:id': async (_b, id) => {
      await clearTriage(triageFile, id!);
      return d.rescan({});
    },
    'POST /api/fix/preview': async (b) => publicPlan(await planFix(await ctx(), target(b), str(b.kind) as FixKind | undefined)),
    'POST /api/fix/apply': async (b) =>
      conflict(async () => {
        const snap = await applyFix(await ctx(), target(b), str(b.kind) as FixKind | undefined, str(b.key));
        return { snapshot: view(snap), inventory: await d.rescan({}) };
      }),
    'GET /api/snapshots': async () => (await listSnapshots()).map(view),
    'POST /api/snapshots/:id/undo': async (_b, id) =>
      conflict(async () => {
        const snap = await undoFix(id!, defaultSecretStore());
        return { snapshot: view(snap), inventory: await d.rescan({}) };
      }),
    'GET /api/activity': async (q) => {
      const { readActivity } = await import('../activity.js');
      const days = Math.min(90, Math.max(1, Number(q.days ?? 7) || 7));
      return readActivity({ claudeDir: d.opts.claudeConfigDir ?? path.join(home, '.claude'), home }, { days, sessions: 30, mutedFlags: await loadActivityMutes() });
    },
    'GET /api/activity/mutes': async () => ({ muted: await loadActivityMutes(), until: await activitySnoozes() }),
    'POST /api/activity/mute': async (b) => {
      const flag = str(b.flag);
      if (!flag) throw new HttpError(400, 'Which kind of flag?');
      return { muted: await setActivityMute(flag, b.muted !== false, b.days === 7 || b.days === 30 ? b.days : undefined) };
    },
    'POST /api/incident/preview': async (b) => {
      const { planIncident } = await import('../incident.js');
      const p = await planIncident(await d.getInventory(), home, Array.isArray(b.keep) ? b.keep.filter((x): x is string => typeof x === 'string') : []);
      return { paused: p.paused, keys: p.keys, manual: p.manual };
    },
    'POST /api/incident/apply': async (b) => {
      const { applyIncident } = await import('../incident.js');
      const r = await applyIncident(await d.getInventory(), home, { claudeDir: d.opts.claudeConfigDir ?? path.join(home, '.claude') }, { keep: Array.isArray(b.keep) ? b.keep.filter((x): x is string => typeof x === 'string') : [], days: 7, pause: b.pause !== false });
      return { snapshot: r.snapshot && view(r.snapshot), report: r.report.replace(home, '~'), inventory: await d.rescan({}) };
    },
    'GET /api/add/targets': async () => {
      const { TARGETS, installedTargets } = await import('../add.js');
      const installed = new Set((await installedTargets(d.opts.home)).map((t) => t.id));
      return TARGETS.map((t) => ({ id: t.id, name: t.name, installed: installed.has(t.id) }));
    },
    'POST /api/add/vet': async (b) => {
      const { vet, defaultName } = await import('../vet.js');
      const spec = str(b.spec)?.trim();
      if (!spec) throw new HttpError(400, 'Enter an npm package, pypi:name, or a server URL.');
      const r = await vet(spec, { online: true });
      const token = randomUUID();
      pendingAdds.set(token, r);
      setTimeout(() => void pendingAdds.get(token)?.cleanup().finally(() => pendingAdds.delete(token)), 10 * 60_000).unref?.();
      return { token, name: defaultName(r.spec), spec: r.spec, version: r.version, latest: r.latest, entry: r.entry, verdict: r.verdict, findings: r.findings, tools: r.tools, trust: r.trust, deps: r.deps && { total: r.deps.total, scope: r.deps.scope, licenseNotes: r.deps.licenseNotes, error: r.deps.error } };
    },
    'POST /api/add/apply': async (b) => {
      const { planAdd, applyAdd, latestMcpRemote } = await import('../add.js');
      const r = pendingAdds.get(str(b.token) ?? '');
      if (!r) throw new HttpError(410, 'That check expired; run it again.');
      const name = (str(b.name) ?? '').trim();
      if (!/^[\w.-]{1,64}$/.test(name)) throw new HttpError(400, 'Use a short name (letters, digits, - _ .).');
      const targets = Array.isArray(b.targets) ? b.targets.filter((x): x is string => typeof x === 'string') : [];
      if (!targets.length) throw new HttpError(400, 'Pick at least one AI tool.');
      if (r.verdict === 'dangerous' && b.force !== true) throw new HttpError(409, 'This server was rated dangerous.');
      const plan = await planAdd(r, { name, targets, home: d.opts.home, force: b.force === true, mcpRemoteVersion: r.spec.kind === 'remote' ? await latestMcpRemote() : undefined });
      const snap = await applyAdd(plan, name, {});
      await r.cleanup();
      pendingAdds.delete(str(b.token)!);
      return { snapshot: snap && view(snap), skipped: plan.skipped, inventory: await d.rescan({}) };
    },
    'GET /api/upgrades': async () => {
      const { upgradeCandidates } = await import('../add.js');
      return upgradeCandidates(await d.getInventory());
    },
    'POST /api/upgrade/diff': async (b) => {
      const { upgradeCandidates, diffUpgrade } = await import('../add.js');
      const c = (await upgradeCandidates(await d.getInventory())).find((x) => x.assetId === str(b.assetId));
      if (!c) throw new HttpError(404, 'No update for this server.');
      return diffUpgrade(c, { online: true });
    },
    'POST /api/upgrade/apply': async (b) => {
      const { applyUpgrade } = await import('../add.js');
      const a = await asset(b);
      const version = str(b.version);
      if (!version || !/^[\w.+-]{1,40}$/.test(version)) throw new HttpError(400, 'Invalid version');
      const snap = await applyUpgrade(a, version, home);
      return { snapshot: view(snap), inventory: await d.rescan({}) };
    },
    'GET /api/sandbox': async () => {
      const { availableSandbox } = await import('../inspect.js');
      return { sandbox: availableSandbox() ?? null };
    },
    'POST /api/inspect': async (b) => {
      const { inspectLive, saveInspection } = await import('../inspect.js');
      const a = await asset(b);
      // The dashboard inventory shows ~ paths; the sandbox needs real ones.
      const r = await inspectLive(untildeDeep(a, home), home);
      await saveInspection(r);
      return { result: r, inventory: await d.rescan({}) };
    },
    'GET /api/preferences': async () => loadPreferences(),
    'POST /api/preferences': async (b) => savePreferences(b),
    'GET /api/scans': async () => readScans(30),
    'GET /api/safeguards': async () => {
      const { safeguardState } = await import('../safeguards.js');
      return safeguardState(claudeDir);
    },
    'POST /api/safeguards': async (b) => {
      const { setSafeguard, safeguardState } = await import('../safeguards.js');
      const which = str(b.name);
      if (which === 'watch') {
        // A scheduled job runs against your real home folder, so a dashboard pointed at another one (the demo) must not install it.
        if (d.opts.home) throw new HttpError(400, 'Background watch can’t be changed from a demo or test dashboard. Run ai-bom watch --install in a terminal.');
        const { installService, uninstallService } = await import('../watch.js');
        const note = b.on === true ? (await installService(30)).join(' ') : await uninstallService();
        return { note, state: await safeguardState(claudeDir) };
      }
      if (which !== 'guard' && which !== 'preflight') throw new HttpError(400, 'Unknown safeguard.');
      const snap = await setSafeguard(which, b.on === true, claudeDir);
      return { snapshot: snap && view(snap), state: await safeguardState(claudeDir), inventory: await d.rescan({}) };
    },
    'POST /api/preflight': async (b) => {
      const { preflight } = await import('../preflight.js');
      const raw = (str(b.path) ?? '').trim();
      if (!raw) throw new HttpError(400, 'Enter the folder to check.');
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('git@')) throw new HttpError(400, 'Enter a folder on this computer. To check a URL, run ai-bom check <url> in a terminal.');
      const dir = path.resolve(raw.startsWith('~') ? path.join(home, raw.slice(1)) : raw);
      const st = await fs.stat(dir).catch(() => undefined);
      if (!st?.isDirectory()) throw new HttpError(404, `${tilde(dir)} is not a folder.`);
      const r = await preflight(dir, { triageFile, online: false });
      try {
        return {
          folder: tilde(dir),
          verdict: r.verdict,
          autorun: r.autorun,
          findings: r.inventory.findings.filter((f) => !f.muted).map((f) => ({ id: f.id, severity: f.severity, title: f.title, location: f.location && tilde(f.location), evidence: f.evidence, remediation: f.remediation })),
          reads: r.inventory.assets.filter((x) => ['skill', 'agent', 'command', 'instructions'].includes(x.kind)).length,
        };
      } finally {
        await r.cleanup();
      }
    },
    'GET /api/doctor': async () => {
      const { VERSION } = await import('../scan.js');
      const { inv, found, errors, missing } = await doctorScan(d.opts, home);
      return {
        version: VERSION,
        node: process.version,
        platform: process.platform,
        claudeDir: tilde(claudeDir ?? path.join(home, '.claude')),
        tools: inv.clients.map((c) => c.name),
        assets: inv.assets.length,
        projects: inv.projects.length,
        found,
        errors,
        missing: missing.length,
      };
    },
    'GET /api/baselines': async () => {
      const { baselines } = await import('../frameworks/baselines.js');
      const { atlasView } = await import('../frameworks/atlas.js');
      const inv = await d.getInventory();
      return { ...(await baselines(inv)), atlas: atlasView(inv) };
    },
    'POST /api/baselines/attest': async (b) => {
      const { attest, isFramework } = await import('../frameworks/baselines.js');
      if (!isFramework(b.framework) || !str(b.control)) throw new HttpError(400, 'Unknown framework or control.');
      const status = b.status === 'done' || b.status === 'na' ? b.status : undefined;
      try {
        await attest(b.framework, str(b.control)!, status, str(b.note));
      } catch (e) {
        throw new HttpError(400, (e as Error).message);
      }
      return { ok: true };
    },
    'POST /api/asset/source': async (b) => {
      const files = await assetSource(await asset(b), home);
      if (!files.length) throw new HttpError(404, 'No readable file for this item.');
      return { files };
    },
    'POST /api/explain/preview': async (b) => {
      const input = await reviewInput(await asset(b), d.opts.home ?? os.homedir());
      return { files: input.files.map((f) => f.name), chars: input.chars, truncated: input.truncated, model: MODEL, cached: await cachedReview(input, 'claude', MODEL) };
    },
    'POST /api/explain': async (b) => {
      const input = await reviewInput(await asset(b), d.opts.home ?? os.homedir());
      if (!input.files.length) throw new HttpError(400, 'Nothing readable to review for this item.');
      return b.backend === 'ollama' ? reviewWithOllama(input, str(b.model)) : reviewWithClaude(input);
    },
  };
}

async function baselineReports(inv: Inventory) {
  const { baselines } = await import('../frameworks/baselines.js');
  return baselines(inv);
}

export function dashboardDownloads(getInventory: () => Promise<Inventory>): NonNullable<ServeOptions['downloads']> {
  return {
    '/api/report.html': ['text/html; charset=utf-8', async () => { const inv = await getInventory(); return toHtml(inv, undefined, await baselineReports(inv)); }],
    '/api/report.sarif': ['application/sarif+json', async () => JSON.stringify(toSarif(await getInventory()), null, 2)],
    '/api/report.md': ['text/markdown; charset=utf-8', async () => { const inv = await getInventory(); return toMarkdown(inv, undefined, await baselineReports(inv)); }],
  };
}
