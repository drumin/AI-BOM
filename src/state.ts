import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { Inventory, Severity } from './types.js';
import { cleanTriageEntries } from './triage.js';
import { dataDir, readJsonFile, writeAtomic, writeJsonFile } from './util/store.js';

/**
 * Everything AI-BOM remembers lives in ~/.ai-bom (or $AI_BOM_HOME), with
 * owner-only permissions:
 *
 *   triage.json        accepted / snoozed / false-positive findings, with reasons
 *   snapshots/         every change `fix` made, with what's needed to undo it
 *   audit.log          one line per fix / undo / install (file names only)
 *   connectors.json    cloud connectors you registered
 *   preferences.json   dashboard preferences (theme, views)
 *   activity-mutes.json  kinds of flagged steps you stopped flagging in Activity
 *   history/scans.jsonl  one summary line per scan (counts only), for trends
 *   last-scan.json     asset ids of the previous scan ("new since last scan")
 *   tool-hashes.json   tool descriptions per server (rug-pull detection)
 *   reviews.json       cached plain-language reviews
 *   quarantine/        skills/agents/commands you quarantined
 *   feed/, cache/      signed advisory feed and NVD responses
 *   bin/               the keychain launcher used by fixed MCP entries
 */

/* ---------------- Scan history ---------------- */

export interface ScanRecord {
  at: string;
  source: string;
  assets: number;
  byKind: Record<string, number>;
  active: Partial<Record<Severity, number>>;
  muted: number;
  added: number;
  removed: number;
  score?: number;
}

const MAX_RECORDS = 1000;
export const scanLogFile = () => path.join(dataDir(), 'history', 'scans.jsonl');

export function summarize(inv: Inventory, source: string): ScanRecord {
  const byKind: Record<string, number> = {};
  for (const a of inv.assets) byKind[a.kind] = (byKind[a.kind] ?? 0) + 1;
  const active: Partial<Record<Severity, number>> = {};
  for (const f of inv.findings) if (!f.muted) active[f.severity] = (active[f.severity] ?? 0) + 1;
  return {
    at: inv.scannedAt,
    source,
    assets: inv.assets.length,
    byKind,
    active,
    muted: inv.findings.filter((f) => f.muted).length,
    added: inv.assets.filter((a) => a.isNew).length,
    removed: inv.removed?.length ?? 0,
    score: inv.score?.value,
  };
}

/** Append one line (counts only, no names or paths); keeps the newest 1000. */
export async function recordScan(inv: Inventory, source: string, file = scanLogFile()): Promise<void> {
  try {
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    await fs.appendFile(file, JSON.stringify(summarize(inv, source)) + '\n', { mode: 0o600 });
    const lines = (await fs.readFile(file, 'utf8')).split('\n').filter(Boolean);
    if (lines.length > MAX_RECORDS * 1.2) await writeAtomic(file, lines.slice(-MAX_RECORDS).join('\n') + '\n');
  } catch {
    /* history is best effort */
  }
}

export async function readScans(limit = 50, file = scanLogFile()): Promise<ScanRecord[]> {
  try {
    const lines = (await fs.readFile(file, 'utf8')).split('\n').filter(Boolean).slice(-limit);
    return lines.flatMap((l) => {
      try {
        return [JSON.parse(l) as ScanRecord];
      } catch {
        return [];
      }
    }).reverse();
  } catch {
    return [];
  }
}

/* ---------------- Dashboard preferences ---------------- */

export interface Preferences {
  theme?: 'system' | 'light' | 'dark';
  mapView?: 'overview' | 'network';
  findingsView?: 'active' | 'muted';
  baselineView?: 'nist-ai-rmf' | 'iso-42001' | 'atlas';
  baselineFilter?: 'all' | 'attention' | 'answer';
  /** Set once the first-run welcome has been dismissed. */
  welcomed?: 'yes' | 'no';
}

const prefsFile = () => path.join(dataDir(), 'preferences.json');
const ALLOWED: Record<keyof Preferences, string[]> = {
  theme: ['system', 'light', 'dark'],
  mapView: ['overview', 'network'],
  findingsView: ['active', 'muted'],
  baselineView: ['nist-ai-rmf', 'iso-42001', 'atlas'],
  baselineFilter: ['all', 'attention', 'answer'],
  welcomed: ['yes', 'no'],
};

export async function loadPreferences(): Promise<Preferences> {
  const p = (await readJsonFile<Record<string, unknown>>(prefsFile())) ?? {};
  const out: Preferences = {};
  for (const [k, allowed] of Object.entries(ALLOWED)) if (typeof p[k] === 'string' && allowed.includes(p[k] as string)) (out as Record<string, string>)[k] = p[k] as string;
  return out;
}

/** Merge validated keys into the stored preferences. Unknown keys and values are ignored. */
export async function savePreferences(patch: Record<string, unknown>): Promise<Preferences> {
  const cur = await loadPreferences();
  for (const [k, allowed] of Object.entries(ALLOWED)) if (typeof patch[k] === 'string' && allowed.includes(patch[k] as string)) (cur as Record<string, string>)[k] = patch[k] as string;
  await writeJsonFile(prefsFile(), cur);
  return cur;
}

/* ---------------- Muted activity flags ---------------- */

const mutesFile = () => path.join(dataDir(), 'activity-mutes.json');

/** Active mute rules for flagged steps in Activity (see `mutedBy` in activity.ts). Snoozed rules drop out when their date passes. */
export async function loadActivityMutes(): Promise<string[]> {
  const v = await readJsonFile<{ muted?: unknown; until?: Record<string, string> }>(mutesFile());
  const now = Date.now();
  const live = (k: string) => !(v?.until?.[k] && Date.parse(v.until[k]) <= now);
  return Array.isArray(v?.muted) ? v.muted.filter((x): x is string => typeof x === 'string' && live(x)).slice(0, 200) : [];
}

/** When each snoozed rule comes back, for display. */
export async function activitySnoozes(): Promise<Record<string, string>> {
  const v = await readJsonFile<{ until?: Record<string, string> }>(mutesFile());
  const live = await loadActivityMutes();
  return Object.fromEntries(Object.entries(v?.until ?? {}).filter(([k]) => live.includes(k)));
}

/** Add or remove a rule. `days` makes it a snooze that lifts itself. */
export async function setActivityMute(flag: string, muted: boolean, days?: number): Promise<string[]> {
  const cur = new Set(await loadActivityMutes());
  const until = await activitySnoozes();
    if (muted) {
    cur.add(flag);
    if (days) until[flag] = new Date(Date.now() + days * 86_400_000).toISOString();
    else delete until[flag];
  } else {
    cur.delete(flag);
    delete until[flag];
  }
  const list = [...cur];
  await writeJsonFile(mutesFile(), { version: 1, muted: list, until });
  return list;
}

/* ---------------- Overview, backup, restore ---------------- */

const DESCRIBE: [string, string][] = [
  ['triage.json', 'Muted findings (accepted, snoozed, false positives) and your reasons'],
  ['snapshots', 'Changes made by `ai-bom fix`, each undoable'],
  ['audit.log', 'Log of fixes, undos and installs (file names only)'],
  ['connectors.json', 'Cloud connectors you registered'],
  ['attestations.json', 'Your answers for NIST AI RMF / ISO 42001 controls a scan can’t check'],
  ['preferences.json', 'Dashboard preferences'],
  ['activity-mutes.json', 'Kinds of flagged steps you stopped flagging in Activity'],
  ['history/scans.jsonl', 'One summary per scan (counts only)'],
  ['last-scan.json', 'Previous scan, for "new since last scan"'],
  ['tool-hashes.json', 'Tool descriptions per server (rug-pull detection)'],
  ['reviews.json', 'Cached plain-language reviews'],
  ['quarantine', 'Quarantined skills, agents and commands'],
  ['feed', 'Verified advisory feed'],
  ['cache', 'NVD response cache'],
  ['watch-state.json', 'What watch mode already notified you about'],
  ['guard.log', 'Decisions of the live MCP call guard'],
  ['inspections.json', 'Results of sandboxed live checks'],
  ['incidents', 'Reports written by incident mode'],
  ['bin', 'Keychain launcher used by fixed MCP entries'],
];

async function sizeOf(p: string): Promise<{ bytes: number; items?: number } | undefined> {
  try {
    const st = await fs.stat(p);
    if (st.isFile()) return { bytes: st.size };
    const names = await fs.readdir(p);
    let bytes = 0;
    for (const n of names) bytes += (await sizeOf(path.join(p, n)))?.bytes ?? 0;
    return { bytes, items: names.length };
  } catch {
    return undefined;
  }
}

export async function describeState(): Promise<{ dir: string; entries: { name: string; what: string; bytes: number; items?: number }[] }> {
  const dir = dataDir();
  const entries = [];
  for (const [name, what] of DESCRIBE) {
    const s = await sizeOf(path.join(dir, name));
    if (s) entries.push({ name, what, ...s });
  }
  return { dir, entries };
}

interface Backup {
  kind: 'ai-bom-state';
  version: 1;
  exportedAt: string;
  files: Record<string, unknown>;
}

/** The small, hand-made state worth carrying to another machine (no secrets, no caches). */
const PORTABLE = ['triage.json', 'connectors.json', 'preferences.json', 'attestations.json', 'activity-mutes.json'];

export async function exportState(file: string): Promise<string[]> {
  const files: Record<string, unknown> = {};
  for (const n of PORTABLE) {
    const v = await readJsonFile(path.join(dataDir(), n));
    if (v !== undefined) files[n] = v;
  }
  await writeJsonFile(file, { kind: 'ai-bom-state', version: 1, exportedAt: new Date().toISOString(), files } satisfies Backup);
  return Object.keys(files);
}

/** Restore a backup. Triage decisions and connectors are merged; existing entries win unless `replace`. */
export async function importState(file: string, replace = false): Promise<string[]> {
  const b = await readJsonFile<Backup>(file);
  if (!b || b.kind !== 'ai-bom-state' || typeof b.files !== 'object') throw new Error(`${file} is not an ai-bom state export.`);
  const done: string[] = [];
  for (const n of PORTABLE) {
    const incoming = b.files[n] as Record<string, unknown> | undefined;
    if (!incoming || typeof incoming !== 'object') continue;
    const target = path.join(dataDir(), n);
    const current = (await readJsonFile<Record<string, unknown>>(target)) ?? {};
    let merged: unknown = incoming;
    if (n === 'triage.json') {
      const clean = cleanTriageEntries(incoming.entries);
      merged = { version: 1, entries: replace ? clean : { ...clean, ...cleanTriageEntries(current.entries) } };
    } else if (!replace && n === 'attestations.json') {
      merged = { version: 1, entries: { ...(incoming.entries as object), ...(current.entries as object) } };
    } else if (!replace && n === 'connectors.json') {
      const cur = Array.isArray(current.connectors) ? (current.connectors as { id: string }[]) : [];
      const inc = Array.isArray(incoming.connectors) ? (incoming.connectors as { id: string }[]) : [];
      merged = { version: 1, connectors: [...cur, ...inc.filter((c) => !cur.some((x) => x.id === c.id))] };
    } else if (!replace && n === 'activity-mutes.json') {
      const a = Array.isArray(current.muted) ? current.muted : [];
      const b = Array.isArray(incoming.muted) ? incoming.muted : [];
      merged = { version: 1, muted: [...new Set([...a, ...b])], until: { ...(incoming.until as object), ...(current.until as object) } };
    } else if (!replace && n === 'preferences.json') {
      merged = { ...incoming, ...current };
    }
    await writeJsonFile(target, merged);
    done.push(n);
  }
  return done;
}
