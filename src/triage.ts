import path from 'node:path';
import type { Finding, TriageDecision, TriageStatus } from './types.js';
import { dataDir, readJsonFile, writeJsonFile } from './util/store.js';

/**
 * Triage: the user's decisions about findings. A finding can be
 *   accepted        - a known, deliberate risk ("I need this")
 *   snoozed         - hidden until a date, then it comes back
 *   false-positive  - the check got it wrong
 * Muted findings stay in the inventory (so nothing is hidden for good) but do
 * not count toward risk, --fail-on, notifications or the headline numbers.
 *
 * Keys are finding ids, which are stable hashes of rule + asset + location +
 * evidence: if the evidence changes (a new version, a different token) the
 * decision no longer applies and the finding shows up again.
 */
export interface TriageEntry extends TriageDecision {
  ruleId?: string;
  title?: string;
}

interface TriageFile {
  version: 1;
  entries: Record<string, TriageEntry>;
}

export const defaultTriageFile = () => path.join(dataDir(), 'triage.json');

export async function loadTriage(file = defaultTriageFile()): Promise<Record<string, TriageEntry>> {
  const data = await readJsonFile<Partial<TriageFile>>(file);
  return data && typeof data.entries === 'object' && data.entries ? data.entries : {};
}

const STATUSES: TriageStatus[] = ['accepted', 'snoozed', 'false-positive'];

/** Keep only well-formed decisions from an untrusted file (a state import): real finding ids, known statuses, valid dates. */
export function cleanTriageEntries(raw: unknown): Record<string, TriageEntry> {
  const out: Record<string, TriageEntry> = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [id, v] of Object.entries(raw)) {
    const e = v as Partial<TriageEntry> | null;
    if (!/^[0-9a-f]{12}$/.test(id) || !e || !STATUSES.includes(e.status as TriageStatus)) continue;
    const date = (x: unknown) => (typeof x === 'string' && !Number.isNaN(Date.parse(x)) ? x : undefined);
    if (e.status === 'snoozed' && !date(e.until)) continue;
    out[id] = {
      status: e.status!,
      reason: typeof e.reason === 'string' ? e.reason.slice(0, 500) : undefined,
      until: e.status === 'snoozed' ? date(e.until) : undefined,
      at: date(e.at) ?? new Date().toISOString(),
      ruleId: typeof e.ruleId === 'string' ? e.ruleId.slice(0, 80) : undefined,
      title: typeof e.title === 'string' ? e.title.slice(0, 200) : undefined,
    };
  }
  return out;
}

/** Parse "30d", "2w", "6m" or an ISO date into an ISO timestamp. */
export function parseUntil(v: string, now = Date.now()): string {
  const m = v.trim().match(/^(\d+)\s*([dwm])$/i);
  if (m) {
    const n = Number(m[1]);
    const days = m[2].toLowerCase() === 'd' ? n : m[2].toLowerCase() === 'w' ? n * 7 : n * 30;
    return new Date(now + days * 86_400_000).toISOString();
  }
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw new Error(`Invalid date "${v}". Use e.g. 30d, 2w, 3m or 2026-12-31.`);
  if (t <= now) throw new Error('The snooze date must be in the future.');
  return new Date(t).toISOString();
}

export async function setTriage(
  file: string,
  findingId: string,
  input: { status: string; reason?: string; until?: string; ruleId?: string; title?: string },
): Promise<TriageEntry> {
  if (!/^[0-9a-f]{12}$/.test(findingId)) throw new Error('Invalid finding id');
  const status = input.status as TriageStatus;
  if (!STATUSES.includes(status)) throw new Error(`Status must be one of: ${STATUSES.join(', ')}`);
  if (status === 'snoozed' && !input.until) throw new Error('A snooze needs an end date (e.g. 30d).');
  const reason = input.reason?.trim().slice(0, 500) || undefined;
  const entries = await loadTriage(file);
  const entry: TriageEntry = {
    status,
    reason,
    until: status === 'snoozed' ? parseUntil(input.until!) : undefined,
    at: new Date().toISOString(),
    ruleId: input.ruleId,
    title: input.title?.slice(0, 200),
  };
  entries[findingId] = entry;
  await writeJsonFile(file, { version: 1, entries } satisfies TriageFile);
  return entry;
}

export async function clearTriage(file: string, findingId: string): Promise<boolean> {
  const entries = await loadTriage(file);
  if (!(findingId in entries)) return false;
  delete entries[findingId];
  await writeJsonFile(file, { version: 1, entries } satisfies TriageFile);
  return true;
}

/** Attach decisions to findings; expired snoozes are left active. Returns counts. */
export function applyTriage(findings: Finding[], entries: Record<string, TriageEntry>, now = Date.now()) {
  const counts = { accepted: 0, snoozed: 0, falsePositive: 0, expired: 0 };
  for (const f of findings) {
    const e = entries[f.id];
    if (!e) continue;
    if (e.status === 'snoozed' && e.until && Date.parse(e.until) <= now) {
      counts.expired++;
      continue;
    }
    f.muted = { status: e.status, reason: e.reason, until: e.until, at: e.at };
    if (e.status === 'accepted') counts.accepted++;
    else if (e.status === 'snoozed') counts.snoozed++;
    else counts.falsePositive++;
  }
  return counts;
}

export const isActive = (f: Finding) => !f.muted;
