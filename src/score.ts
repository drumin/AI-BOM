import type { Finding, Inventory, Severity } from './types.js';

/**
 * One number for "how exposed is my AI setup", with the single most useful
 * thing to do next. Muted findings don't count. The curve flattens so a
 * messy machine still sees progress from each fix.
 */

const WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

export interface NextAction {
  findingId: string;
  title: string;
  /** Automatic fix available (label of the first fix kind). */
  fix?: string;
  /** Points gained if this one finding goes away. */
  gain: number;
}

export interface Score {
  value: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  penalty: number;
  next: NextAction[];
}

const penaltyOf = (fs: Finding[]) => fs.reduce((n, f) => n + (f.muted ? 0 : WEIGHT[f.severity]), 0);
/** 100 with nothing open; one critical ≈ 67, one high ≈ 83, one medium ≈ 93. Never quite reaches 0. */
const raw = (penalty: number) => 100 / (1 + penalty / 50);
export const scoreFrom = (penalty: number) => Math.round(raw(penalty));
export const gradeOf = (v: number): Score['grade'] => (v >= 90 ? 'A' : v >= 75 ? 'B' : v >= 55 ? 'C' : v >= 35 ? 'D' : 'F');

const FIX_WORD: Record<string, string> = {
  'pin-version': 'Pin a safe version',
  'remove-entry': 'Remove from config',
  'move-to-keychain': 'Move secret to Keychain',
  settings: 'Fix the setting',
  'remove-hook': 'Remove the hook',
  quarantine: 'Quarantine',
  'disable-plugin': 'Disable the plugin',
};

export function computeScore(inv: Pick<Inventory, 'findings'>): Score {
  const active = inv.findings.filter((f) => !f.muted && WEIGHT[f.severity] > 0);
  const penalty = penaltyOf(active);
  const value = scoreFrom(penalty);
  // Rank by points gained; one-click fixes first among equals.
  const next = active
    .map((f) => ({ f, gain: Math.round((raw(penalty - WEIGHT[f.severity]) - raw(penalty)) * 10) / 10 }))
    .sort((a, b) => b.gain - a.gain || Number(!!b.f.fixes?.length) - Number(!!a.f.fixes?.length) || WEIGHT[b.f.severity] - WEIGHT[a.f.severity])
    .slice(0, 3)
    .map(({ f, gain }) => ({ findingId: f.id, title: f.title, fix: f.fixes?.[0] && FIX_WORD[f.fixes[0]], gain }));
  return { value, grade: gradeOf(value), penalty, next };
}
