import os from 'node:os';
import path from 'node:path';
import { applyChanges, hookInstallOps, type Snapshot } from './fix/index.js';
import { getAt, readJsonDoc } from './fix/jsonedit.js';
import { selfCommand, selfInvocation } from './selfcmd.js';
import { watchInstalled } from './watch.js';

/**
 * The two Claude Code hooks AI-BOM can install, and whether the background watch is running. Shared by the
 * CLI (`ai-bom guard --install`, `ai-bom check --install-hook`) and the dashboard so both do the same thing,
 * through the same undoable snapshots.
 */

export type Safeguard = 'guard' | 'preflight';

export const settingsFile = (claudeDir?: string) => path.join(claudeDir ?? path.join(os.homedir(), '.claude'), 'settings.json');

interface Spec {
  title: { on: string; off: string };
  /** Hook entries to add: [event, entry]. */
  entries: () => [string, unknown][];
  /** Which events to look in, and how to recognise our entry there. */
  events: string[];
  mine: (entry: unknown) => boolean;
}

const has = (needle: string) => (entry: unknown) => JSON.stringify(entry).includes(needle);

const SPECS: Record<Safeguard, Spec> = {
  guard: {
    title: { on: 'Install the ai-bom MCP call guard', off: 'Remove the ai-bom MCP call guard' },
    entries: () => {
      const entry = { matcher: 'mcp__.*', hooks: [{ type: 'command', command: selfCommand(['guard']), timeout: 10 }] };
      return [['PreToolUse', entry], ['PostToolUse', entry]];
    },
    events: ['PreToolUse', 'PostToolUse'],
    mine: has(' guard'),
  },
  preflight: {
    title: { on: 'Install the ai-bom pre-flight hook', off: 'Remove the ai-bom pre-flight hook' },
    entries: () => [['SessionStart', { hooks: [{ type: 'command', command: selfCommand(['check', '--hook']), timeout: 60 }] }]],
    events: ['SessionStart'],
    mine: has(' check --hook'),
  },
};

async function listFor(file: string, event: string): Promise<unknown[]> {
  try {
    const list = getAt((await readJsonDoc(file)).data, ['hooks', event]);
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

export async function isInstalled(which: Safeguard, claudeDir?: string): Promise<boolean> {
  const file = settingsFile(claudeDir);
  const spec = SPECS[which];
  for (const ev of spec.events) if ((await listFor(file, ev)).some(spec.mine)) return true;
  return false;
}

/** Turn a hook on or off. Returns the undoable snapshot, or null when it was already in the wanted state. */
export async function setSafeguard(which: Safeguard, on: boolean, claudeDir?: string): Promise<Snapshot | null> {
  const file = settingsFile(claudeDir);
  const spec = SPECS[which];
  if (on) {
    const ops = await hookInstallOps(file, spec.entries());
    return ops.length ? applyChanges(spec.title.on, 'settings', ops) : null;
  }
  const doc = await readJsonDoc(file).catch(() => undefined);
  if (!doc) return null;
  const ops = [];
  for (const ev of spec.events) {
    const list = getAt(doc.data, ['hooks', ev]);
    if (!Array.isArray(list)) continue;
    for (let i = list.length - 1; i >= 0; i--) {
      if (spec.mine(list[i])) ops.push({ type: 'json' as const, file, path: ['hooks', ev, i], before: { present: true as const, value: list[i] }, after: { present: false as const }, array: true });
    }
  }
  return ops.length ? applyChanges(spec.title.off, 'remove-hook', ops) : null;
}

export interface SafeguardState {
  guard: boolean;
  preflight: boolean;
  watch: { supported: boolean; installed: boolean };
  settingsFile: string;
  /** Running from the npx cache: a hook installed now can break when the cache is cleared. */
  ephemeral: boolean;
}

export async function safeguardState(claudeDir?: string): Promise<SafeguardState> {
  const home = os.homedir();
  const file = settingsFile(claudeDir);
  return {
    guard: await isInstalled('guard', claudeDir),
    preflight: await isInstalled('preflight', claudeDir),
    watch: { supported: process.platform === 'darwin' || process.platform === 'linux', installed: await watchInstalled() },
    settingsFile: file.startsWith(home) ? `~${file.slice(home.length)}` : file,
    ephemeral: selfInvocation().ephemeral,
  };
}
