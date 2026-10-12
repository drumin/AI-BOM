import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promises as fs, watch as fsWatch, type FSWatcher } from 'node:fs';
import type { Inventory } from './types.js';
import { scan, type ScanOptions } from './scan.js';
import { severityRank } from './checks/index.js';
import { dataDir, readJsonFile, writeAtomic, writeJsonFile } from './util/store.js';
import { selfInvocation } from './selfcmd.js';

/**
 * Watch mode: rescan when AI config changes (and on a timer), and send a
 * desktop notification for anything new: a new MCP server/skill/hook, or a
 * new high/critical finding. Muted (triaged) findings never notify.
 */

interface WatchState {
  assets: string[];
  alerts: string[];
  at: string;
}

const stateFile = () => path.join(dataDir(), 'watch-state.json');

export interface Change {
  title: string;
  body: string;
}

export function diff(inv: Inventory, prev: WatchState | undefined): { changes: Change[]; state: WatchState } {
  const alerts = inv.findings.filter((f) => !f.muted && severityRank(f.severity) <= severityRank('high'));
  const state: WatchState = { assets: inv.assets.map((a) => a.id), alerts: alerts.map((f) => f.id), at: inv.scannedAt };
  if (!prev) return { changes: [], state };
  const known = new Set(prev.assets);
  const alerted = new Set(prev.alerts);
  const name = new Map(inv.assets.map((a) => [a.id, a]));
  const newAssets = inv.assets.filter((a) => !known.has(a.id) && a.kind !== 'model' && a.kind !== 'app');
  const newAlerts = alerts.filter((f) => !alerted.has(f.id));
  const changes: Change[] = [];
  if (newAssets.length) {
    const first = newAssets[0];
    const where = first.occurrences[0]?.source.replace(os.homedir(), '~');
    changes.push({
      title: newAssets.length === 1 ? `New ${first.kind.replace('-', ' ')}: ${first.name}` : `${newAssets.length} new AI assets`,
      body: newAssets.length === 1 ? `Added in ${where}` : newAssets.slice(0, 4).map((a) => a.name).join(', '),
    });
  }
  for (const f of newAlerts.slice(0, 3)) {
    changes.push({ title: `${f.severity === 'critical' ? 'Critical' : 'High'}: ${f.title}`, body: f.assetId ? `${name.get(f.assetId)?.name ?? ''} — ${f.remediation}`.slice(0, 180) : f.remediation.slice(0, 180) });
  }
  if (newAlerts.length > 3) changes.push({ title: `${newAlerts.length - 3} more new findings`, body: 'Open the dashboard: ai-bom' });
  return { changes, state };
}

export function notify(c: Change, platform = process.platform): Promise<void> {
  return new Promise((resolve) => {
    const done = () => resolve();
    if (platform === 'darwin') {
      // Text is passed as argv, never interpolated into AppleScript source.
      execFile('osascript', ['-e', 'on run argv', '-e', 'display notification (item 2 of argv) with title "AI-BOM" subtitle (item 1 of argv)', '-e', 'end run', c.title, c.body], done);
    } else if (platform === 'linux') {
      execFile('notify-send', ['--app-name=AI-BOM', c.title, c.body], done);
    } else done();
  });
}

/** One check: scan, compare with the last watch state, notify, save. Returns the changes. */
export async function watchOnce(opts: ScanOptions, send: (c: Change) => Promise<void> = notify): Promise<Change[]> {
  const inv = await scan({ ...opts, historyFile: undefined, recordAs: 'watch' });
  const prev = await readJsonFile<WatchState>(stateFile());
  const { changes, state } = diff(inv, prev);
  for (const c of changes) await send(c);
  await writeJsonFile(stateFile(), state);
  return changes;
}

/** Long-running watch: fs events on config files (debounced) plus a periodic rescan. */
export async function watchLoop(opts: ScanOptions, intervalMs: number, log: (s: string) => void): Promise<never> {
  let watchers: FSWatcher[] = [];
  let timer: NodeJS.Timeout | undefined;
  const run = async (why: string) => {
    try {
      const changes = await watchOnce(opts);
      log(`${new Date().toLocaleTimeString()} ${why}: ${changes.length ? changes.map((c) => c.title).join('; ') : 'no changes'}`);
    } catch (e) {
      log(`scan failed: ${(e as Error).message}`);
    }
    // Re-arm file watchers on whatever config exists now.
    for (const w of watchers) w.close();
    watchers = [];
    const inv = await scan({ ...opts, historyFile: undefined, sessionLogs: false, toolAnalysis: false }).catch(() => undefined);
    const files = new Set<string>();
    for (const c of inv?.clients ?? []) for (const f of c.configFiles) files.add(f.replace(/^~/, os.homedir()));
    for (const f of files) {
      try {
        watchers.push(fsWatch(f, { persistent: true }, () => schedule('config changed')));
      } catch {
        /* vanished */
      }
    }
  };
  const schedule = (why: string) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void run(why), 5000);
  };
  await run('initial scan');
  setInterval(() => void run('periodic scan'), intervalMs).unref?.();
  return new Promise<never>(() => {});
}

/* ---------------- Background service ---------------- */

const LABEL = 'dev.ai-bom.watch';

export async function installService(intervalMin: number): Promise<string[]> {
  const { node, cli, ephemeral } = selfInvocation();
  const notes: string[] = [];
  if (ephemeral) notes.push('Warning: ai-bom is running from the npx cache, which can be cleared. Install it permanently (npm i -g) and re-run --install.');
  const log = path.join(dataDir(), 'watch.log');
  if (process.platform === 'darwin') {
    const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
    const x = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
    await writeAtomic(
      plist,
      `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array><string>${x(node)}</string><string>${x(cli)}</string><string>watch</string><string>--once</string></array>
  <key>StartInterval</key><integer>${intervalMin * 60}</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>${x(log)}</string>
  <key>StandardErrorPath</key><string>${x(log)}</string>
</dict></plist>
`,
      0o644,
    );
    const uid = String(process.getuid?.() ?? '');
    await new Promise<void>((r) => execFile('launchctl', ['bootout', `gui/${uid}/${LABEL}`], () => r()));
    await new Promise<void>((r, j) => execFile('launchctl', ['bootstrap', `gui/${uid}`, plist], (e) => (e ? j(new Error(`launchctl: ${e.message}`)) : r())));
    notes.push(`Installed ${plist}; checks every ${intervalMin} minutes. Log: ${log}`);
  } else if (process.platform === 'linux') {
    const dir = path.join(os.homedir(), '.config', 'systemd', 'user');
    await fs.mkdir(dir, { recursive: true });
    await writeAtomic(path.join(dir, 'ai-bom-watch.service'), `[Unit]\nDescription=AI-BOM watch\n\n[Service]\nType=oneshot\nExecStart=${node} ${cli} watch --once\n`, 0o644);
    await writeAtomic(path.join(dir, 'ai-bom-watch.timer'), `[Unit]\nDescription=AI-BOM watch every ${intervalMin} minutes\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=${intervalMin}min\n\n[Install]\nWantedBy=timers.target\n`, 0o644);
    await new Promise<void>((r) => execFile('systemctl', ['--user', 'daemon-reload'], () => r()));
    await new Promise<void>((r, j) => execFile('systemctl', ['--user', 'enable', '--now', 'ai-bom-watch.timer'], (e) => (e ? j(new Error(`systemctl: ${e.message}`)) : r())));
    notes.push(`Installed a systemd user timer (ai-bom-watch.timer); checks every ${intervalMin} minutes.`);
  } else throw new Error('Background watch is supported on macOS and Linux.');
  return notes;
}

/** Is the background service set up (launchd agent on macOS, systemd user timer on Linux)? */
export async function watchInstalled(): Promise<boolean> {
  const file =
    process.platform === 'darwin'
      ? path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`)
      : process.platform === 'linux'
        ? path.join(os.homedir(), '.config', 'systemd', 'user', 'ai-bom-watch.timer')
        : undefined;
  if (!file) return false;
  return fs.access(file).then(() => true, () => false);
}

export async function uninstallService(): Promise<string> {
  if (process.platform === 'darwin') {
    const plist = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
    await new Promise<void>((r) => execFile('launchctl', ['bootout', `gui/${process.getuid?.()}/${LABEL}`], () => r()));
    await fs.rm(plist, { force: true });
    return `Removed ${plist}.`;
  }
  if (process.platform === 'linux') {
    await new Promise<void>((r) => execFile('systemctl', ['--user', 'disable', '--now', 'ai-bom-watch.timer'], () => r()));
    const dir = path.join(os.homedir(), '.config', 'systemd', 'user');
    await fs.rm(path.join(dir, 'ai-bom-watch.timer'), { force: true });
    await fs.rm(path.join(dir, 'ai-bom-watch.service'), { force: true });
    return 'Removed the systemd user timer.';
  }
  return 'Nothing to remove.';
}
