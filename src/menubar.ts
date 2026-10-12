import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import type { Inventory } from './types.js';
import { selfInvocation } from './selfcmd.js';
import { writeAtomic } from './util/store.js';

/**
 * macOS menu bar: a SwiftBar / xbar plugin. The plugin script just runs
 * `ai-bom menubar`, which scans and prints the menu in their text format:
 * score in the bar; top findings, the next best action and quick actions
 * in the dropdown.
 */

const esc = (s: string) => s.replace(/\|/g, '¦').replace(/\n/g, ' ').slice(0, 90);

export function menubarText(inv: Inventory): string {
  const { node, cli } = selfInvocation();
  const run = (...args: string[]) => `bash="${node}" ${[cli, ...args].map((a, i) => `param${i + 1}="${a}"`).join(' ')}`;
  const score = inv.score;
  const active = inv.findings.filter((f) => !f.muted);
  const top = active.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const color = !score ? '' : score.value >= 75 ? '' : score.value >= 40 ? ' color=#c98500' : ' color=#d03b3b';
  const lines = [
    `${top.length ? '⚠︎ ' : ''}AI ${score?.value ?? '–'} |${color} sfimage=${top.length ? 'exclamationmark.shield' : 'checkmark.shield'} tooltip=AI-BOM security score`,
    '---',
    `Security score ${score?.value ?? '–'}/100 (${score?.grade ?? '–'}) | size=13`,
    `${inv.assets.length} AI assets · ${active.length} open finding${active.length === 1 ? '' : 's'} | size=12 color=gray`,
  ];
  const next = score?.next[0];
  if (next) {
    lines.push('---', 'Next best action | size=11 color=gray');
    lines.push(`${esc(next.title)} (+${next.gain}) | ${next.fix ? run('fix', next.findingId) + ' terminal=true' : run('ui') + ' terminal=false'}`);
  }
  if (top.length) {
    lines.push('---', `${top.length} critical/high | size=11 color=gray`);
    const name = new Map(inv.assets.map((a) => [a.id, a.name]));
    for (const f of top.slice(0, 8)) lines.push(`${f.severity === 'critical' ? '🔴' : '🟠'} ${esc(f.title)}${f.assetId ? ` — ${esc(name.get(f.assetId) ?? '')}` : ''} | ${run('ui')} terminal=false`);
    if (top.length > 8) lines.push(`…and ${top.length - 8} more | ${run('ui')} terminal=false`);
  }
  const fresh = inv.assets.filter((a) => a.isNew);
  if (fresh.length) {
    lines.push('---', `${fresh.length} new since last scan | size=11 color=gray`);
    for (const a of fresh.slice(0, 5)) lines.push(`${esc(a.name)} (${a.kind}) | ${run('ui')} terminal=false`);
  }
  lines.push('---', `Open dashboard | ${run('ui')} terminal=false`, 'Rescan | refresh=true', `Undo last change | ${run('undo')} terminal=true`, `Scanned ${new Date(inv.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} | size=11 color=gray`);
  return lines.join('\n');
}

function pluginDirs(): string[] {
  const home = os.homedir();
  const out: string[] = [];
  try {
    const d = execFileSync('defaults', ['read', 'com.ameba.SwiftBar', 'PluginDirectory'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (d) out.push(d.replace(/^~/, home));
  } catch {
    /* SwiftBar not configured */
  }
  out.push(path.join(home, 'Library', 'Application Support', 'xbar', 'plugins'), path.join(home, 'Library', 'Application Support', 'SwiftBar', 'Plugins'));
  return [...new Set(out)];
}

export async function installMenubar(minutes = 30): Promise<string> {
  if (process.platform !== 'darwin') throw new Error('The menu bar plugin is for macOS (SwiftBar or xbar).');
  const { node, cli, ephemeral } = selfInvocation();
  let dir: string | undefined;
  for (const d of pluginDirs()) {
    try {
      await fs.access(d);
      dir = d;
      break;
    } catch {
      /* next */
    }
  }
  if (!dir) throw new Error('Install SwiftBar (brew install --cask swiftbar) or xbar first, pick its plugin folder, then run this again.');
  const file = path.join(dir, `ai-bom.${minutes}m.sh`);
  await writeAtomic(
    file,
    `#!/bin/sh\n# <xbar.title>AI-BOM</xbar.title>\n# <xbar.desc>Security score and risky AI config at a glance.</xbar.desc>\n# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>\nexec "${node}" "${cli}" menubar\n`,
    0o755,
  );
  return `Installed ${file.replace(os.homedir(), '~')}${ephemeral ? ' (warning: ai-bom runs from the npx cache; install it permanently)' : ''}.`;
}

export async function uninstallMenubar(): Promise<string> {
  const removed: string[] = [];
  for (const d of pluginDirs()) {
    for (const n of await fs.readdir(d).catch(() => [] as string[])) {
      if (/^ai-bom\.\d+[smhd]\.sh$/.test(n)) {
        await fs.rm(path.join(d, n));
        removed.push(n);
      }
    }
  }
  return removed.length ? `Removed ${removed.join(', ')}.` : 'No AI-BOM menu bar plugin found.';
}
