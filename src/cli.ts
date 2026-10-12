#!/usr/bin/env node
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';
import { DEFAULT_CONNECTORS_FILE, DEFAULT_HISTORY_FILE, DEFAULT_NVD_CACHE, scan, VERSION, type ScanOptions } from './scan.js';
import { renderSummary } from './report.js';
import { toCycloneDX } from './bom/cyclonedx.js';
import { serve } from './server/serve.js';
import { severityRank } from './checks/index.js';
import { addConnector, loadConnectors, markReviewed, PLATFORMS, removeConnector } from './connectors.js';
import type { FixKind, Inventory, Severity } from './types.js';
import { addCommand, upgradeCommand, inspectCommand, timelineCommand, incidentCommand, contextCommand, menubarCommand, baselineCommand, checkCommand, stateCommand, explainCommand, fixCommand, guardCommand, reportCommand, snapshotsCommand, triageCommand, undoCommand, updateCommand, watchCommand } from './commands.js';
import { dashboardActions, dashboardDownloads } from './server/actions.js';
import { defaultTriageFile } from './triage.js';
import { dataDir } from './util/store.js';
import { doctorScan } from './doctor.js';
import { tilde as tildePath } from './util/paths.js';

const HELP = `ai-bom ${VERSION} — inventory the AI assets on your machine and check them

Usage:
  ai-bom [ui]                  Scan and open the dashboard (default)
  ai-bom scan                  Scan and print a summary
  ai-bom report                Write a shareable report (--html, --sarif, --markdown)
  ai-bom check [target]        Pre-flight check of something you did not write: a repository folder or
                               git URL, a skill folder, a SKILL.md, or a .zip/.skill download.
                               Nothing is installed or run. (exit 0 safe, 1 review, 2 dangerous; --sarif for CI)
       check --install-hook    Check every project when a Claude Code session starts
  ai-bom fix                   List findings with an automatic, reversible fix
  ai-bom fix <id|name>         Preview a fix, confirm, apply (--kind <fix>, --dry-run, --yes)
  ai-bom undo [snapshot]       Undo the last (or a given) change made by ai-bom (--force)
  ai-bom snapshots             List changes made by ai-bom
  ai-bom triage [list]         Muted findings
  ai-bom triage accept <id> --reason "…"      Accept a risk
  ai-bom triage snooze <id> 30d [--reason …]  Hide until a date (30d, 2w, 3m or YYYY-MM-DD)
  ai-bom triage fp <id> [--reason …]          Mark as a false positive
  ai-bom triage clear <id>                    Make it active again
  ai-bom watch                 Rescan when AI config changes; notify about new assets/risks
       watch --install         Run in the background (launchd / systemd), --uninstall to stop
  ai-bom guard --install       Check every MCP tool call live in Claude Code (--uninstall)
  ai-bom explain <name>        Plain-language AI review of one skill/hook/server (opt-in;
                               --local uses Ollama, nothing leaves your machine)
  ai-bom add <package|url>     Vet a server before adding it (downloads, never runs), then add it
                               pinned to your AI tools (--to claude-code,cursor --secret KEY --name n)
  ai-bom upgrade [name]        List updates; for one server, show what changes, then pin it
  ai-bom inspect <server>      Run a server once in a sandbox (no network, no secrets) and list
                               its real tools; compare with its code
  ai-bom timeline [session]    What your agents did: commands, files, fetches, MCP calls (--days 7)
  ai-bom incident              Pause servers and data-sending hooks (undoable), list keys to rotate,
                               write a report with the activity timeline (--keep a,b --no-pause)
  ai-bom context               Tokens your setup adds to every conversation, per agent
  ai-bom menubar --install     macOS menu bar (SwiftBar or xbar): score and top risks
  ai-bom baseline [nist|iso|atlas]  Your setup against NIST AI RMF, ISO/IEC 42001 and MITRE ATLAS
       baseline mark <nist|iso> <control> [--na] [--notes "…"]   Answer a control a scan can't check
  ai-bom update                Fetch the latest signed advisory feed
  ai-bom state                 Show what AI-BOM keeps in ~/.ai-bom (muted findings, fixes, history…)
  ai-bom state export <file>   Back up your triage decisions, connectors and preferences
  ai-bom state import <file>   Restore them (merges; --force replaces)
  ai-bom connectors            List the cloud connectors you registered
  ai-bom connectors add <platform> <name> [--access read|read-write] [--notes text]
  ai-bom connectors remove <id> | review <id>
  ai-bom doctor [--all]        Show every location checked and what was found there

Scan options:
  -p, --project <dir>    Also scan this project directory (repeatable)
  -d, --discover <dir>   Find projects with AI config under <dir>, e.g. ~/code (repeatable)
      --online           Also query OSV.dev, the NIST NVD, npm/PyPI and the official MCP Registry
                         (sends package names and versions only). NVD_API_KEY speeds up NVD.
      --no-known         Skip projects remembered by Claude Code (~/.claude.json)
      --no-auto-discover Don't sweep ~/Projects, ~/code, ~/Developer… for projects
      --no-cwd           Don't treat the current directory as a project
      --no-history       Don't save/compare with the previous scan
      --no-session-logs  Don't read Claude Code session logs (usage + tool-call audit)
      --no-tool-analysis Don't read MCP server code to compare tools with their descriptions
      --full-paths       Keep absolute home paths instead of "~"

Output (scan):
      --json [file]      Write the full inventory as JSON (stdout if no file)
      --cyclonedx <file> Write a CycloneDX 1.6 AI-BOM
      --fail-on <sev>    Exit 1 if an active finding at/above severity exists

Dashboard (ui):
      --port <n>         Port to listen on (default 7654)
      --no-open          Don't open the browser

Everything runs locally. Nothing is uploaded unless you pass --online or ask for an AI review.
Secret values are redacted from all output. Every change ai-bom makes can be undone.
`;

function expandHome(p: string): string {
  return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : p;
}

async function connectorsCommand(args: string[], values: { access?: string; notes?: string }) {
  const [sub = 'list', ...rest] = args;
  const file = DEFAULT_CONNECTORS_FILE;
  if (sub === 'list') {
    const list = await loadConnectors(file);
    if (!list.length) return console.log(`No connectors registered. Add one with:\n  ai-bom connectors add claude.ai Gmail --access read-write`);
    for (const c of list) {
      const reviewed = c.reviewedAt ? new Date(c.reviewedAt).toLocaleDateString() : 'never';
      console.log(`${c.id}  ${c.platform.padEnd(18)} ${c.name.padEnd(20)} ${c.access.padEnd(10)} reviewed ${reviewed}`);
    }
    return;
  }
  if (sub === 'add') {
    const [platform, ...nameParts] = rest;
    if (!platform || !nameParts.length) throw new Error(`Usage: ai-bom connectors add <platform> <name>\nPlatforms: ${PLATFORMS.join(', ')}`);
    const rec = await addConnector(file, { platform, name: nameParts.join(' '), access: values.access, notes: values.notes });
    return console.log(`Added ${rec.name} (${rec.platform}) — id ${rec.id}`);
  }
  if (sub === 'remove' || sub === 'review') {
    const id = rest[0];
    if (!id) throw new Error(`Usage: ai-bom connectors ${sub} <id>`);
    const ok = sub === 'remove' ? await removeConnector(file, id) : await markReviewed(file, id);
    if (!ok) throw new Error(`No connector with id ${id}`);
    return console.log(sub === 'remove' ? 'Removed.' : 'Marked as reviewed.');
  }
  throw new Error(`Unknown connectors command "${sub}"`);
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      project: { type: 'string', short: 'p', multiple: true },
      discover: { type: 'string', short: 'd', multiple: true },
      online: { type: 'boolean' },
      'no-known': { type: 'boolean' },
      'no-auto-discover': { type: 'boolean' },
      'no-cwd': { type: 'boolean' },
      'no-history': { type: 'boolean' },
      'full-paths': { type: 'boolean' },
      json: { type: 'boolean' },
      cyclonedx: { type: 'string' },
      'fail-on': { type: 'string' },
      port: { type: 'string' },
      'no-open': { type: 'boolean' },
      access: { type: 'string' },
      all: { type: 'boolean' },
      notes: { type: 'string' },
      'no-session-logs': { type: 'boolean' },
      'no-tool-analysis': { type: 'boolean' },
      html: { type: 'string' },
      sarif: { type: 'string' },
      markdown: { type: 'string' },
      hook: { type: 'boolean' },
      'install-hook': { type: 'boolean' },
      install: { type: 'boolean' },
      uninstall: { type: 'boolean' },
      once: { type: 'boolean' },
      interval: { type: 'string' },
      kind: { type: 'string' },
      yes: { type: 'boolean', short: 'y' },
      'dry-run': { type: 'boolean' },
      force: { type: 'boolean' },
      reason: { type: 'string' },
      local: { type: 'boolean' },
      model: { type: 'string' },
      to: { type: 'string' },
      name: { type: 'string' },
      secret: { type: 'string', multiple: true },
      keep: { type: 'string' },
      days: { type: 'string' },
      'no-pause': { type: 'boolean' },
      na: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  if (values.help) return void process.stdout.write(HELP);
  if (values.version) return void console.log(VERSION);

  const [command = 'ui', ...rest] = positionals;
  if (command === 'connectors') return connectorsCommand(rest, values);
  if (command === 'undo') return undoCommand(rest, values);
  if (command === 'snapshots') return snapshotsCommand();
  if (command === 'update') return updateCommand();
  if (command === 'state') return stateCommand(rest, values);
  const known = ['ui', 'scan', 'doctor', 'report', 'check', 'fix', 'triage', 'watch', 'guard', 'explain', 'add', 'upgrade', 'inspect', 'timeline', 'incident', 'context', 'menubar', 'baseline', 'baselines'];
  if (!known.includes(command)) {
    process.stderr.write(`Unknown command "${command}"\n\n${HELP}`);
    process.exit(2);
  }
  const failOn = values['fail-on'] as Severity | undefined;
  if (failOn && severityRank(failOn) < 0) throw new Error(`Invalid --fail-on value "${failOn}"`);

  const projects = (values.project ?? []).map(expandHome);
  const cwd = process.cwd();
  if (!values['no-cwd'] && cwd !== os.homedir()) projects.push(cwd);
  const opts: ScanOptions = {
    projects,
    discover: (values.discover ?? []).map(expandHome),
    knownProjects: !values['no-known'],
    autoDiscover: !values['no-auto-discover'],
    historyFile: values['no-history'] ? undefined : DEFAULT_HISTORY_FILE,
    keepHomePaths: values['full-paths'],
    connectorsFile: DEFAULT_CONNECTORS_FILE,
    online: values.online,
    nvdApiKey: process.env.NVD_API_KEY || undefined,
    nvdCacheFile: DEFAULT_NVD_CACHE,
    claudeConfigDir: process.env.CLAUDE_CONFIG_DIR || undefined,
    triageFile: defaultTriageFile(),
    toolHashesFile: path.join(dataDir(), 'tool-hashes.json'),
    sessionLogs: !values['no-session-logs'],
    toolAnalysis: !values['no-tool-analysis'],
  };

  if (command === 'doctor') return doctor(opts, !!values.all);
  if (command === 'guard') return guardCommand(values, opts);
  if (command === 'check') {
    process.exitCode = await checkCommand(rest, opts, values);
    return;
  }
  if (command === 'report') return reportCommand(opts, values);
  if (command === 'fix') return fixCommand(rest, opts, values as { kind?: FixKind; yes?: boolean; 'dry-run'?: boolean });
  if (command === 'triage') return triageCommand(rest, opts, values);
  if (command === 'watch') return watchCommand(opts, values);
  if (command === 'explain') return explainCommand(rest, opts, values);
  if (command === 'add') return addCommand(rest, opts, { ...values, project: values.project });
  if (command === 'upgrade') return upgradeCommand(rest, opts, values);
  if (command === 'inspect') return inspectCommand(rest, opts, values);
  if (command === 'timeline') return timelineCommand(rest, opts, values);
  if (command === 'incident') return incidentCommand(opts, values);
  if (command === 'context') return contextCommand(opts);
  if (command === 'menubar') return menubarCommand(opts, values);
  if (command === 'baseline' || command === 'baselines') return baselineCommand(rest, opts, values);

  if (command === 'scan') {
    const jsonFile = rest[0];
    const inv = await scan({ ...opts, recordAs: 'scan' });
    if (values.json) {
      const out = JSON.stringify(inv, null, 2);
      if (jsonFile) await fs.writeFile(jsonFile, out, { mode: 0o600 });
      else process.stdout.write(out + '\n');
    }
    if (values.cyclonedx) await fs.writeFile(values.cyclonedx, JSON.stringify(toCycloneDX(inv), null, 2), { mode: 0o600 });
    if (!values.json || jsonFile) console.log(renderSummary(inv));
    if (failOn && inv.findings.some((f) => !f.muted && severityRank(f.severity) <= severityRank(failOn))) process.exit(1);
    return;
  }

  // ui
  let inventory = await scan({ ...opts, recordAs: 'dashboard' });
  console.log(renderSummary(inventory));
  const sessionStart = inventory;
  let online = !!opts.online;
  const run = async (o: { online?: boolean; record?: boolean }): Promise<Inventory> => {
    if (o.online !== undefined) online = o.online;
    // Compare against the pre-session snapshot without overwriting it, and keep
    // everything that was already "new" when the dashboard opened.
    const fresh = await scan({ ...opts, online, historyReadOnly: true, recordAs: o.record ? (online ? 'dashboard (online)' : 'dashboard') : undefined });
    const newAtStart = new Set(sessionStart.assets.filter((a) => a.isNew).map((a) => a.id));
    for (const a of fresh.assets) if (newAtStart.has(a.id)) a.isNew = true;
    const removed = new Map([...(sessionStart.removed ?? []), ...(fresh.removed ?? [])].map((r) => [r.id, r]));
    inventory = { ...fresh, removed: [...removed.values()] };
    return inventory;
  };
  // One scan at a time, in request order: a late finisher can't overwrite a newer inventory.
  let queue: Promise<unknown> = Promise.resolve();
  const rescan = (o: { online?: boolean; record?: boolean } = {}): Promise<Inventory> => {
    const next = queue.then(() => run(o));
    queue = next.catch(() => {});
    return next;
  };
  const server = await serve({
    port: Number(values.port ?? 7654),
    getInventory: async () => inventory,
    rescan,
    connectors: {
      add: async (input) => void (await addConnector(DEFAULT_CONNECTORS_FILE, input)),
      remove: (id) => removeConnector(DEFAULT_CONNECTORS_FILE, id),
      review: (id) => markReviewed(DEFAULT_CONNECTORS_FILE, id),
    },
    actions: dashboardActions({ opts, getInventory: async () => inventory, rescan }),
    downloads: dashboardDownloads(async () => inventory),
  });
  console.log(`\nDashboard: ${server.url}  (Ctrl+C to stop)`);
  if (!values['no-open']) openBrowser(server.url);
}

/** Explain what the scanner saw, for troubleshooting "nothing found". Prints names and counts, never values. */
async function doctor(opts: ScanOptions, all: boolean) {
  const home = os.homedir();
  const tilde = (p: string) => tildePath(p, home);
  const { inv, trace, found, errors, missing } = await doctorScan(opts, home);
  const out: string[] = [];
  out.push(`ai-bom ${VERSION} doctor — node ${process.version}, ${process.platform}`);
  out.push(`Claude config dir: ${tilde(opts.claudeConfigDir ?? path.join(home, '.claude'))}${process.env.CLAUDE_CONFIG_DIR ? ' (from CLAUDE_CONFIG_DIR)' : ''}`);
  out.push('');
  out.push(`AI tools detected: ${inv.clients.map((c) => c.name).join(', ') || 'none'}`);
  const byKind = new Map<string, number>();
  for (const a of inv.assets) byKind.set(a.kind, (byKind.get(a.kind) ?? 0) + 1);
  out.push(`Assets: ${inv.assets.length}${byKind.size ? ` (${[...byKind].map(([k, n]) => `${n} ${k}`).join(', ')})` : ''}`);
  out.push(`Projects scanned: ${new Set(trace.map((t) => t.note?.match(/ for (.+)$/)?.[1]).filter(Boolean)).size} with MCP config · ${inv.projects.length} with any assets`);
  out.push('');
  out.push(`Found (${found.length}):`);
  for (const t of found) out.push(`  ${t.path}${t.note ? `  —  ${t.note}` : ''}`);
  if (errors.length) {
    out.push('');
    out.push(`Could not read (${errors.length}):`);
    for (const t of errors) out.push(`  ${t.path}  —  ${t.note ?? ''}`);
  }
  out.push('');
  out.push(`Checked but not present: ${missing.length} location(s)${all ? ':' : ' (add --all to list them)'}`);
  if (all) for (const p of missing) out.push(`  ${p}`);
  // Folder listings (names only) of the places that usually hold AI config.
  const listing = async (dir: string) => {
    try {
      const names = (await fs.readdir(dir)).filter((n) => !n.startsWith('.DS_Store'));
      return names.length ? names.slice(0, 40).join('  ') + (names.length > 40 ? `  … (+${names.length - 40})` : '') : '(empty)';
    } catch {
      return '(not present)';
    }
  };
  const claudeDir = opts.claudeConfigDir ?? path.join(home, '.claude');
  out.push('');
  out.push('Folder contents (names only):');
  for (const d of [claudeDir, path.join(claudeDir, 'plugins'), path.join(claudeDir, 'plugins', 'cache'), path.join(claudeDir, 'plugins', 'marketplaces'), path.join(claudeDir, 'skills'), path.join(claudeDir, 'agents'), path.join(home, 'Library', 'Application Support', 'Claude')]) {
    out.push(`  ${tilde(d)}: ${await listing(d)}`);
  }
  out.push('');
  out.push('Nothing here contains secret values: only file names, key names and counts.');
  console.log(out.join('\n'));
}

function openBrowser(url: string) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try {
    spawn(cmd, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
  } catch {
    /* no browser available */
  }
}

main().catch((e) => {
  console.error(`ai-bom: ${(e as Error).message}`);
  process.exit(1);
});
