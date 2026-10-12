import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { promises as fs } from 'node:fs';
import type { Asset, FixKind, Inventory } from './types.js';
import { scan, type ScanOptions } from './scan.js';
import { applyFix, FIX_LABEL, listSnapshots, planFix, publicPlan, undoFix, type FixContext } from './fix/index.js';
import { defaultSecretStore } from './fix/keychain.js';
import { clearTriage, defaultTriageFile, loadTriage, setTriage } from './triage.js';
import { preflight, hookMessage } from './preflight.js';
import { toSarif } from './reports/sarif.js';
import { toHtml } from './reports/html.js';
import { toMarkdown } from './reports/markdown.js';
import { updateFeed } from './feed/index.js';
import { runGuard } from './guard.js';
import { installService, uninstallService, watchLoop, watchOnce } from './watch.js';
import { reviewInput, reviewWithClaude, reviewWithOllama, type Review } from './review/explain.js';
import { selfInvocation } from './selfcmd.js';
import { renderSummary } from './report.js';
import { setSafeguard } from './safeguards.js';
import { describeState, exportState, importState, readScans } from './state.js';

/** CLI commands beyond scan/ui. Each prints plain text and throws on errors. */

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const color = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = color('1');
const dim = color('2');
const red = color('31');
const green = color('32');
const yellow = color('33');

async function confirm(q: string, yes?: boolean): Promise<boolean> {
  if (yes) return true;
  if (!process.stdin.isTTY) throw new Error('Not a terminal: re-run with --yes to confirm.');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const a = await rl.question(`${q} [y/N] `);
  rl.close();
  return /^y(es)?$/i.test(a.trim());
}

function fixContext(inv: Inventory, opts: ScanOptions): FixContext {
  return { home: opts.home ?? os.homedir(), inventory: inv, claudeDir: opts.claudeConfigDir, secretStore: defaultSecretStore() };
}

/** Resolve "a1b2c3" (finding id / prefix) or an asset name. */
function resolveTarget(inv: Inventory, ref: string): { findingId?: string; assetId?: string } {
  const f = inv.findings.filter((x) => x.id.startsWith(ref));
  if (f.length === 1) return { findingId: f[0].id };
  const a = inv.assets.filter((x) => x.name === ref || x.id === ref);
  if (a.length === 1) return { assetId: a[0].id };
  if (f.length > 1 || a.length > 1) throw new Error(`"${ref}" is ambiguous; use more characters of the finding id.`);
  throw new Error(`No finding or asset "${ref}". Run \`ai-bom fix\` to list what can be fixed.`);
}

function printPlan(p: ReturnType<typeof publicPlan>) {
  console.log(`\n${bold(p.title)}  ${dim(`(${p.label})`)}`);
  console.log(p.summary);
  for (const w of p.warnings) console.log(yellow(`! ${w}`));
  for (const c of p.changes) {
    console.log(`\n${bold(c.file.replace(os.homedir(), '~'))}  ${dim(c.description)}`);
    if (c.diff) for (const l of c.diff.split('\n')) console.log(l.startsWith('+ ') ? green(l) : l.startsWith('- ') ? red(l) : dim(l));
  }
  if (p.manual.length) {
    console.log(`\n${bold('Also change by hand:')}`);
    for (const m of p.manual) console.log(`  • ${m}`);
  }
}

export async function fixCommand(args: string[], opts: ScanOptions, v: { kind?: string; yes?: boolean; 'dry-run'?: boolean }) {
  const inv = await scan({ ...opts, keepHomePaths: false, historyFile: undefined });
  if (!args[0]) {
    const fixable = inv.findings.filter((f) => f.fixes?.length && !f.muted);
    if (!fixable.length) return console.log('Nothing can be fixed automatically right now.');
    const name = new Map(inv.assets.map((a) => [a.id, a.name]));
    console.log(bold(`${fixable.length} finding(s) with an automatic, reversible fix:\n`));
    for (const f of fixable) console.log(`  ${f.id}  ${f.severity.padEnd(8)} ${f.title}${f.assetId ? dim(` — ${name.get(f.assetId)}`) : ''}\n${' '.repeat(16)}${dim(f.fixes!.map((k) => `${k} (${FIX_LABEL[k]})`).join(', '))}`);
    console.log(`\nPreview and apply one:  ai-bom fix <id> [--kind <fix>]`);
    return;
  }
  const target = resolveTarget(inv, args[0]);
  const ctx = fixContext(inv, opts);
  const plan = await planFix(ctx, target, v.kind as FixKind | undefined);
  printPlan(publicPlan(plan));
  if (v['dry-run']) return;
  if (!plan.ops.length) return;
  if (!(await confirm('\nApply this change?', v.yes))) return console.log('Nothing changed.');
  const snap = await applyFix(ctx, target, plan.kind, plan.key);
  console.log(green(`\nDone.`) + ` Undo any time with: ${bold(`ai-bom undo ${snap.id}`)}`);
}

export async function undoCommand(args: string[], v: { force?: boolean }) {
  const list = await listSnapshots();
  const id = args[0] ?? list.find((s) => s.status === 'applied')?.id;
  if (!id) return console.log('Nothing to undo.');
  const s = await undoFix(id, defaultSecretStore(), v.force);
  console.log(`${green('Undone:')} ${s.title}`);
}

export async function snapshotsCommand() {
  const list = await listSnapshots();
  if (!list.length) return console.log('No changes made by ai-bom yet.');
  for (const s of list) console.log(`${s.id}  ${s.status === 'undone' ? dim('undone ') : green('applied')}  ${s.title}  ${dim(s.files.map((f) => f.replace(os.homedir(), '~')).join(', '))}`);
}

export async function triageCommand(args: string[], opts: ScanOptions, v: { reason?: string }) {
  const [sub = 'list', ref, until] = args;
  const file = defaultTriageFile();
  if (sub === 'list') {
    const entries = await loadTriage(file);
    const ids = Object.keys(entries);
    if (!ids.length) return console.log('No triage decisions yet. Use: ai-bom triage accept <finding-id> --reason "…"');
    for (const id of ids) {
      const e = entries[id];
      const expired = e.status === 'snoozed' && e.until && Date.parse(e.until) <= Date.now();
      console.log(`${id}  ${e.status.padEnd(14)} ${e.title ?? e.ruleId ?? ''}${e.until ? dim(` until ${e.until.slice(0, 10)}${expired ? ' (expired)' : ''}`) : ''}${e.reason ? dim(` — ${e.reason}`) : ''}`);
    }
    return;
  }
  if (!ref) throw new Error(`Usage: ai-bom triage ${sub} <finding-id>${sub === 'snooze' ? ' <30d|2w|YYYY-MM-DD>' : ''} [--reason "…"]`);
  if (sub === 'clear') {
    if (!(await clearTriage(file, ref))) throw new Error(`No triage decision for ${ref}`);
    return console.log('Cleared; the finding is active again.');
  }
  const status = sub === 'accept' ? 'accepted' : sub === 'snooze' ? 'snoozed' : sub === 'fp' || sub === 'false-positive' ? 'false-positive' : undefined;
  if (!status) throw new Error(`Unknown triage command "${sub}" (accept | snooze | fp | clear | list)`);
  const inv = await scan({ ...opts, historyFile: undefined, sessionLogs: false });
  const f = inv.findings.filter((x) => x.id.startsWith(ref));
  if (f.length !== 1) throw new Error(f.length ? 'Ambiguous finding id.' : `No finding ${ref}.`);
  const e = await setTriage(file, f[0].id, { status, reason: v.reason, until, ruleId: f[0].ruleId, title: f[0].title });
  console.log(`${f[0].title}: ${e.status}${e.until ? ` until ${e.until.slice(0, 10)}` : ''}.`);
}

export async function reportCommand(opts: ScanOptions, v: { html?: string; sarif?: string; markdown?: string }) {
  const inv = await scan(opts);
  const { baselines } = await import('./frameworks/baselines.js');
  const base = await baselines(inv);
  const outs: [string | undefined, () => string][] = [
    [v.html ?? (!v.sarif && !v.markdown ? 'ai-bom-report.html' : undefined), () => toHtml(inv, undefined, base)],
    [v.sarif, () => JSON.stringify(toSarif(inv), null, 2)],
    [v.markdown, () => toMarkdown(inv, undefined, base)],
  ];
  for (const [file, make] of outs) {
    if (!file) continue;
    await fs.writeFile(file, make(), { mode: 0o600 });
    console.log(`Wrote ${file}`);
  }
}

async function readStdinJson(): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return {};
  }
}

export async function checkCommand(args: string[], opts: ScanOptions, v: { json?: boolean; sarif?: string; hook?: boolean; 'install-hook'?: boolean; markdown?: string }): Promise<number> {
  if (v['install-hook']) {
    const snap = await setSafeguard('preflight', true, opts.claudeConfigDir);
    if (!snap) {
      console.log('The pre-flight hook is already installed.');
      return 0;
    }
    if (selfInvocation().ephemeral) console.log(yellow('! ai-bom is running from the npx cache; install it permanently so the hook keeps working.'));
    console.log(`Installed: Claude Code will check each project when a session starts.\nRemove with: ai-bom undo ${snap.id}`);
    return 0;
  }
  if (v.hook) {
    const input = await readStdinJson();
    const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd();
    if (path.resolve(cwd) === os.homedir()) return 0;
    try {
      const r = await preflight(cwd, { ...opts, triageFile: opts.triageFile });
      const out = hookMessage(r);
      if (Object.keys(out).length) process.stdout.write(JSON.stringify(out));
    } catch {
      /* never block a session on our own failure */
    }
    return 0;
  }
  const target = args[0] ?? '.';
  const r = await preflight(target, { online: opts.online, triageFile: opts.triageFile, fetchImpl: opts.fetchImpl });
  try {
    if (v.sarif) await fs.writeFile(v.sarif, JSON.stringify(toSarif(r.inventory, { baseDir: r.dir }), null, 2));
    if (v.markdown) await fs.writeFile(v.markdown, toMarkdown(r.inventory, `AI-BOM pre-flight: ${target}`));
    if (v.json) {
      process.stdout.write(JSON.stringify({ target, verdict: r.verdict, autorun: r.autorun, findings: r.inventory.findings, assets: r.inventory.assets }, null, 2) + '\n');
    } else {
      const label = r.verdict === 'dangerous' ? red(bold('DANGEROUS')) : r.verdict === 'review' ? yellow(bold('REVIEW')) : green(bold('SAFE'));
      console.log(`${bold('Pre-flight check:')} ${target}  →  ${label}\n`);
      if (r.autorun.length) {
        console.log(bold('What this repository sets up for your AI tools:'));
        for (const x of r.autorun) console.log(`  • ${x}`);
        console.log('');
      } else console.log(dim('It does not configure any hooks, MCP servers or auto-run tasks.\n'));
      const active = r.inventory.findings.filter((f) => !f.muted);
      if (active.length) {
        console.log(bold('Findings:'));
        for (const f of active) console.log(`  ${f.severity.toUpperCase().padEnd(8)} ${f.title}${f.location ? dim(` — ${f.location}`) : ''}${f.evidence ? `\n           ${dim(f.evidence)}` : ''}`);
      }
      const kinds = r.inventory.assets.filter((a) => ['skill', 'agent', 'command', 'instructions'].includes(a.kind));
      if (kinds.length) console.log(dim(`\nAlso brings ${kinds.length} skill/agent/command/instruction file(s) your agent will read.`));
    }
  } finally {
    await r.cleanup();
  }
  return r.verdict === 'dangerous' ? 2 : r.verdict === 'review' ? 1 : 0;
}

export async function guardCommand(v: { install?: boolean; uninstall?: boolean }, opts: ScanOptions) {
  if (v.install) {
    const snap = await setSafeguard('guard', true, opts.claudeConfigDir);
    if (!snap) return console.log('The guard is already installed.');
    console.log(`Installed: every MCP tool call is checked before it runs and its result after.\nRemove with: ai-bom guard --uninstall (or ai-bom undo ${snap.id})`);
    return;
  }
  if (v.uninstall) {
    const snap = await setSafeguard('guard', false, opts.claudeConfigDir);
    if (!snap) return console.log('The guard is not installed.');
    return console.log(`Removed. (ai-bom undo ${snap.id} puts it back.)`);
  }
  await runGuard();
}

export async function watchCommand(opts: ScanOptions, v: { once?: boolean; install?: boolean; uninstall?: boolean; interval?: string }) {
  const minutes = Math.max(5, Number(v.interval ?? 30) || 30);
  if (v.install) return (await installService(minutes)).forEach((n) => console.log(n));
  if (v.uninstall) return console.log(await uninstallService());
  const o = { ...opts, historyFile: undefined };
  if (v.once) {
    const changes = await watchOnce(o);
    console.log(`${new Date().toISOString()} ${changes.length ? changes.map((c) => c.title).join('; ') : 'no changes'}`);
    return;
  }
  console.log(`Watching your AI config (rescans on change and every ${minutes} min). Ctrl+C to stop.`);
  await watchLoop(o, minutes * 60_000, (s) => console.log(s));
}

export async function updateCommand() {
  const r = await updateFeed();
  console.log(r.message);
  if (r.status === 'error') process.exitCode = 1;
}

export function formatReview(a: Asset, r: Review): string {
  const verdict = r.verdict === 'avoid' ? red(bold('Avoid')) : r.verdict === 'review' ? yellow(bold('Review')) : green(bold('Looks fine'));
  const list = (title: string, xs: string[]) => (xs.length ? `\n${bold(title)}\n${xs.map((x) => `  • ${x}`).join('\n')}` : '');
  return `${bold(a.name)} — ${verdict}: ${r.reason}\n\n${r.summary}\n${list('What it does', r.whatItDoes)}${list('Data it touches', r.dataItTouches)}${list('Where data goes', r.whereDataGoes)}${list('Not mentioned in its description', r.mismatches)}\n\n${dim(`Reviewed by ${r.backend} (${r.model})${r.truncated ? '; content was truncated at 60,000 characters' : ''}. AI reviews can be wrong.`)}`;
}

export async function explainCommand(args: string[], opts: ScanOptions, v: { local?: boolean; model?: string; yes?: boolean }) {
  if (!args[0]) throw new Error('Usage: ai-bom explain <skill | agent | command | hook | MCP server name> [--local] [--yes]');
  const inv = await scan({ ...opts, historyFile: undefined });
  const matches = inv.assets.filter((a) => a.name === args[0] || a.name.toLowerCase() === args[0].toLowerCase());
  if (!matches.length) throw new Error(`Nothing named "${args[0]}".`);
  const a = matches.find((x) => x.kind !== 'extension' && x.kind !== 'plugin') ?? matches[0];
  const input = await reviewInput(a, os.homedir());
  if (!input.files.length) throw new Error('Nothing readable to review for this item.');
  const where = v.local ? `your local Ollama model (${v.model ?? 'llama3.1'}); nothing leaves this machine` : `the Claude API (Anthropic)`;
  console.log(`This sends ${input.chars.toLocaleString()} characters (${input.files.map((f) => f.name).join(', ')}) to ${where}. Secrets are masked first.${input.truncated ? ' Content over 60,000 characters is cut.' : ''}`);
  if (!(await confirm('Continue?', v.yes))) return;
  const review = v.local ? await reviewWithOllama(input, v.model) : await reviewWithClaude(input);
  console.log('\n' + formatReview(a, review));
}

export { renderSummary };

export async function stateCommand(args: string[], v: { force?: boolean }) {
  const [sub = 'show', file] = args;
  if (sub === 'export') {
    if (!file) throw new Error('Usage: ai-bom state export <file.json>');
    const saved = await exportState(file);
    return console.log(saved.length ? `Saved ${saved.join(', ')} to ${file}.` : 'Nothing to export yet.');
  }
  if (sub === 'import') {
    if (!file) throw new Error('Usage: ai-bom state import <file.json> [--force]');
    const done = await importState(file, v.force);
    return console.log(done.length ? `Restored ${done.join(', ')}${v.force ? ' (replaced)' : ' (merged with what was here)'}.` : 'The file had nothing to restore.');
  }
  const { dir, entries } = await describeState();
  console.log(`${bold('AI-BOM data folder:')} ${dir.replace(os.homedir(), '~')}  ${dim('(owner-only permissions)')}\n`);
  if (!entries.length) return console.log('Nothing stored yet.');
  const kb = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  for (const e of entries) console.log(`  ${e.name.padEnd(22)} ${kb(e.bytes).padStart(9)}${e.items !== undefined ? dim(` · ${e.items} item(s)`) : ''}  ${dim(e.what)}`);
  const muted = Object.keys((await loadTriage(defaultTriageFile())) ?? {}).length;
  const snaps = await listSnapshots();
  const scans = await readScans(5);
  console.log(`\n${muted} triage decision(s) · ${snaps.filter((s) => s.status === 'applied').length} active fix(es) · ${(await readScans(1000)).length} recorded scan(s)`);
  if (scans.length) {
    console.log(bold('\nRecent scans:'));
    for (const s of scans) {
      const sev = (['critical', 'high', 'medium', 'low'] as const).map((k) => (s.active[k] ? `${s.active[k]} ${k}` : '')).filter(Boolean).join(', ') || 'no active findings';
      console.log(`  ${new Date(s.at).toLocaleString().padEnd(24)} ${s.source.padEnd(20)} ${String(s.assets).padStart(4)} assets · ${sev}${s.muted ? dim(` · ${s.muted} muted`) : ''}`);
    }
  }
  console.log(dim('\nBack up what you decided with: ai-bom state export ai-bom-state.json'));
}

/* ---------------- add / upgrade ---------------- */

async function readSecret(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) throw new Error('Secrets are read from the keyboard; run this in a terminal.');
  process.stdout.write(prompt);
  return new Promise((resolve) => {
    let value = '';
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    const onData = (d: Buffer) => {
      for (const ch of d.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stdout.write('\n');
          return resolve(value);
        }
        if (ch === '\u0003') process.exit(130);
        if (ch === '\u007f') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function printVet(r: import('./vet.js').VetResult) {
  const label = r.verdict === 'dangerous' ? red(bold('DANGEROUS')) : r.verdict === 'review' ? yellow(bold('REVIEW')) : green(bold('LOOKS SAFE'));
  console.log(`\n${bold(r.spec.kind === 'remote' ? r.spec.url! : `${r.spec.name}@${r.version}`)}  →  ${label}${r.latest && r.version !== r.latest ? dim(`  (latest is ${r.latest})`) : ''}`);
  if (r.trust?.notes.length) console.log(dim(`  ${r.trust.notes.join(' · ')}`));
  if (r.tools.length) {
    console.log(bold(`\n  Tools (${r.tools.length}), read from its code:`));
    for (const t of r.tools.slice(0, 30)) console.log(`    ${t.behavior?.verdict === 'mismatch' ? red('✗') : t.behavior?.verdict === 'matches' ? green('✓') : dim('·')} ${t.name}${t.description ? dim(` — ${t.description.slice(0, 80)}`) : ''}${t.behavior?.reasons.length ? `\n        ${red(t.behavior.reasons.join('; '))}` : ''}`);
  } else if (r.spec.kind !== 'remote') console.log(dim('\n  No tool registrations found in its code (it may build them at runtime; try `ai-bom inspect` after adding).'));
  if (r.deps) console.log(dim(`\n  Dependencies: ${r.deps.total} (${r.deps.scope === 'direct' ? 'direct' : 'installed'})${r.deps.error ? ` · ${r.deps.error}` : ''}${r.deps.licenseNotes.length ? ` · ${r.deps.licenseNotes.join('; ')}` : ''}`));
  if (r.findings.length) {
    console.log(bold('\n  Findings:'));
    for (const f of r.findings) console.log(`    ${f.severity.toUpperCase().padEnd(8)} ${f.title}${f.evidence ? dim(` — ${f.evidence.slice(0, 120)}`) : ''}`);
  }
}

export async function addCommand(args: string[], opts: ScanOptions, v: { to?: string; name?: string; project?: string[]; secret?: string[]; yes?: boolean; force?: boolean }) {
  const { vet, defaultName } = await import('./vet.js');
  const { TARGETS, installedTargets, planAdd, applyAdd, latestMcpRemote } = await import('./add.js');
  if (!args[0]) throw new Error('Usage: ai-bom add <npm package[@version] | pypi:name[==version] | https://remote/url> [--to claude-code,cursor] [--name n] [--secret KEY]');
  console.log(dim('Downloading and checking the package (nothing is installed or run)…'));
  const r = await vet(args[0], { online: true });
  try {
    printVet(r);
    const name = v.name ?? defaultName(r.spec);
    const targets = v.to ? v.to.split(',').map((s) => s.trim()) : (await installedTargets(opts.home)).map((t) => t.id);
    if (!targets.length) throw new Error(`No supported AI tool found. Pick with --to (${TARGETS.map((t) => t.id).join(', ')}).`);
    const plan = await planAdd(r, { name, targets, project: v.project?.[0], home: opts.home, secretNames: v.secret, force: v.force, mcpRemoteVersion: r.spec.kind === 'remote' ? await latestMcpRemote() : undefined });
    console.log(bold(`\nWill add "${name}" to:`));
    for (const w of plan.writes) console.log(`  ${w.target.padEnd(15)} ${w.file.replace(os.homedir(), '~')}  ${dim(JSON.stringify(w.entry))}`);
    for (const s of plan.skipped) console.log(yellow(`  ! ${s}`));
    if (!plan.writes.length) return;
    if (r.verdict === 'dangerous' && !v.force) return console.log(red('\nNot adding a server rated dangerous. Re-run with --force if you are sure.'));
    if (!(await confirm('\nAdd it?', v.yes))) return console.log('Nothing changed.');
    const secrets: Record<string, string> = {};
    for (const k of v.secret ?? []) secrets[k] = await readSecret(`Value for ${k} (stored in the keychain, not in any file): `);
    const snap = await applyAdd(plan, name, secrets, defaultSecretStore());
    console.log(green('\nAdded.') + (snap ? ` Undo with: ${bold(`ai-bom undo ${snap.id}`)}` : ''));
  } finally {
    await r.cleanup();
  }
}

export async function upgradeCommand(args: string[], opts: ScanOptions, v: { yes?: boolean; force?: boolean }) {
  const { upgradeCandidates, diffUpgrade, applyUpgrade } = await import('./add.js');
  const inv = await scan({ ...opts, historyFile: undefined, keepHomePaths: false });
  const list = await upgradeCandidates(inv);
  if (!args[0]) {
    if (!list.length) return console.log('Every pinned MCP server is on its latest release.');
    console.log(bold('Updates available:'));
    for (const c of list) console.log(`  ${c.name.padEnd(20)} ${c.package} ${c.current} → ${green(c.latest)}`);
    return console.log(`\nSee what changes before upgrading:  ai-bom upgrade <name>`);
  }
  const c = list.find((x) => x.name === args[0] || x.package === args[0]);
  if (!c) throw new Error(`No update found for "${args[0]}".`);
  console.log(dim(`Downloading ${c.package} ${c.current} and ${c.latest} to compare (nothing is installed or run)…`));
  const d = await diffUpgrade(c, { online: true });
  const line = (t: string, xs: string[], col = (s: string) => s) => xs.length && console.log(`  ${t}: ${col(xs.join(', '))}`);
  console.log(bold(`\n${c.name}: ${c.current} → ${c.latest}`) + `  ${d.verdict === 'dangerous' ? red('DANGEROUS') : d.verdict === 'review' ? yellow('REVIEW') : green('LOOKS SAFE')}`);
  line('New tools', d.toolsAdded, yellow);
  line('Removed tools', d.toolsRemoved);
  line('Changed descriptions', d.descriptionsChanged, yellow);
  line('New hosts contacted', d.newHosts, red);
  line('Now does more than it says', d.newMismatches, red);
  line('Install scripts', d.installScripts, yellow);
  line('New findings', d.newFindings.map((f) => `${f.severity}: ${f.title}`), red);
  line('Fixed', d.fixedFindings.map((f) => f.title), green);
  if (!d.toolsAdded.length && !d.descriptionsChanged.length && !d.newHosts.length && !d.newFindings.length) console.log(dim('  No changes to tools, hosts or findings.'));
  if (d.verdict === 'dangerous' && !v.force) return console.log(red('\nNot upgrading to a release rated dangerous (--force to override).'));
  if (!(await confirm(`\nPin ${c.name} to ${c.latest}?`, v.yes))) return;
  const snap = await applyUpgrade(inv.assets.find((a) => a.id === c.assetId)!, c.latest, opts.home ?? os.homedir());
  console.log(green('Upgraded.') + ` Undo with: ${bold(`ai-bom undo ${snap.id}`)}`);
}

/* ---------------- inspect ---------------- */

export async function inspectCommand(args: string[], opts: ScanOptions, v: { yes?: boolean }) {
  const { availableSandbox, inspectLive, saveInspection } = await import('./inspect.js');
  if (!args[0]) throw new Error('Usage: ai-bom inspect <MCP server name>');
  const inv = await scan({ ...opts, historyFile: undefined, keepHomePaths: true, sessionLogs: false });
  const a = inv.assets.find((x) => x.kind === 'mcp-server' && (x.name === args[0] || x.name.toLowerCase() === args[0].toLowerCase()));
  if (!a) throw new Error(`No MCP server named "${args[0]}".`);
  const kind = availableSandbox();
  if (!kind) throw new Error('No sandbox available (macOS sandbox-exec, or bwrap/unshare on Linux).');
  const what = kind === 'unshare' ? 'with no network (your home folder stays readable; install bwrap for full isolation)' : 'with no network, no access to your home folder or credentials';
  console.log(`This starts ${bold(a.name)} once, inside ${kind} ${what}, without your environment variables or secrets, for up to 20 seconds, and asks it for its tool list.`);
  if (!(await confirm('Run it?', v.yes))) return;
  const r = await inspectLive(a, opts.home ?? os.homedir());
  await saveInspection(r);
  if (!r.ok) return console.log(yellow(`Could not list its tools: ${r.error}`) + (r.stderrTail ? dim(`\n${r.stderrTail}`) : ''));
  console.log(`\n${green('✓')} ${r.serverInfo?.name ?? a.name} ${r.serverInfo?.version ?? ''} exposes ${r.tools.length} tool(s):`);
  for (const t of r.tools) console.log(`  ${r.poisoned.includes(t.name) ? red('✗') : r.liveOnly.includes(t.name) ? yellow('+') : ' '} ${t.name}${t.description ? dim(` — ${t.description.slice(0, 90)}`) : ''}`);
  if (r.liveOnly.length && a.mcp?.tools?.length) console.log(yellow(`\nNot visible in its code: ${r.liveOnly.join(', ')}`));
  if (r.changedDescriptions.length) console.log(yellow(`Descriptions differ from the code: ${r.changedDescriptions.join(', ')}`));
  if (r.networkAttempts.length) console.log(yellow(`Tried to reach the network while starting: ${r.networkAttempts[0]}`));
  console.log(dim('\nSaved; the dashboard and future scans include this result.'));
}

/* ---------------- timeline / incident / context / menubar ---------------- */

export async function timelineCommand(args: string[], opts: ScanOptions, v: { days?: string; markdown?: string; all?: boolean }) {
  const { readActivity, activityMarkdown } = await import('./activity.js');
  const home = opts.home ?? os.homedir();
  const list = await readActivity({ claudeDir: opts.claudeConfigDir ?? path.join(home, '.claude'), home }, { days: Number(v.days ?? 7), session: args[0], mutedFlags: await (await import('./state.js')).loadActivityMutes() });
  if (v.markdown) {
    await fs.writeFile(v.markdown, activityMarkdown(list), { mode: 0o600 });
    return console.log(`Wrote ${v.markdown}`);
  }
  if (!list.length) return console.log(`No agent sessions in the last ${v.days ?? 7} days.`);
  for (const s of list.slice(0, args[0] ? 1 : 10)) {
    const counts = Object.entries(s.counts).map(([k, n]) => `${n} ${k}`).join(', ');
    console.log(`${bold(`${s.agent}`)} ${dim(s.session.slice(0, 8))}  ${s.project?.replace(home, '~') ?? ''}  ${dim(`${s.start?.slice(0, 16).replace('T', ' ')} → ${s.end?.slice(11, 16)}`)}`);
    console.log(`  ${counts}${s.flagged ? red(`  · ${s.flagged} flagged`) : ''}${s.hosts.length ? dim(`  · contacted ${s.hosts.slice(0, 5).join(', ')}`) : ''}`);
    const show = args[0] || v.all ? s.events : s.events.filter((e) => e.flag);
    for (const e of show.slice(0, args[0] ? 400 : 5)) console.log(`    ${dim(e.at?.slice(11, 19) ?? '        ')} ${e.kind === 'prompt' ? 'You: ' : e.kind === 'response' ? 'Agent: ' : ''}${e.text.replace(home, '~')}${e.flag ? red(`  ← ${e.flag}`) : ''}`);
  }
  if (!args[0]) console.log(dim('\nOne session in full: ai-bom timeline <session id>   ·   export: --markdown file.md'));
}

export async function incidentCommand(opts: ScanOptions, v: { keep?: string; days?: string; yes?: boolean; 'no-pause'?: boolean }) {
  const { planIncident, applyIncident } = await import('./incident.js');
  const home = opts.home ?? os.homedir();
  const inv = await scan({ ...opts, historyFile: undefined });
  const keep = v.keep ? v.keep.split(',').map((s) => s.trim()) : [];
  const plan = await planIncident(inv, home, keep);
  console.log(bold('Incident mode'));
  if (!v['no-pause']) {
    console.log(`\nWill pause ${plan.paused.length} MCP server(s)/hook(s) (one undoable change):`);
    for (const p of plan.paused) console.log(`  ${p.name} ${dim(`(${p.files.join(', ')})`)}`);
    for (const m of plan.manual) console.log(yellow(`  ! ${m}`));
  }
  console.log(`\nKeys to rotate (${plan.keys.length}):`);
  for (const k of plan.keys) console.log(`  ${bold(k.label)} — ${k.why}${k.url ? `\n    ${k.url}` : ''}`);
  if (!(await confirm(`\n${v['no-pause'] ? 'Write the incident report' : 'Pause them and write the incident report'}?`, v.yes))) return;
  const r = await applyIncident(inv, home, { claudeDir: opts.claudeConfigDir ?? path.join(home, '.claude') }, { keep, days: Number(v.days ?? 7), pause: !v['no-pause'] });
  console.log(`\n${green('Done.')} Report: ${r.report.replace(home, '~')}${r.snapshot ? `\nUndo the pause with: ${bold(`ai-bom undo ${r.snapshot.id}`)}` : ''}`);
}

export async function contextCommand(opts: ScanOptions) {
  const inv = await scan({ ...opts, historyFile: undefined });
  const list = inv.context ?? [];
  if (!list.length) return console.log('No agent configuration found.');
  const name = (id: string) => inv.clients.find((c) => c.id === id)?.name ?? id;
  const max = Math.max(...list.map((c) => c.total));
  console.log(bold('Tokens your setup adds to every conversation (estimate)\n'));
  for (const c of list.slice(0, 12)) {
    const bar = '█'.repeat(Math.max(1, Math.round((c.total / max) * 28)));
    console.log(`${`${name(c.client)}${c.project ? ` · ${path.basename(c.project)}` : ''}`.padEnd(34)} ${bar} ${c.total.toLocaleString()}`);
    for (const i of c.items.slice(0, 4)) console.log(dim(`    ${i.name.padEnd(28)} ${String(i.tokens).padStart(6)}${i.estimated ? ' (rough)' : ''}${i.unused ? '  never used' : ''}`));
    for (const s of c.suggestions) console.log(yellow(`    → ${s}`));
  }
}

export async function menubarCommand(opts: ScanOptions, v: { install?: boolean; uninstall?: boolean; interval?: string }) {
  const { menubarText, installMenubar, uninstallMenubar } = await import('./menubar.js');
  if (v.install) return console.log(await installMenubar(Math.max(5, Number(v.interval ?? 30) || 30)));
  if (v.uninstall) return console.log(await uninstallMenubar());
  const inv = await scan({ ...opts, sessionLogs: true, recordAs: 'menubar', historyReadOnly: true });
  console.log(menubarText(inv));
}

const FW_ALIAS: Record<string, 'nist-ai-rmf' | 'iso-42001' | 'atlas'> = { nist: 'nist-ai-rmf', 'nist-ai-rmf': 'nist-ai-rmf', rmf: 'nist-ai-rmf', iso: 'iso-42001', 'iso-42001': 'iso-42001', iso42001: 'iso-42001', atlas: 'atlas' };
const STATUS_LABEL = { met: ['In place', green], partial: ['Partly', yellow], gap: ['Gap', red], manual: ['Your answer', dim], attested: ['You confirmed', green], na: ['Not applicable', dim] } as const;

export async function baselineCommand(rest: string[], opts: ScanOptions, v: { json?: boolean; na?: boolean; notes?: string }) {
  const { baselines, attest, isFramework } = await import('./frameworks/baselines.js');
  const { atlasView } = await import('./frameworks/atlas.js');
  const [sub, ...args] = rest;
  if (sub === 'mark' || sub === 'clear') {
    const fw = FW_ALIAS[args[0]?.toLowerCase() ?? ''];
    const id = args.slice(1).join(' ');
    if (!isFramework(fw) || !id) throw new Error(`Usage: ai-bom baseline ${sub} <nist|iso> <control> ${sub === 'mark' ? '[--na] [--notes "…"]' : ''}`);
    const r = await attest(fw, id, sub === 'clear' ? undefined : v.na ? 'na' : 'done', v.notes);
    return console.log(sub === 'clear' ? `Cleared your answer for ${r.id}.` : `Recorded ${r.id} as ${v.na ? 'not applicable' : 'done'}. Saved in ~/.ai-bom/attestations.json.`);
  }
  const which = sub ? FW_ALIAS[sub.toLowerCase()] : undefined;
  if (sub && !which) throw new Error(`Unknown baseline "${sub}". Use nist, iso or atlas.`);
  const inv = await scan({ ...opts, historyFile: undefined });
  const reports = await baselines(inv);
  const atlas = atlasView(inv);
  if (v.json) return console.log(JSON.stringify(which === 'atlas' ? atlas : which ? reports[which] : { ...reports, atlas }, null, 2));

  if (!which) {
    console.log(bold('Baselines (self-assessment, not a certification)\n'));
    for (const r of Object.values(reports)) {
      const c = r.counts;
      console.log(`${`${r.name} ${r.version}`.padEnd(30)} ${String(r.coverage).padStart(3)}% in place   ${green(`${c.met + c.attested} in place`)} · ${yellow(`${c.partial} partly`)} · ${red(`${c.gap} gap${c.gap === 1 ? "" : "s"}`)} · ${dim(`${c.manual} need your answer`)}`);
    }
    console.log(`${`MITRE ATLAS ${atlas.version}`.padEnd(30)} ${atlas.seen} of ${atlas.checked} techniques AI-BOM checks for have open findings`);
    return console.log(dim('\nDetails: ai-bom baseline nist | iso | atlas'));
  }
  if (which === 'atlas') {
    console.log(bold(`MITRE ATLAS ${atlas.version}: open findings by tactic\n`));
    for (const t of atlas.tactics) {
      console.log(bold(t.name));
      for (const x of t.techniques) console.log(`  ${x.findings.length ? red(String(x.findings.length).padStart(3)) : dim('  ·')}  ${x.id.padEnd(14)} ${x.findings.length ? x.name : dim(x.name)}`);
    }
    return console.log(dim('\n· = checked, nothing found. https://atlas.mitre.org'));
  }
  const r = reports[which];
  console.log(bold(`${r.name} ${r.version}: ${r.coverage}% in place`));
  let group = '';
  for (const c of r.controls) {
    if (c.group !== group) console.log(bold(`\n${(group = c.group)}`));
    const [label, paint] = c.stale ? (['Re-check', yellow] as const) : STATUS_LABEL[c.status];
    console.log(`  ${paint(label.padEnd(14))} ${c.id.padEnd(12)} ${c.title}${c.org ? dim(' (organization)') : ''}`);
    for (const e of c.evidence) console.log(dim(`                 ${e}`));
    if (c.action) console.log(yellow(`                 → ${c.action}`));
    if (c.status === 'manual') console.log(dim(`                 ${c.hint ?? c.ask} Mark it: ai-bom baseline mark ${which === 'nist-ai-rmf' ? 'nist' : 'iso'} "${c.id}" [--na] --notes "…"`));
  }
}
