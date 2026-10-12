import path from 'node:path';
import { promises as fs } from 'node:fs';
import { randomBytes } from 'node:crypto';
import type { Asset, Finding, FixKind, Inventory, Occurrence } from '../types.js';
import { normalizeMcpEntry } from '../mcp.js';
import { pinnedArgs, upgradeTarget } from '../vulns/fix.js';
import { compareVersions } from '../vulns/semver.js';
import { classifySecret } from '../util/secrets.js';
import { dataDir, readJsonFile, writeAtomic, writeJsonFile } from '../util/store.js';
import { deepEqual, editText, getAt, hasAt, lineDiff, makeSplice, readJsonDoc, restoreSplice, sha256, type JsonPath, type Splice } from './jsonedit.js';
import { ensureLauncher, LAUNCHER_NAME, launcherPath, serviceName, type SecretStore } from './keychain.js';

/**
 * "Fix it for me": small, previewable, reversible edits.
 *
 *  - Every fix is planned first; the plan shows a redacted diff of each file.
 *  - Applying re-reads every file and refuses if it changed since the preview.
 *  - Edits go through a JSONC-aware editor, so comments, key order and
 *    formatting outside the touched node are kept, and the result is re-parsed
 *    before it is written (atomically, keeping the file's permissions).
 *  - Every applied fix records its inverse in ~/.ai-bom/snapshots/<id>/, and
 *    `ai-bom undo <id>` reverts it, refusing if you edited the same spot since.
 *  - No full copies of config files are kept (they often hold secrets); the
 *    snapshot only has the entries that were changed.
 */

type Present = { present: true; value: unknown } | { present: false };

export type Op =
  | { type: 'json'; file: string; path: JsonPath; before: Present & { fromKeychain?: string }; after: Present; array?: boolean }
  | { type: 'move'; from: string; to?: string }
  | { type: 'keychain'; service: string };

export interface FixChange {
  file: string;
  description: string;
  diff?: string;
}

export interface FixPlan {
  /** Hash of the ops and file contents; apply refuses a plan whose key no longer matches. */
  key: string;
  kind: FixKind;
  title: string;
  summary: string;
  warnings: string[];
  changes: FixChange[];
  /** Manual steps for configs that cannot be edited automatically (TOML/YAML, plugin files…). */
  manual: string[];
  /** Internal; never sent to the dashboard. */
  ops: Op[];
  fileHashes: Record<string, string>;
  secrets: Map<string, string>;
}

export interface Snapshot {
  id: string;
  createdAt: string;
  title: string;
  kind: FixKind;
  target: FixTarget;
  files: string[];
  ops: Op[];
  /** Changed region per file, so undo restores the exact original text. */
  splices?: Splice[];
  status: 'applied' | 'undone';
  undoneAt?: string;
}

export type FixTarget = { findingId?: string; assetId?: string };

export interface FixContext {
  home: string;
  inventory: Inventory;
  /** Claude Code config dir (for enabledPlugins); defaults to ~/.claude. */
  claudeDir?: string;
  secretStore?: SecretStore;
}

export const FIX_LABEL: Record<FixKind, string> = {
  'pin-version': 'Pin a safe version',
  'remove-entry': 'Remove from config',
  'move-to-keychain': 'Move secret to Keychain',
  settings: 'Fix the setting',
  'remove-hook': 'Remove the hook',
  quarantine: 'Quarantine',
  'disable-plugin': 'Disable the plugin',
};

const snapshotsDir = () => path.join(dataDir(), 'snapshots');
const auditFile = () => path.join(dataDir(), 'audit.log');
const expand = (home: string, p: string) => (p === '~' || p.startsWith('~/') ? path.join(home, p.slice(1)) : p);
const isJson = (f: string) => /\.(json|jsonc)$/i.test(f);

/* ---------------- Which fixes apply ---------------- */

const CONTENT_KINDS = new Set(['skill', 'agent', 'command', 'instructions']);
const PIN_RULES = new Set(['VULN-KNOWN', 'MCP-UNPINNED']);
const SETTINGS_RULES = new Set(['PERM-BYPASS', 'PERM-AUTO-PROJECT-MCP', 'PERM-BROAD-ALLOW', 'SETTINGS-API-REDIRECT', 'TELEMETRY-PROMPTS']);

const editable = (a: Asset) => a.occurrences.filter((o) => o.jsonPath && !o.via && isJson(o.source));

/** Target version for a pin: the advisory's fix/latest, else the latest release, else the newest cached copy. */
export function pinTarget(a: Asset, f?: Finding): string | undefined {
  const p = a.mcp?.package;
  if (!p || (p.ecosystem !== 'npm' && p.ecosystem !== 'pypi')) return undefined;
  if (f?.vuln) return f.vuln.fixCommand ? upgradeTarget(f.vuln.fixedVersion, p.latestVersion) : undefined;
  if (p.latestVersion) return p.latestVersion;
  const cached = [...(p.installedVersions ?? [])].sort(compareVersions).pop();
  return cached;
}

const envKey = (f: Finding) => f.evidence?.match(/^([A-Za-z_][A-Za-z0-9_]*)=/)?.[1];

export function fixKindsFor(inv: Inventory, f: Finding | undefined, a: Asset | undefined): FixKind[] {
  const out: FixKind[] = [];
  const bundled = a?.occurrences.some((o) => o.via && o.client === 'claude-code');
  if (f && SETTINGS_RULES.has(f.ruleId) && f.location && isJson(f.location)) out.push('settings');
  if (f?.ruleId === 'SETTINGS-SECRET' && envKey(f) === 'ANTHROPIC_API_KEY' && f.location && isJson(f.location) && inv.host.platform !== 'win32') out.push('move-to-keychain');
  if (!a) return out;
  if (a.kind === 'mcp-server') {
    const occs = editable(a);
    if (f && PIN_RULES.has(f.ruleId) && occs.length && a.mcp?.command && pinTarget(a, f)) out.push('pin-version');
    const key = f && f.ruleId === 'MCP-SECRET' ? envKey(f) : undefined;
    if (key && inv.host.platform !== 'win32' && occs.some((o) => o.source === f!.location && o.env?.[key] !== undefined) && a.mcp?.command) out.push('move-to-keychain');
    if (occs.length) out.push('remove-entry');
  } else if (a.kind === 'hook' && editable(a).length) out.push('remove-hook');
  else if (CONTENT_KINDS.has(a.kind) && a.path && !a.occurrences.some((o) => o.via || o.note?.startsWith('Synced'))) out.push('quarantine');
  if (bundled && !out.includes('remove-entry')) out.push('disable-plugin');
  return [...new Set(out)];
}

/* ---------------- Planning ---------------- */

interface Draft {
  kind: FixKind;
  title: string;
  summary: string;
  ops: Op[];
  warnings: string[];
  manual: string[];
  descriptions: Map<string, string[]>;
  secrets: Map<string, string>;
}

function warnFor(file: string, home: string, occ?: Occurrence): string[] {
  const w: string[] = [];
  if (path.basename(file) === '.claude.json') w.push('Quit Claude Code first: it rewrites ~/.claude.json while running and could undo this change.');
  if (occ?.scope === 'project' && occ.project && file.startsWith(occ.project + path.sep) && occ.project !== home) {
    w.push(`${path.relative(occ.project, file)} belongs to the ${path.basename(occ.project)} project; the change will show up in git.`);
  }
  if (occ?.scope === 'managed') w.push('This is an admin-managed policy file; you may not have permission to change it.');
  return w;
}

function describe(d: Draft, file: string, text: string) {
  const list = d.descriptions.get(file) ?? [];
  list.push(text);
  d.descriptions.set(file, list);
}

async function planPin(ctx: FixContext, d: Draft, a: Asset, f?: Finding) {
  const version = pinTarget(a, f);
  if (!version) throw new Error('No safe version is known yet. Run the scan with --online to look up the latest release.');
  d.title = `Pin ${a.mcp!.package!.name} to ${version}`;
  d.summary = `Every config that starts ${a.name} will run exactly ${a.mcp!.package!.name}@${version} instead of whatever version the runner picks.`;
  for (const o of editable(a)) {
    const file = expand(ctx.home, o.source);
    const doc = await readJsonDoc(file);
    const entry = getAt(doc.data, o.jsonPath!) as Record<string, unknown> | undefined;
    const norm = normalizeMcpEntry(entry);
    if (!entry || !norm || typeof entry.command !== 'string' || !Array.isArray(entry.args)) continue;
    const pinned = pinnedArgs(norm.details, version);
    if (!pinned) continue;
    const raw = entry.args as string[];
    let next = pinned;
    if (path.basename(entry.command) === LAUNCHER_NAME) {
      const sep = raw.indexOf('--');
      next = [...raw.slice(0, sep + 2), ...pinned];
    }
    if (deepEqual(raw, next)) continue;
    d.ops.push({ type: 'json', file, path: [...o.jsonPath!, 'args'], before: { present: true, value: raw }, after: { present: true, value: next } });
    describe(d, file, `Change the "${o.name}" arguments to use ${version}.`);
    d.warnings.push(...warnFor(file, ctx.home, o));
  }
  for (const o of a.occurrences.filter((x) => !editable(a).includes(x))) {
    d.manual.push(`${o.source}: change "${a.mcp!.package!.name}" to "${a.mcp!.package!.ecosystem === 'npm' ? `${a.mcp!.package!.name}@${version}` : `${a.mcp!.package!.name}==${version}`}" in the "${o.name}" entry.`);
  }
}

async function planRemoveEntry(ctx: FixContext, d: Draft, a: Asset) {
  d.title = `Remove ${a.name} from your configs`;
  d.summary = `${a.name} is taken out of every JSON config that starts it. The entries are kept in the snapshot, so Undo puts them back exactly.`;
  for (const o of editable(a)) {
    const file = expand(ctx.home, o.source);
    const doc = await readJsonDoc(file);
    if (!hasAt(doc.data, o.jsonPath!)) continue;
    d.ops.push({ type: 'json', file, path: o.jsonPath!, before: { present: true, value: getAt(doc.data, o.jsonPath!) }, after: { present: false } });
    describe(d, file, `Remove the "${o.name}" server entry.`);
    d.warnings.push(...warnFor(file, ctx.home, o));
  }
  for (const o of a.occurrences.filter((x) => !editable(a).includes(x))) {
    d.manual.push(o.via ? `${o.source} is part of a plugin/extension: disable or uninstall it instead.` : `${o.source}: delete the "${o.name}" entry by hand.`);
  }
}

async function planKeychainMcp(ctx: FixContext, d: Draft, a: Asset, f: Finding) {
  const key = envKey(f)!;
  const o = editable(a).find((x) => expand(ctx.home, x.source) === expand(ctx.home, f.location ?? '') && x.env?.[key] !== undefined);
  if (!o) throw new Error('Could not find the config entry holding this secret.');
  const file = expand(ctx.home, o.source);
  const doc = await readJsonDoc(file);
  const entry = getAt(doc.data, o.jsonPath!) as Record<string, unknown> | undefined;
  const env = entry?.env as Record<string, unknown> | undefined;
  const value = env?.[key];
  if (!entry || typeof entry.command !== 'string' || typeof value !== 'string' || !classifySecret(key, value)) throw new Error('The secret is no longer in the config.');
  const service = serviceName(`${o.client}/${o.name}`, key);
  const launcher = launcherPath();
  const args = Array.isArray(entry.args) ? (entry.args as string[]) : [];
  const wrapped = path.basename(entry.command) === LAUNCHER_NAME;
  const nextArgs = wrapped ? [`${key}=${service}`, ...args] : [`${key}=${service}`, '--', entry.command, ...args];
  d.title = `Move ${key} for ${a.name} into the ${ctx.secretStore?.name ?? 'keychain'}`;
  d.summary = `The value is stored in the ${ctx.secretStore?.name ?? 'keychain'} as "${service}" and removed from the file. The server is started through ${LAUNCHER_NAME}, which reads it back at launch.`;
  d.secrets.set(service, value);
  d.ops.push({ type: 'keychain', service });
  if (!wrapped) d.ops.push({ type: 'json', file, path: [...o.jsonPath!, 'command'], before: { present: true, value: entry.command }, after: { present: true, value: launcher } });
  d.ops.push({ type: 'json', file, path: [...o.jsonPath!, 'args'], before: entry.args === undefined ? { present: false } : { present: true, value: args }, after: { present: true, value: nextArgs } });
  d.ops.push({ type: 'json', file, path: [...o.jsonPath!, 'env', key], before: { present: true, value: undefined, fromKeychain: service }, after: { present: false } });
  describe(d, file, `Replace the literal ${key} in "${o.name}" with a keychain lookup.`);
  d.warnings.push(...warnFor(file, ctx.home, o), 'Rotate the key anyway: it may already be in backups, dotfile repos or shell history.');
}

async function planKeychainClaude(ctx: FixContext, d: Draft, f: Finding) {
  const file = expand(ctx.home, f.location!);
  const doc = await readJsonDoc(file);
  const value = getAt(doc.data, ['env', 'ANTHROPIC_API_KEY']);
  if (typeof value !== 'string') throw new Error('The key is no longer in this file.');
  if (hasAt(doc.data, ['apiKeyHelper'])) throw new Error('apiKeyHelper is already set in this file; move the key by hand.');
  const service = serviceName('claude-code', 'ANTHROPIC_API_KEY');
  d.title = 'Move ANTHROPIC_API_KEY into the keychain';
  d.summary = `Claude Code reads the key through its apiKeyHelper setting, which asks the ${ctx.secretStore?.name ?? 'keychain'} for it at startup.`;
  d.secrets.set(service, value);
  d.ops.push({ type: 'keychain', service });
  d.ops.push({ type: 'json', file, path: ['apiKeyHelper'], before: { present: false }, after: { present: true, value: ctx.secretStore?.lookupCommand(service) ?? service } });
  d.ops.push({ type: 'json', file, path: ['env', 'ANTHROPIC_API_KEY'], before: { present: true, value: undefined, fromKeychain: service }, after: { present: false } });
  describe(d, file, 'Replace env.ANTHROPIC_API_KEY with an apiKeyHelper keychain lookup.');
  d.warnings.push('Rotate the key anyway: it may already be in backups or dotfile repos.');
}

async function planSettings(ctx: FixContext, d: Draft, f: Finding) {
  const file = expand(ctx.home, f.location!);
  const doc = await readJsonDoc(file);
  const remove = (p: JsonPath) => d.ops.push({ type: 'json', file, path: p, before: { present: true, value: getAt(doc.data, p) }, after: { present: false } });
  if (f.ruleId === 'PERM-BYPASS') {
    d.title = 'Turn permission prompts back on';
    d.summary = 'The agent will ask before running tools again. Rules you allowed explicitly keep working.';
    if (getAt(doc.data, ['permissions', 'defaultMode']) === 'bypassPermissions') remove(['permissions', 'defaultMode']);
    if (getAt(doc.data, ['skipDangerousModePermissionPrompt']) === true) remove(['skipDangerousModePermissionPrompt']);
    describe(d, file, 'Remove the bypass-permissions setting.');
  } else if (f.ruleId === 'PERM-AUTO-PROJECT-MCP') {
    d.title = 'Stop auto-approving project MCP servers';
    d.summary = 'Servers defined in a repository\'s .mcp.json will need your approval before they start.';
    if (hasAt(doc.data, ['enableAllProjectMcpServers'])) remove(['enableAllProjectMcpServers']);
    describe(d, file, 'Remove enableAllProjectMcpServers.');
  } else if (f.ruleId === 'SETTINGS-API-REDIRECT') {
    const key = envKey(f);
    if (!key || !hasAt(doc.data, ['env', key])) throw new Error('The setting is no longer in this file.');
    d.title = `Remove the ${key} redirect`;
    d.summary = 'Requests go to the provider\'s own API again. If you run a proxy on purpose, don\'t apply this.';
    remove(['env', key]);
    describe(d, file, `Remove env.${key}.`);
  } else if (f.ruleId === 'TELEMETRY-PROMPTS') {
    const keys = ['OTEL_LOG_USER_PROMPTS', 'OTEL_LOG_TOOL_DETAILS'].filter((k) => hasAt(doc.data, ['env', k]));
    if (!keys.length) throw new Error('Prompt logging is not set in this file (it may come from your shell profile).');
    d.title = 'Stop exporting prompt text';
    d.summary = 'Usage metrics keep flowing to the collector, but the text of your prompts and tool parameters no longer does.';
    for (const k of keys) remove(['env', k]);
    describe(d, file, `Remove ${keys.join(' and ')}.`);
  } else {
    const rule = f.evidence ?? '';
    const allow = getAt(doc.data, ['permissions', 'allow']);
    const idx = Array.isArray(allow) ? allow.indexOf(rule) : -1;
    if (idx < 0) throw new Error(`"${rule}" is no longer in the allow list.`);
    d.title = `Remove the "${rule}" allow rule`;
    d.summary = 'Commands it covered will ask for approval again.';
    d.ops.push({ type: 'json', file, path: ['permissions', 'allow', idx], before: { present: true, value: rule }, after: { present: false }, array: true });
    describe(d, file, `Remove "${rule}" from permissions.allow.`);
  }
  if (!d.ops.length) throw new Error('The setting is already fixed.');
  d.warnings.push(...warnFor(file, ctx.home));
}

async function planRemoveHook(ctx: FixContext, d: Draft, a: Asset) {
  d.title = `Remove the ${a.name} hook`;
  d.summary = `The command stops running automatically. Undo restores it.`;
  for (const o of editable(a)) {
    const file = expand(ctx.home, o.source);
    const doc = await readJsonDoc(file);
    if (!hasAt(doc.data, o.jsonPath!)) continue;
    const array = typeof o.jsonPath![o.jsonPath!.length - 1] === 'number';
    d.ops.push({ type: 'json', file, path: o.jsonPath!, before: { present: true, value: getAt(doc.data, o.jsonPath!) }, after: { present: false }, array });
    describe(d, file, `Remove the ${a.name} hook.`);
    d.warnings.push(...warnFor(file, ctx.home, o));
  }
}

async function planQuarantine(ctx: FixContext, d: Draft, a: Asset) {
  const from = expand(ctx.home, a.path!);
  await fs.lstat(from);
  d.title = `Quarantine ${a.name}`;
  d.summary = `The ${a.kind} is moved to ~/.ai-bom/quarantine so no agent loads it. Undo moves it back.`;
  d.ops.push({ type: 'move', from });
  describe(d, from, `Move ${path.basename(from)} into quarantine.`);
  const o = a.occurrences[0];
  if (o?.project && from.startsWith(o.project + path.sep) && o.project !== ctx.home) d.warnings.push(`This is part of the ${path.basename(o.project)} project; git will show it as deleted.`);
}

async function planDisablePlugin(ctx: FixContext, d: Draft, a: Asset) {
  const pluginId = a.kind === 'plugin' ? a.id : a.occurrences.find((o) => o.via)?.via;
  const plugin = ctx.inventory.assets.find((x) => x.id === pluginId);
  if (!plugin || plugin.kind !== 'plugin') throw new Error('Only Claude Code plugins can be disabled automatically; uninstall the extension from its app.');
  const file = path.join(ctx.claudeDir ?? path.join(ctx.home, '.claude'), 'settings.json');
  let data: unknown;
  try {
    data = (await readJsonDoc(file)).data;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') throw new Error(`${file} does not exist; disable the plugin with /plugin in Claude Code.`);
    throw e;
  }
  const p = ['enabledPlugins', plugin.name];
  if (getAt(data, p) === false) throw new Error(`${plugin.name} is already disabled.`);
  d.title = `Disable the ${plugin.name} plugin`;
  d.summary = `Claude Code stops loading ${plugin.name} and everything it bundles${plugin.children?.length ? ` (${plugin.children.length} item(s))` : ''}. It stays installed; Undo re-enables it.`;
  d.ops.push({ type: 'json', file, path: p, before: hasAt(data, p) ? { present: true, value: getAt(data, p) } : { present: false }, after: { present: true, value: false } });
  describe(d, file, `Set enabledPlugins["${plugin.name}"] to false.`);
}

export async function planFix(ctx: FixContext, target: FixTarget, kind?: FixKind): Promise<FixPlan> {
  const inv = ctx.inventory;
  const tilde = (p: string) => (p.startsWith(ctx.home + path.sep) ? `~${p.slice(ctx.home.length)}` : p);
  const f = target.findingId ? inv.findings.find((x) => x.id === target.findingId) : undefined;
  if (target.findingId && !f) throw new Error('Finding not found; rescan and try again.');
  const a = inv.assets.find((x) => x.id === (target.assetId ?? f?.assetId));
  const kinds = fixKindsFor(inv, f, a);
  const k = kind ?? kinds[0];
  if (!k || !kinds.includes(k)) throw new Error(kinds.length ? `Available fixes: ${kinds.join(', ')}` : 'No automatic fix is available for this.');
  if (k === 'move-to-keychain' && !(ctx.secretStore && (await ctx.secretStore.available()))) throw new Error('No keychain tool found (macOS `security` or Linux `secret-tool`).');

  const d: Draft = { kind: k, title: '', summary: '', ops: [], warnings: [], manual: [], descriptions: new Map(), secrets: new Map() };
  if (k === 'pin-version') await planPin(ctx, d, a!, f);
  else if (k === 'remove-entry') await planRemoveEntry(ctx, d, a!);
  else if (k === 'move-to-keychain') await (a?.kind === 'mcp-server' ? planKeychainMcp(ctx, d, a, f!) : planKeychainClaude(ctx, d, f!));
  else if (k === 'settings') await planSettings(ctx, d, f!);
  else if (k === 'remove-hook') await planRemoveHook(ctx, d, a!);
  else if (k === 'quarantine') await planQuarantine(ctx, d, a!);
  else if (k === 'disable-plugin') await planDisablePlugin(ctx, d, a!);
  if (!d.ops.length && !d.manual.length) throw new Error('Nothing to change: it looks already fixed. Rescan to refresh.');

  // Preview: apply the JSON ops in memory and diff each file.
  const fileHashes: Record<string, string> = {};
  const changes: FixChange[] = [];
  const byFile = groupJson(d.ops);
  for (const [file, ops] of byFile) {
    const doc = await readJsonDoc(file);
    fileHashes[file] = doc.hash;
    const after = applyJsonOps(doc.text, ops, d.secrets);
    changes.push({ file: tilde(file), description: (d.descriptions.get(file) ?? []).join(' '), diff: lineDiff(doc.text, after) });
  }
  for (const op of d.ops) if (op.type === 'move') changes.push({ file: tilde(op.from), description: (d.descriptions.get(op.from) ?? []).join(' ') });
  const key = sha256(JSON.stringify({ k, target, ops: d.ops, fileHashes })).slice(0, 16);
  d.manual = d.manual.map(tilde);
  return { key, kind: k, title: d.title, summary: d.summary, warnings: [...new Set(d.warnings)], changes, manual: d.manual, ops: d.ops, fileHashes, secrets: d.secrets };
}

/** The part of a plan that is safe to show (no ops, no secret values). */
export function publicPlan(p: FixPlan) {
  return { key: p.key, kind: p.kind, label: FIX_LABEL[p.kind], title: p.title, summary: p.summary, warnings: p.warnings, changes: p.changes, manual: p.manual };
}

function groupJson(ops: Op[]): Map<string, Extract<Op, { type: 'json' }>[]> {
  const m = new Map<string, Extract<Op, { type: 'json' }>[]>();
  for (const op of ops) if (op.type === 'json') m.set(op.file, [...(m.get(op.file) ?? []), op]);
  return m;
}

/** Apply forward ops to a file's text. Array removals run from the highest index down. */
function applyJsonOps(text: string, ops: Extract<Op, { type: 'json' }>[], _secrets: Map<string, string>): string {
  const ordered = [...ops].sort((x, y) => (x.array && y.array ? Number(y.path[y.path.length - 1]) - Number(x.path[x.path.length - 1]) : 0));
  let out = text;
  for (const op of ordered) out = editText(out, op.path, op.after.present ? op.after.value : undefined, !!op.array && op.after.present);
  return out;
}

/* ---------------- Apply / undo ---------------- */

async function audit(entry: Record<string, unknown>) {
  try {
    await fs.mkdir(dataDir(), { recursive: true, mode: 0o700 });
    await fs.appendFile(auditFile(), JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
  } catch {
    /* best effort */
  }
}

async function writeKeepingMode(file: string, text: string) {
  let mode = 0o600;
  try {
    mode = (await fs.stat(file)).mode & 0o777;
  } catch {
    /* new file */
  }
  await writeAtomic(file, text, mode);
}

export async function applyFix(ctx: FixContext, target: FixTarget, kind: FixKind | undefined, expectedKey?: string): Promise<Snapshot> {
  const plan = await planFix(ctx, target, kind);
  if (expectedKey && plan.key !== expectedKey) throw new ConflictError('Something changed since the preview. Review the new preview and try again.');
  const id = `${new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '')}-${randomBytes(3).toString('hex')}`;
  const written: { file: string; original: string }[] = [];
  const splices: Splice[] = [];
  const stored: string[] = [];
  const moved: { from: string; to: string }[] = [];
  try {
    for (const op of plan.ops) {
      if (op.type !== 'keychain') continue;
      await ctx.secretStore!.set(op.service, plan.secrets.get(op.service)!);
      stored.push(op.service);
    }
    if (stored.length) await ensureLauncher();
    for (const [file, ops] of groupJson(plan.ops)) {
      const doc = await readJsonDoc(file);
      if (doc.hash !== plan.fileHashes[file]) throw new ConflictError(`${file} changed since the preview.`);
      const next = applyJsonOps(doc.text, ops, plan.secrets);
      await writeKeepingMode(file, next);
      written.push({ file, original: doc.text });
      const sp = makeSplice(file, doc.text, next, plan.secrets);
      if (sp) splices.push(sp);
    }
    for (const op of plan.ops) {
      if (op.type !== 'move') continue;
      const to = path.join(dataDir(), 'quarantine', id, path.basename(op.from));
      await fs.mkdir(path.dirname(to), { recursive: true, mode: 0o700 });
      await fs.rename(op.from, to);
      op.to = to;
      moved.push({ from: op.from, to });
    }
  } catch (e) {
    // Roll back whatever was done, newest first.
    for (const m of moved.reverse()) await fs.rename(m.to, m.from).catch(() => {});
    for (const w of written.reverse()) await writeKeepingMode(w.file, w.original).catch(() => {});
    for (const s of stored) await ctx.secretStore!.remove(s).catch(() => {});
    throw e;
  }
  const snap: Snapshot = {
    id,
    createdAt: new Date().toISOString(),
    title: plan.title,
    kind: plan.kind,
    target,
    files: [...new Set(plan.ops.map((o) => (o.type === 'json' ? o.file : o.type === 'move' ? o.from : '')).filter(Boolean))],
    ops: plan.ops,
    splices: splices.length ? splices : undefined,
    status: 'applied',
  };
  await writeJsonFile(path.join(snapshotsDir(), id, 'manifest.json'), snap);
  await audit({ action: 'fix', id, kind: plan.kind, title: plan.title, files: snap.files });
  return snap;
}

export async function listSnapshots(): Promise<Snapshot[]> {
  let names: string[] = [];
  try {
    names = await fs.readdir(snapshotsDir());
  } catch {
    return [];
  }
  const out: Snapshot[] = [];
  for (const n of names) {
    const s = await readJsonFile<Snapshot>(path.join(snapshotsDir(), n, 'manifest.json'));
    if (s?.id === n) out.push(s);
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** Public view of a snapshot (no stored values). */
export const publicSnapshot = (s: Snapshot) => ({ id: s.id, createdAt: s.createdAt, title: s.title, kind: s.kind, files: s.files, status: s.status, undoneAt: s.undoneAt });

export async function undoFix(id: string, store?: SecretStore, force = false): Promise<Snapshot> {
  if (!/^[\w-]{1,64}$/.test(id)) throw new Error('Invalid snapshot id');
  const file = path.join(snapshotsDir(), id, 'manifest.json');
  const snap = await readJsonFile<Snapshot>(file);
  if (!snap) throw new Error(`No snapshot ${id}`);
  if (snap.status === 'undone') throw new Error('Already undone.');

  // Check every op can be reverted before touching anything.
  const conflicts: string[] = [];
  const docs = new Map<string, { text: string; data: unknown }>();
  for (const [f] of groupJson(snap.ops)) docs.set(f, await readJsonDoc(f));
  for (const op of snap.ops) {
    if (op.type === 'json') {
      const data = docs.get(op.file)!.data;
      if (op.array && op.after.present) {
        if (!deepEqual(getAt(data, op.path), op.after.value)) conflicts.push(`${op.file}: ${op.path.join('.')} was changed after the change was made.`);
      } else if (op.array) {
        const parent = getAt(data, op.path.slice(0, -1));
        if (Array.isArray(parent) && parent.some((x) => deepEqual(x, op.before.present ? op.before.value : undefined))) conflicts.push(`${op.file}: the entry is already back.`);
      } else if (op.after.present ? !deepEqual(getAt(data, op.path), op.after.value) : hasAt(data, op.path)) {
        conflicts.push(`${op.file}: ${op.path.join('.')} was changed after the fix.`);
      }
    } else if (op.type === 'move' && op.to) {
      try {
        await fs.lstat(op.from);
        conflicts.push(`${op.from} exists again.`);
      } catch {
        /* free */
      }
    }
  }
  if (conflicts.length && !force) throw new ConflictError(`Cannot undo safely:\n  ${conflicts.join('\n  ')}\nRe-run with --force to overwrite.`);

  for (const op of [...snap.ops].reverse()) if (op.type === 'move' && op.to) await fs.rename(op.to, op.from);
  for (const [f, ops] of groupJson(snap.ops)) {
    let text = docs.get(f)!.text;
    // Untouched since the fix: put the original bytes back, formatting and all.
    const sp = snap.splices?.find((x) => x.file === f);
    const exact = sp ? await restoreSplice(sp, text, (service) => store?.get(service) ?? Promise.resolve(undefined)) : undefined;
    if (exact !== undefined) {
      await writeKeepingMode(f, exact);
      continue;
    }
    // Undo in reverse; array insertions go lowest index first so positions line up.
    const ordered = [...ops].reverse().sort((x, y) => (x.array && y.array ? Number(x.path[x.path.length - 1]) - Number(y.path[y.path.length - 1]) : 0));
    for (const op of ordered) {
      let value: unknown = op.before.present ? op.before.value : undefined;
      if (op.before.fromKeychain) {
        value = await store?.get(op.before.fromKeychain);
        if (value === undefined) throw new Error(`Could not read ${op.before.fromKeychain} from the keychain.`);
      }
      if (op.array && op.after.present) {
        text = editText(text, op.path, undefined);
      } else if (op.array) {
        const parent = getAt(JSON.parse(JSON.stringify(docs.get(f)!.data)), op.path.slice(0, -1));
        const idx = Math.min(Number(op.path[op.path.length - 1]), Array.isArray(parent) ? parent.length : 0);
        text = editText(text, [...op.path.slice(0, -1), idx], value, true);
      } else text = editText(text, op.path, op.before.present ? value : undefined);
    }
    await writeKeepingMode(f, text);
  }
  for (const op of snap.ops) if (op.type === 'keychain') await store?.remove(op.service).catch(() => {});
  snap.status = 'undone';
  snap.undoneAt = new Date().toISOString();
  await writeJsonFile(file, snap);
  await audit({ action: 'undo', id, title: snap.title, files: snap.files });
  return snap;
}

export class ConflictError extends Error {}

/**
 * Apply a set of JSON edits outside the finding-based planner (installing
 * ai-bom's own hooks, for example), with the same snapshot, audit log and undo.
 */
export async function applyChanges(title: string, kind: FixKind, ops: Extract<Op, { type: 'json' }>[]): Promise<Snapshot> {
  const id = `${new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '')}-${randomBytes(3).toString('hex')}`;
  const written: { file: string; original: string }[] = [];
  const splices: Splice[] = [];
  try {
    for (const [file, list] of groupJson(ops)) {
      let doc;
      try {
        doc = await readJsonDoc(file);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
        await writeAtomic(file, '{}\n');
        doc = await readJsonDoc(file);
      }
      await writeKeepingMode(file, applyJsonOps(doc.text, list, new Map()));
      written.push({ file, original: doc.text });
    }
  } catch (e) {
    for (const w of written.reverse()) await writeKeepingMode(w.file, w.original).catch(() => {});
    throw e;
  }
  const snap: Snapshot = { id, createdAt: new Date().toISOString(), title, kind, target: {}, files: [...new Set(ops.map((o) => o.file))], ops, status: 'applied' };
  await writeJsonFile(path.join(snapshotsDir(), id, 'manifest.json'), snap);
  await audit({ action: 'install', id, title, files: snap.files });
  return snap;
}

/** Ops that append hook entries to settings.hooks[event] (creating the containers as needed). */
export async function hookInstallOps(file: string, entries: [event: string, entry: unknown][]): Promise<Extract<Op, { type: 'json' }>[]> {
  let data: Record<string, unknown> = {};
  try {
    data = ((await readJsonDoc(file)).data as Record<string, unknown>) ?? {};
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const ops: Extract<Op, { type: 'json' }>[] = [];
  // Simulate each op on a copy so later entries see the containers earlier ones created.
  const sim = JSON.parse(JSON.stringify(data)) as { hooks?: Record<string, unknown[]> };
  for (const [event, entry] of entries) {
    const list = sim.hooks?.[event];
    if (Array.isArray(list) && list.some((x) => deepEqual(x, entry))) continue;
    if (Array.isArray(list)) {
      ops.push({ type: 'json', file, path: ['hooks', event, list.length], before: { present: false }, after: { present: true, value: entry }, array: true });
      list.push(entry);
    } else if (sim.hooks) {
      ops.push({ type: 'json', file, path: ['hooks', event], before: { present: false }, after: { present: true, value: [entry] } });
      sim.hooks[event] = [entry];
    } else {
      ops.push({ type: 'json', file, path: ['hooks'], before: { present: false }, after: { present: true, value: { [event]: [entry] } } });
      sim.hooks = { [event]: [entry] };
    }
  }
  // Undo reverts in reverse order, so a container created here is removed last.
  return ops;
}
