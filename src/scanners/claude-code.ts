import path from 'node:path';
import type { Collector } from '../collector.js';
import type { ClientId, Scope } from '../types.js';
import { asString, exists, isDir, isObject, listDir } from '../util/fs.js';
import { compareVersions } from '../vulns/semver.js';
import {
  addHooks,
  addInstructionsFile,
  addMcpMap,
  readConfig,
  scanMarkdownDir,
  scanSkillsDir,
  type Where,
} from './common.js';
import type { Scanner } from './index.js';

const CLIENT = 'claude-code' as const;
const NAME = 'Claude Code';

/**
 * Per-scan approval state for project .mcp.json servers, gathered at user
 * level (~/.claude.json projects[dir], user settings) and applied per project.
 */
const approvals = new WeakMap<Collector, Map<string, Record<string, unknown>>>();
const USER_KEY = '\0user-settings';

async function scanSettings(col: Collector, file: string, scope: Scope, project?: string) {
  const data = await readConfig(col, file);
  if (!data) return undefined;
  col.client(CLIENT, NAME, file);
  col.settings.push({ client: CLIENT, scope, file, data, project });
  addHooks(col, data.hooks, file, { client: CLIENT, scope, project }, ['hooks']);
  return data;
}

/** Paths in plugin.json may be a string or an array, relative to the plugin root. */
function manifestPaths(dir: string, v: unknown): string[] {
  const list = typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  return list.map((p) => path.resolve(dir, p.replace(/^\$\{CLAUDE_PLUGIN_ROOT\}\/?/, '')));
}

/** Scan a plugin install directory and register the plugin plus everything it bundles. */
export async function scanPluginDir(
  col: Collector,
  dir: string,
  meta: { id: string; version?: string; enabled?: boolean; scope: Scope; project?: string; source: string; client?: ClientId; note?: string },
): Promise<void> {
  const manifestFile = path.join(dir, '.claude-plugin', 'plugin.json');
  const manifest = (await readConfig(col, manifestFile)) ?? {};
  const author = isObject(manifest.author) ? asString(manifest.author.name) : asString(manifest.author);
  const pluginId = col.add({
    kind: 'plugin',
    name: meta.id,
    key: `claude-plugin:${meta.id}`,
    path: dir,
    skill: { description: asString(manifest.description), version: meta.version ?? asString(manifest.version), author },
    occurrence: { client: meta.client ?? CLIENT, scope: meta.scope, source: meta.source, name: meta.id, project: meta.project, enabled: meta.enabled, note: meta.note },
  });
  const where: Where = { client: meta.client ?? CLIENT, scope: meta.scope, project: meta.project, via: pluginId };

  // Default folders plus any extra locations the manifest declares.
  for (const d of new Set([path.join(dir, 'skills'), ...manifestPaths(dir, manifest.skills)])) await scanSkillsDir(col, d, where);
  for (const d of new Set([path.join(dir, 'commands'), ...manifestPaths(dir, manifest.commands)])) {
    if (d.endsWith('.md')) await scanMarkdownDir(col, path.dirname(d), 'command', where);
    else await scanMarkdownDir(col, d, 'command', where);
  }
  for (const d of new Set([path.join(dir, 'agents'), ...manifestPaths(dir, manifest.agents)])) {
    if (d.endsWith('.md')) await scanMarkdownDir(col, path.dirname(d), 'agent', where);
    else await scanMarkdownDir(col, d, 'agent', where);
  }

  for (const f of new Set([path.join(dir, 'hooks', 'hooks.json'), ...manifestPaths(dir, manifest.hooks)])) {
    const hooks = await readConfig(col, f);
    if (hooks) addHooks(col, hooks.hooks ?? hooks, f, where);
  }
  if (isObject(manifest.hooks)) addHooks(col, manifest.hooks.hooks ?? manifest.hooks, manifestFile, where);

  for (const f of new Set([path.join(dir, '.mcp.json'), ...manifestPaths(dir, manifest.mcpServers)])) {
    const mcp = await readConfig(col, f);
    if (mcp) addMcpMap(col, isObject(mcp.mcpServers) ? mcp.mcpServers : mcp, f, where);
  }
  if (isObject(manifest.mcpServers)) addMcpMap(col, manifest.mcpServers, manifestFile, where);
}

const expand = (col: Collector, p: string, base: string) =>
  p.startsWith('~') ? path.join(col.ctx.home, p.slice(1)) : path.isAbsolute(p) ? p : path.resolve(base, p);

/** Newest version folder under cache/<marketplace>/<plugin>/, or the folder itself if it is a plugin. */
async function cachedPluginDir(base: string, marketplace: string, name: string): Promise<string | undefined> {
  const root = path.join(base, 'cache', marketplace, name);
  if (!(await isDir(root))) return undefined;
  if (await exists(path.join(root, '.claude-plugin'))) return root;
  const versions = (await listDir(root)).filter((v) => !v.startsWith('.'));
  versions.sort((a, b) => compareVersions(b, a) || b.localeCompare(a));
  for (const v of versions) if (await isDir(path.join(root, v))) return path.join(root, v);
  return undefined;
}

/** Resolve a plugin inside a marketplace checkout via its marketplace.json, or by folder convention. */
async function marketplacePluginDir(col: Collector, base: string, marketplace: string, name: string): Promise<string | undefined> {
  const mroot = path.join(base, 'marketplaces', marketplace);
  if (!(await isDir(mroot))) return undefined;
  const manifest = await readConfig(col, path.join(mroot, '.claude-plugin', 'marketplace.json'));
  const entry = Array.isArray(manifest?.plugins) ? manifest!.plugins.find((p) => isObject(p) && p.name === name) : undefined;
  const src = isObject(entry) ? entry.source : undefined;
  if (typeof src === 'string') {
    const d = path.resolve(mroot, src);
    if (await isDir(d)) return d;
  }
  for (const d of [path.join(mroot, 'plugins', name), path.join(mroot, name)]) if (await isDir(d)) return d;
  return undefined;
}

/**
 * Plugins come from three places, merged:
 *  1. plugins/installed_plugins.json (v1 object or v2 array-per-id format)
 *  2. `enabledPlugins` in settings (a plugin can be enabled without being listed in 1)
 *  3. their files: plugins/cache/<marketplace>/<plugin>/<version>/ or plugins/marketplaces/<marketplace>/…
 */
async function scanPlugins(col: Collector, enabled: Record<string, unknown>) {
  const base = path.join(col.ctx.claudeDir, 'plugins');
  const file = path.join(base, 'installed_plugins.json');
  const data = await readConfig(col, file);
  const done = new Set<string>();
  let listed = 0;
  let missing = 0;

  if (data && isObject(data.plugins)) {
    for (const [id, raw] of Object.entries(data.plugins)) {
      const installs = Array.isArray(raw) ? raw : [raw];
      for (const inst of installs) {
        if (!isObject(inst)) continue;
        listed++;
        const [name, marketplace = ''] = id.split('@');
        let dir = asString(inst.installPath) ? expand(col, asString(inst.installPath)!, base) : undefined;
        if (!dir || !(await isDir(dir))) dir = (await cachedPluginDir(base, marketplace, name)) ?? (await marketplacePluginDir(col, base, marketplace, name));
        if (!dir) {
          missing++;
          continue;
        }
        const scopeRaw = asString(inst.scope);
        const scope: Scope = scopeRaw === 'project' ? 'project' : scopeRaw === 'local' ? 'local' : scopeRaw === 'managed' ? 'managed' : 'user';
        await scanPluginDir(col, dir, {
          id,
          version: asString(inst.version),
          enabled: id in enabled ? enabled[id] === true : undefined,
          scope,
          project: asString(inst.projectPath),
          source: file,
        });
        done.add(id);
      }
    }
  }

  // Enabled in settings but not in installed_plugins.json.
  let fromSettings = 0;
  for (const [id, on] of Object.entries(enabled)) {
    if (done.has(id) || !id.includes('@')) continue;
    const [name, marketplace] = id.split('@');
    const dir = (await cachedPluginDir(base, marketplace, name)) ?? (await marketplacePluginDir(col, base, marketplace, name));
    if (!dir) {
      missing++;
      continue;
    }
    await scanPluginDir(col, dir, { id, enabled: on === true, scope: 'user', source: path.join(col.ctx.claudeDir, 'settings.json') });
    done.add(id);
    fromSettings++;
  }
  // Plugins synced from a claude.ai account: plugins/synced/<account>/<plugin>/.claude-plugin/plugin.json
  const syncedRoot = path.join(base, 'synced');
  const findPlugins = async (d: string, depth: number): Promise<string[]> => {
    if (await exists(path.join(d, '.claude-plugin', 'plugin.json'))) return [d];
    if (depth >= 3) return [];
    const out: string[] = [];
    for (const n of await listDir(d)) if (!n.startsWith('.') && (await isDir(path.join(d, n)))) out.push(...(await findPlugins(path.join(d, n), depth + 1)));
    return out;
  };
  for (const dir of (await isDir(syncedRoot)) ? await findPlugins(syncedRoot, 0) : []) {
    const manifest = await readConfig(col, path.join(dir, '.claude-plugin', 'plugin.json'));
    const id = `${asString(manifest?.name) ?? path.basename(dir)}@synced`;
    if (done.has(id)) continue;
    await scanPluginDir(col, dir, { id, scope: 'user', source: syncedRoot, enabled: true });
    done.add(id);
  }
  col.note(base, (await isDir(base)) ? 'found' : 'missing', `${done.size} plugin(s) scanned (${listed} listed in installed_plugins.json, ${fromSettings} only in enabledPlugins${missing ? `, ${missing} not found on disk` : ''})`);
}

/**
 * claude.ai connectors (Gmail, Drive, Cloudflare…) are account-side, but Claude Code
 * remembers the ones that still need sign-in in mcp-needs-auth-cache.json, and some
 * versions list ever-connected ones in ~/.claude.json. Names only.
 */
async function addClaudeAiConnectors(col: Collector, state?: Record<string, unknown>) {
  const names = new Map<string, string>();
  const cacheFile = path.join(col.ctx.claudeDir, 'mcp-needs-auth-cache.json');
  const cache = await readConfig(col, cacheFile);
  if (cache) for (const n of Object.keys(cache)) names.set(n, cacheFile);
  const ever = state?.claudeAiMcpEverConnected;
  const everNames = Array.isArray(ever) ? ever.filter((x): x is string => typeof x === 'string') : isObject(ever) ? Object.keys(ever) : [];
  for (const n of everNames) if (!names.has(n)) names.set(n, col.ctx.claudeState);
  for (const [raw, source] of names) {
    const name = raw.replace(/^claude\.ai\s+/i, '').replace(/_/g, ' ');
    col.client('cloud:claude.ai', 'claude.ai', source);
    col.add({
      kind: 'connector',
      name,
      key: `connector:detected:claude.ai:${raw}`,
      origin: 'cloud',
      connector: { id: `detected:${raw}`, platform: 'claude.ai', access: 'unknown', addedAt: '', detectedIn: 'Claude Code' },
      occurrence: {
        client: 'cloud:claude.ai',
        scope: 'user',
        source,
        name: raw,
        note: source === cacheFile ? 'Connected to your Claude account; Claude Code is waiting for you to sign in to it.' : 'Connected to your Claude account and used by Claude Code.',
      },
    });
  }
}

/** Claude Code's own usage counters (skillUsage / pluginUsage in ~/.claude.json), applied after scanning. */
export const usage = new WeakMap<Collector, { skills?: unknown; plugins?: unknown }>();

export function applyUsage(col: Collector) {
  const u = usage.get(col);
  if (!u) return;
  const read = (v: unknown) => (isObject(v) ? v : {}) as Record<string, unknown>;
  const skills = read(u.skills);
  const plugins = read(u.plugins);
  const val = (e: unknown) => {
    if (!isObject(e)) return undefined;
    const count = typeof e.usageCount === 'number' ? e.usageCount : 0;
    const t = e.lastUsedAt;
    const lastUsedAt = typeof t === 'number' ? new Date(t).toISOString() : typeof t === 'string' ? t : undefined;
    return { count, lastUsedAt, source: 'counters' as const };
  };
  for (const a of col.assets.values()) {
    if (!a.occurrences.some((o) => o.client === 'claude-code')) continue;
    if (a.kind === 'skill') {
      // Keys are "name" or "plugin-namespace:name".
      const key = Object.keys(skills).find((k) => k === a.name || k.split(':').pop() === a.name);
      if (key) a.usage = val(skills[key]);
    } else if (a.kind === 'plugin') {
      if (a.name in plugins) a.usage = val(plugins[a.name]);
    }
  }
}

function managedDir(col: Collector): string | undefined {
  const root = col.ctx.systemRoot;
  if (col.ctx.platform === 'darwin') return path.join(root, 'Library', 'Application Support', 'ClaudeCode');
  if (col.ctx.platform === 'linux') return path.join(root, 'etc', 'claude-code');
  if (col.ctx.platform === 'win32') return path.join(root, 'Program Files', 'ClaudeCode');
  return undefined;
}

export const claudeCode: Scanner = {
  id: CLIENT,
  async scanUser(col) {
    const { claudeDir } = col.ctx;

    // ~/.claude.json holds user-scoped MCP servers and per-project "local" ones.
    const stateFile = col.ctx.claudeState;
    const state = await readConfig(col, stateFile);
    const perProject = new Map<string, Record<string, unknown>>();
    approvals.set(col, perProject);
    if (state) {
      col.client(CLIENT, NAME, stateFile);
      addMcpMap(col, state.mcpServers, stateFile, { client: CLIENT, scope: 'user' }, undefined, ['mcpServers']);
      if (isObject(state.projects)) {
        for (const [proj, cfg] of Object.entries(state.projects)) {
          if (!isObject(cfg)) continue;
          perProject.set(proj, cfg);
          if (isObject(cfg.mcpServers) && Object.keys(cfg.mcpServers).length) {
            addMcpMap(col, cfg.mcpServers, stateFile, { client: CLIENT, scope: 'local', project: proj }, undefined, ['projects', proj, 'mcpServers']);
          }
        }
      }
    }

    const enabledPlugins: Record<string, unknown> = {};
    for (const f of ['settings.json', 'settings.local.json', 'launcher-settings.json']) {
      const s = await scanSettings(col, path.join(claudeDir, f), 'user');
      if (s && isObject(s.enabledPlugins)) Object.assign(enabledPlugins, s.enabledPlugins);
      if (s) perProject.set(USER_KEY, { ...perProject.get(USER_KEY), ...s });
    }

    const userWhere: Where = { client: CLIENT, scope: 'user' };
    await scanSkillsDir(col, path.join(claudeDir, 'skills'), userWhere);
    await scanMarkdownDir(col, path.join(claudeDir, 'agents'), 'agent', userWhere);
    await scanMarkdownDir(col, path.join(claudeDir, 'commands'), 'command', userWhere);
    await addInstructionsFile(col, path.join(claudeDir, 'CLAUDE.md'), userWhere);
    await scanPlugins(col, enabledPlugins);
    await addClaudeAiConnectors(col, state);
    if (state) usage.set(col, { skills: state.skillUsage, plugins: state.pluginUsage });

    if (await isDir(claudeDir)) col.client(CLIENT, NAME);

    // Enterprise-managed policy (deployed by an admin; still part of your AI surface).
    const managed = managedDir(col);
    if (managed) {
      await scanSettings(col, path.join(managed, 'managed-settings.json'), 'managed');
      const mf = path.join(managed, 'managed-mcp.json');
      const m = await readConfig(col, mf);
      if (m) addMcpMap(col, m.mcpServers, mf, { client: CLIENT, scope: 'managed' }, undefined, ['mcpServers']);
    }
  },

  async scanProject(col, dir) {
    const where: Where = { client: CLIENT, scope: 'project', project: dir };
    // In the home folder, ~/.claude is the user-level config already scanned above.
    const isHome = path.resolve(dir) === path.resolve(col.ctx.home);
    const projSettings = isHome ? undefined : await scanSettings(col, path.join(dir, '.claude', 'settings.json'), 'project', dir);
    const localSettings = isHome ? undefined : await scanSettings(col, path.join(dir, '.claude', 'settings.local.json'), 'local', dir);

    const mcpFile = path.join(dir, '.mcp.json');
    const mcp = await readConfig(col, mcpFile);
    if (mcp) {
      col.client(CLIENT, NAME, mcpFile);
      // Servers from a checked-in .mcp.json only start after the user approves them.
      const approval = approvals.get(col)?.get(dir);
      const sources = [approval, localSettings, projSettings, approvals.get(col)?.get(USER_KEY)].filter(isObject);
      const pick = (key: string) => sources.flatMap((s) => (Array.isArray(s[key]) ? (s[key] as unknown[]) : []));
      const enabled = new Set(pick('enabledMcpjsonServers'));
      const disabled = new Set(pick('disabledMcpjsonServers'));
      const all = sources.some((s) => s.enableAllProjectMcpServers === true);
      addMcpMap(col, mcp.mcpServers, mcpFile, where, (name) =>
        disabled.has(name)
          ? { enabled: false, note: 'Rejected in Claude Code: this server does not start.' }
          : enabled.has(name) || all
            ? { enabled: true }
            : { note: 'Not approved yet: Claude Code will ask before starting it.' },
        ['mcpServers'],
      );
    }
    if (!isHome) {
      await scanSkillsDir(col, path.join(dir, '.claude', 'skills'), where);
      await scanMarkdownDir(col, path.join(dir, '.claude', 'agents'), 'agent', where);
      await scanMarkdownDir(col, path.join(dir, '.claude', 'commands'), 'command', where);
    }
    for (const f of isHome ? ['CLAUDE.md', 'CLAUDE.local.md'] : ['CLAUDE.md', 'CLAUDE.local.md', path.join('.claude', 'CLAUDE.md')]) {
      if (await addInstructionsFile(col, path.join(dir, f), where)) col.client(CLIENT, NAME);
    }
    if (await exists(path.join(dir, '.claude'))) col.client(CLIENT, NAME);
  },
};
