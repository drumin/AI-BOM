import path from 'node:path';
import type { Collector } from '../collector.js';
import { normalizeMcpEntry } from '../mcp.js';
import { asString, exists, isDir, isObject, listDir } from '../util/fs.js';
import { readConfig, scanMcpFile, scanSkillsDir } from './common.js';
import { scanPluginDir } from './claude-code.js';
import type { Scanner } from './index.js';

const CLIENT = 'claude-desktop' as const;
const NAME = 'Claude Desktop';

function substitute(value: string, vars: Record<string, string>): string {
  return value.replace(/\$\{([^}]+)\}/g, (m, k: string) => vars[k] ?? m);
}

/**
 * Desktop Extensions (.dxt / .mcpb) are one-click installed MCP servers.
 * Each lives in "Claude Extensions/<id>/manifest.json", with its enabled
 * flag and user-supplied config in "Claude Extensions Settings/<id>.json".
 */
async function scanExtensions(col: Collector, base: string) {
  const extRoot = path.join(base, 'Claude Extensions');
  const settingsRoot = path.join(base, 'Claude Extensions Settings');
  if (!(await isDir(extRoot))) return;
  for (const id of await listDir(extRoot)) {
    const dir = path.join(extRoot, id);
    const manifestFile = path.join(dir, 'manifest.json');
    const manifest = await readConfig(col, manifestFile);
    if (!manifest) continue;
    const settingsFile = path.join(settingsRoot, `${id}.json`);
    const settings = await readConfig(col, settingsFile);
    const enabled = settings ? settings.isEnabled !== false : undefined;

    const name = asString(manifest.display_name) ?? asString(manifest.name) ?? id;
    const author = isObject(manifest.author) ? asString(manifest.author.name) : asString(manifest.author);
    const extId = col.add({
      kind: 'extension',
      name,
      key: `claude-extension:${id}`,
      path: dir,
      skill: { description: asString(manifest.description), version: asString(manifest.version), author },
      occurrence: { client: CLIENT, scope: 'user', source: manifestFile, name: id, enabled },
    });
    // User-entered extension config (API keys etc.) is stored here in plain JSON.
    if (settings) col.settings.push({ client: CLIENT, scope: 'user', file: settingsFile, data: settings, assetId: extId });

    const server = isObject(manifest.server) ? manifest.server : undefined;
    const mcpConfig = server && isObject(server.mcp_config) ? server.mcp_config : undefined;
    if (!mcpConfig) continue;
    const vars = { __dirname: dir, HOME: col.ctx.home };
    const resolved = {
      ...mcpConfig,
      command: typeof mcpConfig.command === 'string' ? substitute(mcpConfig.command, vars) : undefined,
      args: Array.isArray(mcpConfig.args) ? mcpConfig.args.map((a) => (typeof a === 'string' ? substitute(a, vars) : a)) : [],
    };
    const norm = normalizeMcpEntry(resolved);
    if (!norm) continue;
    // Manifests declare their tools up front, so we can list them without starting the server.
    if (Array.isArray(manifest.tools)) {
      norm.details.tools = manifest.tools
        .filter(isObject)
        .map((t) => ({ name: asString(t.name) ?? '?', description: asString(t.description) }))
        .slice(0, 100);
    }
    col.add({
      kind: 'mcp-server',
      name,
      mcp: norm.details,
      occurrence: { client: CLIENT, scope: 'user', source: manifestFile, name, via: extId, enabled },
    });
  }
}

/** `<root>/<a>/<b>` folders under root (Desktop nests account and organization ids). */
async function twoLevels(root: string): Promise<string[]> {
  const out: string[] = [];
  for (const a of await listDir(root)) {
    if (a.startsWith('.') || !(await isDir(path.join(root, a)))) continue;
    for (const b of await listDir(path.join(root, a))) if (!b.startsWith('.') && (await isDir(path.join(root, a, b)))) out.push(path.join(root, a, b));
  }
  return out;
}

const SKILL_ORIGIN: Record<string, string> = {
  user: 'Added to your Claude account by you',
  anthropic: 'Built in to Claude (made by Anthropic)',
};

/**
 * Skills of the signed-in account, as Desktop keeps them:
 * local-agent-mode-sessions/skills-plugin/<account>/<org>/{manifest.json,skills/}.
 * The manifest says who made each skill and whether it is switched on. Claude Code
 * keeps a synced copy of most of them; those merge into one asset (two occurrences),
 * while the ones Code does not copy appear here for the first time.
 */
async function scanAccountSkills(col: Collector, base: string) {
  const root = path.join(base, 'local-agent-mode-sessions', 'skills-plugin');
  for (const dir of await twoLevels(root)) {
    const manifestFile = path.join(dir, 'manifest.json');
    const manifest = await readConfig(col, manifestFile);
    const listed = new Map<string, { creator?: string; enabled?: boolean }>();
    if (manifest && Array.isArray(manifest.skills)) {
      for (const s of manifest.skills) if (isObject(s) && asString(s.name)) listed.set(asString(s.name)!, { creator: asString(s.creatorType), enabled: typeof s.enabled === 'boolean' ? s.enabled : undefined });
    }
    const synced = new Map<string, string>();
    for (const a of col.assets.values()) if (a.kind === 'skill' && a.path && /[\\/]synced[\\/]/.test(a.path)) synced.set(a.name, a.path);
    await scanSkillsDir(col, path.join(dir, 'skills'), { client: CLIENT, scope: 'user' }, 1, {
      key: (name, skillDir) => synced.get(name) ?? skillDir,
      note: (name) => (manifest && !listed.has(name) ? 'In the skills folder but not in your account\'s skill list' : SKILL_ORIGIN[listed.get(name)?.creator ?? ''] ?? 'In your Claude account'),
      enabled: (name) => listed.get(name)?.enabled,
    });
  }
}

/** Plugins installed through Desktop (Cowork / "Customize"): local-agent-mode-sessions/<account>/<org>/rpm/. */
async function scanAccountPlugins(col: Collector, base: string) {
  const root = path.join(base, 'local-agent-mode-sessions');
  for (const dir of await twoLevels(root)) {
    const rpm = path.join(dir, 'rpm');
    const manifestFile = path.join(rpm, 'manifest.json');
    const manifest = await readConfig(col, manifestFile);
    if (!manifest || !Array.isArray(manifest.plugins)) continue;
    for (const p of manifest.plugins) {
      if (!isObject(p)) continue;
      const pid = asString(p.id);
      const pdir = pid && !/[\\/]/.test(pid) ? path.join(rpm, pid) : undefined;
      if (!pdir || !(await exists(pdir))) continue;
      const plugin = await readConfig(col, path.join(pdir, '.claude-plugin', 'plugin.json'));
      const name = asString(plugin?.name) ?? asString(p.name) ?? pid!;
      const by = asString(p.installedBy);
      const from = asString(p.marketplaceName);
      await scanPluginDir(col, pdir, {
        id: `${name}@synced`,
        scope: 'user',
        source: manifestFile,
        client: CLIENT,
        note: [asString(p.displayName) && asString(p.displayName) !== name ? `"${asString(p.displayName)}"` : '', from ? `from the ${from} marketplace` : '', by ? `installed by ${by === 'user' ? 'you' : by}` : ''].filter(Boolean).join(', ') || undefined,
      });
    }
  }
}

export const claudeDesktop: Scanner = {
  id: CLIENT,
  async scanUser(col) {
    const base = path.join(col.ctx.appSupport, 'Claude');
    const file = path.join(base, 'claude_desktop_config.json');
    await scanMcpFile(col, file, ['mcpServers'], { client: CLIENT, scope: 'user' }, NAME);
    await scanExtensions(col, base);
    await scanAccountSkills(col, base);
    await scanAccountPlugins(col, base);
    if (await isDir(base)) col.client(CLIENT, NAME);
  },
};
