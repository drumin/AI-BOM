import path from 'node:path';
import type { Collector } from '../collector.js';
import type { ClientId } from '../types.js';
import { asString, asStringArray, asStringRecord, exists, isDir, isObject, listDir, readSmallText } from '../util/fs.js';
import { classifySecret } from '../util/secrets.js';
import { addKey, AI_KEY_VARS, gitignores } from './wider.js';
import {
  addHooks,
  addInstructionsFile,
  addMcpMap,
  readConfig,
  scanMarkdownDir,
  scanMcpFile,
  scanSkillsDir,
  type Where,
} from './common.js';
import type { Scanner } from './index.js';

type PathFn = (col: Collector) => string;

interface SimpleClient {
  id: ClientId;
  name: string;
  /** Directory whose presence means the client is installed. */
  detect?: PathFn[];
  userMcp?: { file: PathFn; keys: string[] }[];
  projectMcp?: { file: string; keys: string[] }[];
  userSkills?: PathFn[];
  projectSkills?: string[];
  userInstructions?: PathFn[];
  projectInstructions?: string[];
  /** Directories of markdown rules/commands (kind, dir). */
  userMarkdown?: { kind: 'command' | 'agent' | 'instructions'; dir: PathFn; exts?: string[] }[];
  projectMarkdown?: { kind: 'command' | 'agent' | 'instructions'; dir: string; exts?: string[] }[];
  userHooks?: PathFn[];
  projectHooks?: string[];
}

const home = (...p: string[]): PathFn => (col) => path.join(col.ctx.home, ...p);
const app = (...p: string[]): PathFn => (col) => path.join(col.ctx.appSupport, ...p);
const xdg = (...p: string[]): PathFn => (col) => path.join(col.ctx.xdgConfig, ...p);

const VSCODE_FLAVORS = ['Code', 'Code - Insiders', 'VSCodium'];
/** Editors that host the Cline / Roo Code extensions. */
const EXTENSION_HOSTS = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];

const SIMPLE: SimpleClient[] = [
  {
    id: 'cursor',
    name: 'Cursor',
    detect: [home('.cursor'), app('Cursor')],
    userMcp: [{ file: home('.cursor', 'mcp.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.cursor/mcp.json', keys: ['mcpServers'] }],
    projectInstructions: ['.cursorrules'],
    userMarkdown: [{ kind: 'command', dir: home('.cursor', 'commands') }],
    projectMarkdown: [
      { kind: 'instructions', dir: '.cursor/rules', exts: ['.mdc', '.md'] },
      { kind: 'command', dir: '.cursor/commands' },
    ],
    userSkills: [home('.cursor', 'skills')],
    projectSkills: ['.cursor/skills'],
    userHooks: [home('.cursor', 'hooks.json')],
    projectHooks: ['.cursor/hooks.json'],
  },
  {
    id: 'vscode',
    name: 'VS Code / Copilot',
    detect: VSCODE_FLAVORS.map((f) => app(f, 'User')),
    userMcp: VSCODE_FLAVORS.flatMap((f) => [
      { file: app(f, 'User', 'mcp.json'), keys: ['servers', 'mcpServers'] },
      { file: app(f, 'User', 'settings.json'), keys: ['mcp.servers'] },
    ]),
    projectMcp: [{ file: '.vscode/mcp.json', keys: ['servers', 'mcpServers'] }],
    projectInstructions: ['.github/copilot-instructions.md'],
    userMarkdown: VSCODE_FLAVORS.map((f) => ({ kind: 'command' as const, dir: app(f, 'User', 'prompts'), exts: ['.md'] })),
    projectMarkdown: [
      { kind: 'instructions', dir: '.github/instructions' },
      { kind: 'command', dir: '.github/prompts' },
      { kind: 'agent', dir: '.github/agents' },
      { kind: 'agent', dir: '.github/chatmodes' },
    ],
    projectSkills: ['.github/skills'],
  },
  {
    id: 'cline',
    name: 'Cline',
    userMcp: EXTENSION_HOSTS.map((h) => ({
      file: app(h, 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
      keys: ['mcpServers'],
    })),
    projectInstructions: ['.clinerules'],
    projectMarkdown: [{ kind: 'instructions', dir: '.clinerules' }],
  },
  {
    id: 'roo-code',
    name: 'Roo Code',
    userMcp: EXTENSION_HOSTS.map((h) => ({
      file: app(h, 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'),
      keys: ['mcpServers'],
    })),
    projectMcp: [{ file: '.roo/mcp.json', keys: ['mcpServers'] }],
    projectMarkdown: [{ kind: 'instructions', dir: '.roo/rules' }],
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    detect: [home('.codeium', 'windsurf')],
    userMcp: [
      { file: home('.codeium', 'windsurf', 'mcp_config.json'), keys: ['mcpServers'] },
      // Windsurf's docs moved to Devin; Cascade's MCP file is now ~/.config/devin (%APPDATA%\\devin on Windows).
      { file: (col) => (col.ctx.platform === 'win32' ? path.join(col.ctx.appSupport, 'devin', 'mcp_config.json') : path.join(col.ctx.xdgConfig, 'devin', 'mcp_config.json')), keys: ['mcpServers'] },
    ],
    userInstructions: [home('.codeium', 'windsurf', 'memories', 'global_rules.md')],
    projectInstructions: ['.windsurfrules'],
    // Windsurf's docs moved to Devin: .devin/ is preferred, .windsurf/ is still read.
    projectMarkdown: [
      { kind: 'instructions', dir: '.devin/rules' },
      { kind: 'instructions', dir: '.windsurf/rules' },
      { kind: 'command', dir: '.devin/workflows' },
      { kind: 'command', dir: '.windsurf/workflows' },
    ],
    userSkills: [home('.codeium', 'windsurf', 'skills'), xdg('devin', 'skills')],
    projectSkills: ['.devin/skills', '.windsurf/skills'],
    userHooks: [home('.codeium', 'windsurf', 'hooks.json')],
    projectHooks: ['.devin/hooks.json', '.windsurf/hooks.json'],
  },
  {
    id: 'gemini-cli',
    name: 'Gemini CLI',
    detect: [home('.gemini')],
    userMcp: [{ file: home('.gemini', 'settings.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.gemini/settings.json', keys: ['mcpServers'] }],
    userSkills: [home('.gemini', 'skills')],
    projectSkills: ['.gemini/skills'],
    userInstructions: [home('.gemini', 'GEMINI.md')],
    projectInstructions: ['GEMINI.md'],
    userMarkdown: [{ kind: 'command', dir: home('.gemini', 'commands'), exts: ['.toml'] }],
    projectMarkdown: [{ kind: 'command', dir: '.gemini/commands', exts: ['.toml'] }],
  },
  {
    id: 'codex',
    name: 'Codex CLI',
    detect: [home('.codex')],
    userMcp: [{ file: home('.codex', 'config.toml'), keys: ['mcp_servers'] }],
    projectMcp: [{ file: '.codex/config.toml', keys: ['mcp_servers'] }],
    userInstructions: [home('.codex', 'AGENTS.md')],
    userSkills: [home('.codex', 'skills')],
    projectSkills: ['.codex/skills'],
    userHooks: [home('.codex', 'hooks.json')],
    projectHooks: ['.codex/hooks.json'],
    userMarkdown: [{ kind: 'command', dir: home('.codex', 'prompts') }],
  },
  {
    id: 'copilot-cli',
    name: 'GitHub Copilot CLI',
    detect: [home('.copilot')],
    userMcp: [{ file: home('.copilot', 'mcp-config.json'), keys: ['mcpServers'] }],
    userSkills: [home('.copilot', 'skills')],
    // It also reads a project .mcp.json, but that file is shared with Claude Code and listed under it.
    projectMcp: [{ file: '.github/mcp.json', keys: ['mcpServers'] }],
  },
  {
    id: 'factory-droid',
    name: 'Factory Droid',
    detect: [home('.factory')],
    userMcp: [{ file: home('.factory', 'mcp.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.factory/mcp.json', keys: ['mcpServers'] }],
    userSkills: [home('.factory', 'skills')],
    projectSkills: ['.factory/skills'],
    userMarkdown: [
      { kind: 'agent', dir: home('.factory', 'droids') },
      { kind: 'command', dir: home('.factory', 'commands') },
    ],
    projectMarkdown: [
      { kind: 'agent', dir: '.factory/droids' },
      { kind: 'command', dir: '.factory/commands' },
    ],
  },
  {
    id: 'qwen-code',
    name: 'Qwen Code',
    detect: [home('.qwen')],
    userMcp: [{ file: home('.qwen', 'settings.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.qwen/settings.json', keys: ['mcpServers'] }],
    userSkills: [home('.qwen', 'skills')],
    projectSkills: ['.qwen/skills'],
    userInstructions: [home('.qwen', 'QWEN.md')],
    projectInstructions: ['QWEN.md'],
  },
  {
    id: 'junie',
    name: 'JetBrains Junie',
    detect: [home('.junie')],
    userMcp: [{ file: home('.junie', 'mcp', 'mcp.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.junie/mcp/mcp.json', keys: ['mcpServers'] }],
    projectInstructions: ['.junie/AGENTS.md', '.junie/guidelines.md'],
    projectMarkdown: [{ kind: 'instructions', dir: '.junie/rules' }],
  },
  {
    id: 'augment',
    name: 'Augment (Auggie)',
    detect: [home('.augment')],
    userMcp: [{ file: home('.augment', 'settings.json'), keys: ['mcpServers'] }],
    userMarkdown: [{ kind: 'instructions', dir: home('.augment', 'rules') }],
    projectMarkdown: [{ kind: 'instructions', dir: '.augment/rules' }],
    projectInstructions: ['.augment-guidelines'],
  },
  {
    id: 'trae',
    name: 'Trae',
    detect: [home('.trae')],
    projectMcp: [{ file: '.trae/mcp.json', keys: ['mcpServers'] }],
    projectMarkdown: [{ kind: 'instructions', dir: '.trae/rules' }],
    projectSkills: ['.trae/skills'],
  },
  {
    id: 'crush',
    name: 'Crush',
    detect: [xdg('crush'), home('.local', 'share', 'crush')],
    // Crush keeps servers under an `mcp` key, each with a `type` of stdio, http or sse.
    userMcp: [{ file: xdg('crush', 'crush.json'), keys: ['mcp'] }],
    projectMcp: [
      { file: 'crush.json', keys: ['mcp'] },
      { file: '.crush.json', keys: ['mcp'] },
    ],
    projectInstructions: ['CRUSH.md'],
  },
  {
    id: 'kilo-code',
    name: 'Kilo Code',
    userMcp: EXTENSION_HOSTS.map((h) => ({
      file: app(h, 'User', 'globalStorage', 'kilocode.kilo-code', 'settings', 'mcp_settings.json'),
      keys: ['mcpServers'],
    })),
    projectMcp: [{ file: '.kilocode/mcp.json', keys: ['mcpServers'] }],
    projectMarkdown: [
      { kind: 'instructions', dir: '.kilocode/rules' },
      { kind: 'command', dir: '.kilocode/workflows' },
    ],
  },
  {
    id: 'kilo-cli',
    name: 'Kilo CLI',
    detect: [xdg('kilo')],
    userMcp: [{ file: xdg('kilo', 'kilo.json'), keys: ['mcp', 'mcpServers'] }],
  },
  {
    id: 'antigravity',
    name: 'Google Antigravity',
    detect: [home('.gemini', 'antigravity'), home('.gemini', 'antigravity-cli'), home('.gemini', 'antigravity-ide'), home('.antigravity')],
    userMcp: ['antigravity', 'antigravity-cli', 'antigravity-ide'].map((d) => ({ file: home('.gemini', d, 'mcp_config.json'), keys: ['mcpServers'] })),
    userSkills: [home('.gemini', 'antigravity', 'skills')],
    projectSkills: ['.agent/skills'],
    projectMarkdown: [
      { kind: 'instructions', dir: '.agent/rules' },
      { kind: 'command', dir: '.agent/workflows' },
    ],
  },
  {
    id: 'lm-studio',
    name: 'LM Studio',
    detect: [home('.lmstudio')],
    userMcp: [{ file: home('.lmstudio', 'mcp.json'), keys: ['mcpServers'] }],
  },
  {
    id: 'amazon-q',
    name: 'Amazon Q Developer',
    detect: [home('.aws', 'amazonq')],
    userMcp: [{ file: home('.aws', 'amazonq', 'mcp.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.amazonq/mcp.json', keys: ['mcpServers'] }],
    projectMarkdown: [{ kind: 'instructions', dir: '.amazonq/rules' }],
  },
  {
    id: 'kiro',
    name: 'Kiro',
    detect: [home('.kiro')],
    userMcp: [{ file: home('.kiro', 'settings', 'mcp.json'), keys: ['mcpServers'] }],
    projectMcp: [{ file: '.kiro/settings/mcp.json', keys: ['mcpServers'] }],
    userMarkdown: [{ kind: 'instructions', dir: home('.kiro', 'steering') }],
    projectMarkdown: [{ kind: 'instructions', dir: '.kiro/steering' }],
  },
];

function simpleScanner(c: SimpleClient): Scanner {
  return {
    id: c.id,
    async scanUser(col) {
      const where: Where = { client: c.id, scope: 'user' };
      for (const m of c.userMcp ?? []) await scanMcpFile(col, m.file(col), m.keys, where, c.name);
      for (const d of c.userSkills ?? []) await scanSkillsDir(col, d(col), where);
      for (const f of c.userInstructions ?? []) if (await addInstructionsFile(col, f(col), where)) col.client(c.id, c.name);
      for (const m of c.userMarkdown ?? []) await scanMarkdownDir(col, m.dir(col), m.kind, where, m.exts);
      for (const h of c.userHooks ?? []) {
        const data = await readConfig(col, h(col));
        if (data) addHooks(col, data.hooks, h(col), where, ['hooks']);
      }
      for (const d of c.detect ?? []) if (await exists(d(col))) col.client(c.id, c.name);
      // Any asset attributed to this client also means the client is present.
      if ([...col.assets.values()].some((a) => a.occurrences.some((o) => o.client === c.id))) col.client(c.id, c.name);
    },
    async scanProject(col, dir) {
      const where: Where = { client: c.id, scope: 'project', project: dir };
      const before = col.assets.size;
      for (const m of c.projectMcp ?? []) await scanMcpFile(col, path.join(dir, m.file), m.keys, where, c.name);
      for (const s of c.projectSkills ?? []) await scanSkillsDir(col, path.join(dir, s), where);
      for (const f of c.projectInstructions ?? []) await addInstructionsFile(col, path.join(dir, f), where);
      for (const m of c.projectMarkdown ?? []) await scanMarkdownDir(col, path.join(dir, m.dir), m.kind, where, m.exts);
      for (const h of c.projectHooks ?? []) {
        const file = path.join(dir, h);
        const data = await readConfig(col, file);
        if (data) addHooks(col, data.hooks, file, where, ['hooks']);
      }
      if (col.assets.size > before) col.client(c.id, c.name);
    },
  };
}

/* ---------- Clients with their own config shapes ---------- */

/** Zed: `context_servers: { name: { command: { path, args, env } } | { command, args } | { url } }` */
const zed: Scanner = {
  id: 'zed',
  async scanUser(col) {
    // Windows keeps Zed's settings in %APPDATA%\Zed.
    const zdir = col.ctx.platform === 'win32' ? path.join(col.ctx.appSupport, 'Zed') : path.join(col.ctx.xdgConfig, 'zed');
    const file = path.join(zdir, 'settings.json');
    const data = await readConfig(col, file);
    if (await isDir(zdir)) col.client('zed', 'Zed');
    if (!data || !isObject(data.context_servers)) return;
    col.client('zed', 'Zed', file);
    const map: Record<string, unknown> = {};
    for (const [name, v] of Object.entries(data.context_servers)) {
      if (!isObject(v)) continue;
      if (isObject(v.command)) {
        map[name] = { command: v.command.path ?? v.command.command, args: v.command.args, env: v.command.env };
      } else map[name] = v;
    }
    addMcpMap(col, map, file, { client: 'zed', scope: 'user' }, undefined, ['context_servers']);
  },
  async scanProject(col, dir) {
    const file = path.join(dir, '.zed', 'settings.json');
    const data = await readConfig(col, file);
    if (data && isObject(data.context_servers)) {
      col.client('zed', 'Zed', file);
      addMcpMap(col, data.context_servers, file, { client: 'zed', scope: 'project', project: dir }, undefined, ['context_servers']);
    }
  },
};

function continueList(col: Collector, list: unknown, file: string, where: Where) {
  if (!Array.isArray(list)) return;
  const map: Record<string, unknown> = {};
  list.forEach((s, i) => {
    if (!isObject(s)) return;
    const t = isObject(s.transport) ? s.transport : s;
    map[asString(s.name) ?? `server-${i + 1}`] = t;
  });
  addMcpMap(col, map, file, where);
}

/** Continue: YAML `mcpServers: [...]`, legacy JSON `experimental.modelContextProtocolServers`, and project blocks. */
const continueDev: Scanner = {
  id: 'continue',
  async scanUser(col) {
    const dir = path.join(col.ctx.home, '.continue');
    if (!(await isDir(dir))) return;
    col.client('continue', 'Continue');
    const where: Where = { client: 'continue', scope: 'user' };
    const yml = await readConfig(col, path.join(dir, 'config.yaml'));
    if (yml) continueList(col, yml.mcpServers, path.join(dir, 'config.yaml'), where);
    const json = await readConfig(col, path.join(dir, 'config.json'));
    if (json && isObject(json.experimental)) {
      continueList(col, json.experimental.modelContextProtocolServers, path.join(dir, 'config.json'), where);
    }
    await scanBlocks(col, path.join(dir, 'mcpServers'), where);
  },
  async scanProject(col, dir) {
    await scanBlocks(col, path.join(dir, '.continue', 'mcpServers'), { client: 'continue', scope: 'project', project: dir });
    await scanMarkdownDir(col, path.join(dir, '.continue', 'rules'), 'instructions', { client: 'continue', scope: 'project', project: dir });
  },
};

async function scanBlocks(col: Collector, dir: string, where: Where) {
  for (const f of await listDir(dir)) {
    if (!/\.(ya?ml|json)$/.test(f)) continue;
    const file = path.join(dir, f);
    const data = await readConfig(col, file);
    if (!data) continue;
    col.client('continue', 'Continue', file);
    continueList(col, data.mcpServers, file, where);
  }
}

/** Goose: `extensions: { key: { type: stdio|sse|streamable_http|builtin, cmd, args, envs, uri, enabled } }` */
const goose: Scanner = {
  id: 'goose',
  async scanUser(col) {
    const file = col.ctx.platform === 'win32' ? path.join(col.ctx.appSupport, 'Block', 'goose', 'config', 'config.yaml') : path.join(col.ctx.xdgConfig, 'goose', 'config.yaml');
    const data = await readConfig(col, file);
    if (!data) return;
    col.client('goose', 'Goose', file);
    if (!isObject(data.extensions)) return;
    const map: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(data.extensions)) {
      if (!isObject(v) || v.type === 'builtin' || v.type === 'platform') continue;
      map[asString(v.name) ?? key] = {
        command: v.cmd,
        args: v.args,
        env: v.envs,
        url: v.uri,
        type: v.type === 'sse' ? 'sse' : v.uri ? 'http' : undefined,
        enabled: v.enabled,
      };
    }
    addMcpMap(col, map, file, { client: 'goose', scope: 'user' });
  },
};

/** opencode: `mcp: { name: { type: local, command: [...], environment } | { type: remote, url, headers } }` */
function opencodeMap(data: Record<string, unknown>): Record<string, unknown> {
  const map: Record<string, unknown> = {};
  if (!isObject(data.mcp)) return map;
  for (const [name, v] of Object.entries(data.mcp)) {
    if (!isObject(v)) continue;
    const cmd = asStringArray(v.command);
    map[name] = cmd
      ? { command: cmd[0], args: cmd.slice(1), env: asStringRecord(v.environment), enabled: v.enabled }
      : { url: v.url, headers: v.headers, enabled: v.enabled };
  }
  return map;
}

/**
 * opencode keeps agents, commands, skills and plugins in `agents/ commands/ skills/ plugins/`
 * (older versions: singular `agent/ command/`), both in ~/.config/opencode and in a project's .opencode.
 * Plugins are JS/TS modules that run inside opencode, so each file is listed as an asset.
 */
async function opencodeFolder(col: Collector, root: string, where: Where) {
  for (const n of ['agents', 'agent']) await scanMarkdownDir(col, path.join(root, n), 'agent', where);
  for (const n of ['commands', 'command']) await scanMarkdownDir(col, path.join(root, n), 'command', where);
  await scanSkillsDir(col, path.join(root, 'skills'), where);
  const plugins = path.join(root, 'plugins');
  for (const name of await listDir(plugins)) {
    const file = path.join(plugins, name);
    if (name.startsWith('.') || !/\.(?:[cm]?[jt]s)$/.test(name) || (await isDir(file))) continue;
    col.add({ kind: 'plugin', name: name.replace(/\.[^.]+$/, ''), key: file, path: file, occurrence: { client: 'opencode', scope: where.scope, source: file, name, project: where.project, note: 'Runs as code inside opencode' } });
    col.client('opencode', 'opencode');
  }
}

const opencode: Scanner = {
  id: 'opencode',
  async scanUser(col) {
    const dir = path.join(col.ctx.xdgConfig, 'opencode');
    if (await isDir(dir)) col.client('opencode', 'opencode');
    for (const f of ['opencode.json', 'opencode.jsonc']) {
      const file = path.join(dir, f);
      const data = await readConfig(col, file);
      if (!data) continue;
      col.client('opencode', 'opencode', file);
      addMcpMap(col, opencodeMap(data), file, { client: 'opencode', scope: 'user' }, undefined, ['mcp']);
    }
    await addInstructionsFile(col, path.join(dir, 'AGENTS.md'), { client: 'opencode', scope: 'user' });
    await opencodeFolder(col, dir, { client: 'opencode', scope: 'user' });
  },
  async scanProject(col, dir) {
    const where: Where = { client: 'opencode', scope: 'project', project: dir };
    for (const f of ['opencode.json', 'opencode.jsonc', path.join('.opencode', 'opencode.json'), path.join('.opencode', 'opencode.jsonc')]) {
      const file = path.join(dir, f);
      const data = await readConfig(col, file);
      if (!data) continue;
      col.client('opencode', 'opencode', file);
      addMcpMap(col, opencodeMap(data), file, where, undefined, ['mcp']);
    }
    await opencodeFolder(col, path.join(dir, '.opencode'), where);
  },
};

/** Gemini CLI extensions bundle MCP servers and context files. */
const geminiExtensions: Scanner = {
  id: 'gemini-cli',
  async scanUser(col) {
    const root = path.join(col.ctx.home, '.gemini', 'extensions');
    for (const name of await listDir(root)) {
      const dir = path.join(root, name);
      const file = path.join(dir, 'gemini-extension.json');
      const manifest = await readConfig(col, file);
      if (!manifest) continue;
      col.client('gemini-cli', 'Gemini CLI', file);
      const extId = col.add({
        kind: 'extension',
        name: asString(manifest.name) ?? name,
        key: `gemini-extension:${dir}`,
        path: dir,
        skill: { version: asString(manifest.version), description: asString(manifest.description) },
        occurrence: { client: 'gemini-cli', scope: 'user', source: file, name },
      });
      addMcpMap(col, manifest.mcpServers, file, { client: 'gemini-cli', scope: 'user', via: extId });
      await scanMarkdownDir(col, path.join(dir, 'commands'), 'command', { client: 'gemini-cli', scope: 'user', via: extId }, ['.toml']);
    }
  },
};

/** Cross-tool conventions read by many agents (AGENTS.md, .agents/skills). */
const shared: Scanner = {
  id: 'generic',
  async scanUser(col) {
    await scanSkillsDir(col, path.join(col.ctx.home, '.agents', 'skills'), { client: 'generic', scope: 'user' });
    if ([...col.assets.values()].some((a) => a.occurrences.some((o) => o.client === 'generic'))) col.client('generic', 'Cross-tool (AGENTS.md)');
  },
  async scanProject(col, dir) {
    const where: Where = { client: 'generic', scope: 'project', project: dir };
    let found = await addInstructionsFile(col, path.join(dir, 'AGENTS.md'), where);
    const before = col.assets.size;
    await scanSkillsDir(col, path.join(dir, '.agents', 'skills'), where);
    found ||= col.assets.size > before;
    if (found) col.client('generic', 'Cross-tool (AGENTS.md)');
  },
};

/**
 * Amp: servers live under the literal key "amp.mcpServers" in ~/.config/amp/settings.json
 * and in a workspace's .amp/settings.json.
 */
const amp: Scanner = {
  id: 'amp',
  async scanUser(col) {
    const file = path.join(col.ctx.xdgConfig, 'amp', 'settings.json');
    const data = await readConfig(col, file);
    if (!data) return;
    col.client('amp', 'Amp', file);
    addMcpMap(col, data['amp.mcpServers'], file, { client: 'amp', scope: 'user' }, undefined, ['amp.mcpServers']);
  },
  async scanProject(col, dir) {
    const file = path.join(dir, '.amp', 'settings.json');
    const data = await readConfig(col, file);
    if (!data) return;
    col.client('amp', 'Amp', file);
    addMcpMap(col, data['amp.mcpServers'], file, { client: 'amp', scope: 'project', project: dir }, undefined, ['amp.mcpServers']);
  },
};

/** Aider has no MCP, but its config can hold API keys in plain text and names convention files the model reads. */
const AIDER_KEYS: Record<string, string> = { 'openai-api-key': 'OPENAI_API_KEY', 'anthropic-api-key': 'ANTHROPIC_API_KEY' };

async function aiderFile(col: Collector, file: string, project?: string) {
  const data = await readConfig(col, file);
  if (!data) return;
  col.client('aider', 'Aider', file);
  const text = (await readSmallText(file)) ?? '';
  const lineOf = (key: string) => Math.max(1, text.split('\n').findIndex((l) => l.trimStart().startsWith(`${key}:`)) + 1);
  const gitDir = project ? await exists(path.join(project, '.git')) : false;
  const ignored = gitDir ? gitignores((await readSmallText(path.join(project!, '.gitignore'))) ?? '', path.basename(file)) : undefined;
  const found: [string, string, number][] = [];
  for (const [key, env] of Object.entries(AIDER_KEYS)) if (typeof data[key] === 'string') found.push([env, data[key] as string, lineOf(key)]);
  for (const entry of asStringArray(data['api-key']) ?? []) {
    const [provider, ...rest] = entry.split('=');
    found.push([`${provider.trim().toUpperCase().replace(/-/g, '_')}_API_KEY`, rest.join('='), lineOf('api-key')]);
  }
  for (const entry of asStringArray(data['set-env']) ?? []) {
    const [name, ...rest] = entry.split('=');
    found.push([name.trim(), rest.join('='), lineOf('set-env')]);
  }
  for (const [name, value, line] of found) {
    if (AI_KEY_VARS[name] && value && classifySecret(name, value)) addKey(col, name, value, file, line, project, ignored);
  }
  // Files named in `read:` are fed to the model on every run.
  const reads = typeof data.read === 'string' ? [data.read] : (asStringArray(data.read) ?? []);
  const base = project ?? col.ctx.home;
  for (const r of reads.slice(0, 10)) {
    const target = path.resolve(base, r.replace(/^~(?=\/)/, col.ctx.home));
    await addInstructionsFile(col, target, { client: 'aider', scope: project ? 'project' : 'user', project });
  }
}

const aider: Scanner = {
  id: 'aider',
  async scanUser(col) {
    await aiderFile(col, path.join(col.ctx.home, '.aider.conf.yml'));
  },
  async scanProject(col, dir) {
    if (path.resolve(dir) === path.resolve(col.ctx.home)) return;
    await aiderFile(col, path.join(dir, '.aider.conf.yml'), dir);
  },
};

export const otherScanners: Scanner[] = [...SIMPLE.map(simpleScanner), zed, continueDev, goose, opencode, geminiExtensions, amp, aider, shared];
