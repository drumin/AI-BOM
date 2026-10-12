import os from 'node:os';
import path from 'node:path';
import type {
  Asset,
  AssetKind,
  Client,
  ClientId,
  ConnectorDetails,
  HookDetails,
  TelemetryDetails,
  ModelDetails,
  ApiKeyDetails,
  AppDetails,
  BrowserExtensionDetails,
  McpServerDetails,
  Occurrence,
  Project,
  ScanError,
  SkillDetails,
} from './types.js';
import { shortHash } from './util/hash.js';
import { mcpIdentity } from './mcp.js';

export interface ScanContext {
  home: string;
  platform: NodeJS.Platform;
  /** ~/Library/Application Support on macOS, ~/.config elsewhere. */
  appSupport: string;
  /** ~/.config (XDG), used by several CLIs on macOS too. */
  xdgConfig: string;
  /** %LOCALAPPDATA% on Windows (browsers, installed apps); same as appSupport elsewhere. */
  localAppData: string;
  /** Absolute project roots to scan for project-level config. */
  projects: string[];
  /** Filesystem root for system-wide (admin-managed) config; overridable for tests. */
  systemRoot: string;
  /** Claude Code config dir: $CLAUDE_CONFIG_DIR or ~/.claude. */
  claudeDir: string;
  /** Claude Code state file: $CLAUDE_CONFIG_DIR/.claude.json or ~/.claude.json. */
  claudeState: string;
}

/** One location the scanner looked at, for `ai-bom doctor`. Never contains values. */
export interface TraceEntry {
  path: string;
  status: 'found' | 'missing' | 'error';
  note?: string;
}

export function defaultContext(
  opts: { home?: string; platform?: NodeJS.Platform; projects?: string[]; systemRoot?: string; claudeConfigDir?: string } = {},
): ScanContext {
  const home = opts.home ?? os.homedir();
  const platform = opts.platform ?? process.platform;
  const appSupport =
    platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support')
      : platform === 'win32'
        ? (!opts.home && process.env.APPDATA) || path.join(home, 'AppData', 'Roaming')
        : path.join(home, '.config');
  const localAppData = platform === 'win32' ? (!opts.home && process.env.LOCALAPPDATA) || path.join(home, 'AppData', 'Local') : appSupport;
  const custom = opts.claudeConfigDir;
  return {
    home,
    platform,
    appSupport,
    localAppData,
    xdgConfig: path.join(home, '.config'),
    projects: opts.projects ?? [],
    systemRoot: opts.systemRoot ?? path.parse(home).root,
    claudeDir: custom ?? path.join(home, '.claude'),
    claudeState: custom ? path.join(custom, '.claude.json') : path.join(home, '.claude.json'),
  };
}

export interface RawAsset {
  kind: AssetKind;
  name: string;
  /** Identity used for merging; defaults to the path. */
  key?: string;
  occurrence: Occurrence;
  mcp?: McpServerDetails;
  skill?: SkillDetails;
  hook?: HookDetails;
  connector?: ConnectorDetails;
  telemetry?: TelemetryDetails;
  model?: ModelDetails;
  apiKey?: ApiKeyDetails;
  app?: AppDetails;
  browserExtension?: BrowserExtensionDetails;
  origin?: Asset['origin'];
  path?: string;
}

/** Raw settings documents kept (in memory only) for settings-level checks. */
export interface SettingsDoc {
  client: ClientId;
  scope: Occurrence['scope'];
  file: string;
  data: Record<string, unknown>;
  project?: string;
  /** Asset the settings belong to (e.g. a desktop extension's user config). */
  assetId?: string;
}

export class Collector {
  readonly clients = new Map<ClientId, Client>();
  readonly projects = new Map<string, Project>();
  readonly assets = new Map<string, Asset>();
  readonly settings: SettingsDoc[] = [];
  readonly errors: ScanError[] = [];
  readonly trace: TraceEntry[] = [];

  note(p: string, status: TraceEntry['status'], note?: string): void {
    this.trace.push({ path: p, status, note });
  }

  constructor(readonly ctx: ScanContext) {}

  client(id: ClientId, name: string, file?: string): void {
    let c = this.clients.get(id);
    if (!c) {
      c = { id, name, configFiles: [] };
      this.clients.set(id, c);
    }
    if (file && !c.configFiles.includes(file)) c.configFiles.push(file);
  }

  project(dir: string): void {
    if (!this.projects.has(dir)) this.projects.set(dir, { path: dir, name: dir === this.ctx.home ? '~ (home folder)' : path.basename(dir) || dir });
  }

  error(file: string, message: string): void {
    this.errors.push({ file, message });
  }

  /** Add an asset occurrence; returns the merged asset's id. */
  add(raw: RawAsset): string {
    let key = raw.key ?? raw.path ?? raw.name;
    if (raw.kind === 'mcp-server' && raw.mcp) {
      key = mcpIdentity(raw.mcp, this.ctx.home);
      // Plugin-relative commands (${CLAUDE_PLUGIN_ROOT}/bin/server) only mean something within their plugin.
      if (raw.occurrence.via && key.startsWith('cmd:')) key = `${raw.occurrence.via}|${key}`;
    }
    // Bundled assets live under versioned install paths (…/plugin/2.0.0/skills/x).
    // Key them by parent + name so an upgrade doesn't look like remove + add.
    else if (raw.occurrence.via) key = `${raw.occurrence.via}|${raw.name}`;
    const id = `${raw.kind}:${shortHash(raw.kind, key)}`;
    const occ = raw.occurrence;
    if (raw.mcp) {
      // The same server can be configured with different credentials in each client.
      if (raw.mcp.env) occ.env = raw.mcp.env;
      if (raw.mcp.headers) occ.headers = raw.mcp.headers;
      if (raw.mcp.url) occ.url = raw.mcp.url;
    }
    if (occ.project) this.project(occ.project);

    const existing = this.assets.get(id);
    // The home folder is also scanned as a project (for ~/.mcp.json, ~/AGENTS.md…). Files there that
    // are already user-level config (~/.claude/skills, ~/.cursor/mcp.json…) must not be counted twice.
    if (existing && occ.project === this.ctx.home && existing.occurrences.some((o) => o.source === occ.source && o.client === occ.client)) {
      return id;
    }
    if (existing) {
      const dup = existing.occurrences.some(
        (o) => o.client === occ.client && o.source === occ.source && o.name === occ.name && o.project === occ.project,
      );
      if (!dup) existing.occurrences.push(occ);
      if (raw.mcp && existing.mcp) {
        // Show the union of configured variable names; values stay per occurrence.
        if (raw.mcp.env) existing.mcp.env = { ...raw.mcp.env, ...existing.mcp.env };
        if (raw.mcp.headers) existing.mcp.headers = { ...raw.mcp.headers, ...existing.mcp.headers };
      }
      return id;
    }
    this.assets.set(id, {
      id,
      kind: raw.kind,
      name: raw.name,
      origin: raw.origin ?? 'local',
      occurrences: [occ],
      mcp: raw.mcp,
      skill: raw.skill,
      hook: raw.hook,
      connector: raw.connector,
      telemetry: raw.telemetry,
      model: raw.model,
      apiKey: raw.apiKey,
      app: raw.app,
      browserExtension: raw.browserExtension,
      path: raw.path,
    });
    return id;
  }

  /** Link bundled children (occurrence.via) to their parent assets. */
  finalizeChildren(): void {
    for (const a of this.assets.values()) {
      for (const o of a.occurrences) {
        if (!o.via) continue;
        const parent = this.assets.get(o.via);
        if (!parent) continue;
        parent.children ??= [];
        if (!parent.children.includes(a.id)) parent.children.push(a.id);
      }
    }
  }
}
