import type { Asset, AssetKind, ClientId, Inventory, Scope, Severity } from '../../src/types';

export type { Asset, AssetKind, ClientId, Inventory, Scope, Severity };
export type { Finding, Client, Occurrence, FixKind, Reach, TrustInfo, ToolBehavior, TriageStatus } from '../../src/types';

export const KIND_LABEL: Record<AssetKind, { one: string; many: string }> = {
  'mcp-server': { one: 'MCP server', many: 'MCP servers' },
  skill: { one: 'Skill', many: 'Skills' },
  plugin: { one: 'Plugin', many: 'Plugins' },
  extension: { one: 'Extension', many: 'Extensions' },
  agent: { one: 'Subagent', many: 'Subagents' },
  command: { one: 'Command', many: 'Commands' },
  hook: { one: 'Hook', many: 'Hooks' },
  instructions: { one: 'Instructions', many: 'Instruction files' },
  connector: { one: 'Cloud connector', many: 'Cloud connectors' },
  telemetry: { one: 'Telemetry export', many: 'Telemetry exports' },
  model: { one: 'Local model', many: 'Local models' },
  'api-key': { one: 'AI API key', many: 'AI API keys' },
  app: { one: 'AI app', many: 'AI apps' },
  'browser-extension': { one: 'Browser extension', many: 'Browser extensions' },
};

/** Kind -> CSS custom property carrying its categorical color (fixed order, see styles.css). */
export const KIND_VAR: Record<AssetKind, string> = {
  'mcp-server': '--series-1',
  skill: '--series-2',
  plugin: '--series-3',
  hook: '--series-4',
  agent: '--series-5',
  command: '--series-6',
  extension: '--series-3', // same family as plugins: installable bundles
  instructions: '--kind-neutral',
  connector: '--series-7',
  // The wider inventory reuses the palette; each kind keeps its own shape (KindMark).
  telemetry: '--series-5',
  model: '--series-6',
  'api-key': '--series-4',
  app: '--kind-neutral',
  'browser-extension': '--series-3',
};

export const KIND_ORDER: AssetKind[] = ['mcp-server', 'skill', 'plugin', 'extension', 'agent', 'command', 'hook', 'telemetry', 'instructions', 'connector', 'api-key', 'model', 'browser-extension', 'app'];

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const SEV_VAR: Record<Severity, string> = {
  critical: '--status-critical',
  high: '--status-serious',
  medium: '--status-warning',
  low: '--status-low',
  info: '--status-low',
};

export const SCOPE_LABEL: Record<Scope, string> = {
  user: 'User',
  project: 'Project',
  local: 'Project (private)',
  managed: 'Managed',
};

export const sevRank = (s?: Severity) => (s ? SEVERITIES.indexOf(s) : 99);

export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Remote = the server runs somewhere else; these are the "connectors" of the local world. */
export function isRemote(a: Asset): boolean {
  return a.kind === 'mcp-server' && (!!a.mcp?.url || !!a.mcp?.remoteUrl);
}

export function subtitle(a: Asset): string {
  if (a.mcp) {
    if (a.mcp.url) return a.mcp.url;
    if (a.mcp.remoteUrl) return `→ ${a.mcp.remoteUrl}`;
    const p = a.mcp.package;
    if (p && (p.ecosystem === 'npm' || p.ecosystem === 'pypi' || p.ecosystem === 'docker')) return `${p.ecosystem}: ${p.name}${p.version ? `@${p.version}` : ''}`;
    return [a.mcp.command, ...(a.mcp.args ?? [])].join(' ');
  }
  if (a.hook) return a.hook.command;
  if (a.telemetry) return `${a.telemetry.endpoint ?? 'local'}${a.telemetry.logsPrompts ? ' · includes prompts' : ''}`;
  if (a.apiKey) return `${a.apiKey.variable} = ${a.apiKey.masked}`;
  if (a.model) return [a.model.runtime, a.model.format, a.model.sizeBytes && formatBytes(a.model.sizeBytes)].filter(Boolean).join(' · ');
  if (a.app) return a.app.version ? `Version ${a.app.version}` : a.path ?? '';
  if (a.browserExtension) return `${a.browserExtension.browser}${a.browserExtension.allSites ? ' · all sites' : ''}`;
  if (a.connector) return `${a.connector.platform} · ${a.connector.access === 'read-write' ? 'read & write' : a.connector.access === 'read' ? 'read only' : 'access unknown'}`;
  if (a.skill?.description) return a.skill.description;
  return a.path ?? '';
}

export function formatBytes(n: number): string {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

export function clientName(inv: Inventory, id: ClientId): string {
  if (id.startsWith('cloud:')) return id.slice(6);
  return inv.clients.find((c) => c.id === id)?.name ?? id;
}

export type { Capability } from '../../src/types';
import type { Capability } from '../../src/types';

export const CAPABILITY_LABEL: Record<Capability, string> = {
  'runs-scripts': 'Runs scripts',
  network: 'Network access',
  subprocess: 'Starts processes',
  'file-write': 'Writes/deletes files',
  'reads-env': 'Reads env vars',
  'credential-access': 'Touches credentials',
};

/** Capabilities that deserve attention get a stronger chip. */
export const SENSITIVE_CAPS = new Set<Capability>(['credential-access', 'network', 'file-write']);

const RTF = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function relativeTime(iso?: string): string {
  if (!iso) return '—';
  const days = Math.round((Date.parse(iso) - Date.now()) / 86_400_000);
  if (Math.abs(days) < 1) return 'today';
  if (Math.abs(days) < 45) return RTF.format(days, 'day');
  if (Math.abs(days) < 540) return RTF.format(Math.round(days / 30), 'month');
  return RTF.format(Math.round(days / 365), 'year');
}

export function daysSince(iso?: string): number {
  return iso ? Math.floor((Date.now() - Date.parse(iso)) / 86_400_000) : 0;
}

/** Most recent change across an asset's config files. */
export function lastChanged(a: Asset): string | undefined {
  return a.occurrences.map((o) => o.modifiedAt).filter(Boolean).sort().pop();
}

/** POST/DELETE to the local API. The custom header is what the server requires for mutations. */
export async function mutate(url: string, method: 'POST' | 'DELETE' = 'POST', body?: unknown): Promise<Inventory> {
  const res = await fetch(url, {
    method,
    headers: { 'X-AI-BOM': '1', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as { error?: string }).error ?? `HTTP ${res.status}`);
  return data as Inventory;
}

/** How AI tools are grouped in the overview map. */
export type ToolGroup = 'Desktop apps' | 'Editors' | 'Command line' | 'Shared config' | 'Online accounts' | 'Local models' | 'Browsers' | 'This computer';
export const TOOL_GROUP_ORDER: ToolGroup[] = ['Desktop apps', 'Editors', 'Command line', 'Shared config', 'Online accounts', 'Local models', 'Browsers', 'This computer'];

export function toolGroup(id: ClientId): ToolGroup {
  if (id.startsWith('cloud:')) return 'Online accounts';
  if (id === 'generic') return 'Shared config';
  if (['ollama', 'huggingface', 'gpt4all', 'jan', 'llama-cpp', 'vllm', 'localai', 'open-webui'].includes(id)) return 'Local models';
  if (['chrome', 'brave', 'edge', 'arc'].includes(id)) return 'Browsers';
  if (['shell', 'applications'].includes(id)) return 'This computer';
  if (['claude-desktop', 'lm-studio'].includes(id)) return 'Desktop apps';
  if (['claude-code', 'gemini-cli', 'codex', 'goose', 'opencode', 'amazon-q', 'copilot-cli', 'amp', 'factory-droid', 'qwen-code', 'augment', 'aider', 'crush', 'kilo-cli'].includes(id)) return 'Command line';
  return 'Editors';
}

const MONOGRAMS: Partial<Record<string, string>> = {
  'claude-desktop': 'Cl',
  'claude-code': 'CC',
  cursor: 'Cu',
  vscode: 'VS',
  windsurf: 'Ws',
  cline: 'Cn',
  'roo-code': 'Ro',
  'gemini-cli': 'Ge',
  codex: 'Cx',
  zed: 'Z',
  continue: 'Co',
  'lm-studio': 'LM',
  goose: 'Go',
  'amazon-q': 'Q',
  kiro: 'Ki',
  opencode: 'oc',
  'copilot-cli': 'GC',
  amp: 'Am',
  'factory-droid': 'Fd',
  'qwen-code': 'Qw',
  junie: 'Ju',
  augment: 'Au',
  trae: 'Tr',
  aider: 'Ai',
  crush: 'Cr',
  'kilo-code': 'Kc',
  'kilo-cli': 'Kl',
  antigravity: 'Ag',
  'llama-cpp': 'Ll',
  vllm: 'vL',
  localai: 'LA',
  'open-webui': 'OW',
  generic: 'A',
  ollama: 'Ol',
  huggingface: 'HF',
  gpt4all: 'G4',
  jan: 'Ja',
  shell: '$_',
  applications: 'Ap',
  chrome: 'Ch',
  brave: 'Br',
  edge: 'Ed',
  arc: 'Ar',
};

/** Two-letter badge for a tool (no logos: product marks aren't ours to ship). */
export function monogram(id: ClientId, name: string): string {
  if (MONOGRAMS[id]) return MONOGRAMS[id]!;
  const words = name.replace(/[^\p{L}\p{N} ]/gu, ' ').split(/\s+/).filter(Boolean);
  return words.length > 1 ? (words[0][0] + words[1][0]).toUpperCase() : (words[0] ?? '?').slice(0, 2);
}

/** A project .mcp.json server Claude Code hasn't been allowed to start yet. */
export const isPendingApproval = (a: Asset) => a.occurrences.some((o) => o.enabled === undefined && !!o.note?.startsWith('Not approved'));
/** Came from the user's Claude account rather than a local install. */
export const isSynced = (a: Asset) => a.occurrences.some((o) => !!o.note?.startsWith('Synced'));

/** Worst severity in a list, for badges. */
export function worst(list: (Severity | undefined)[]): Severity | undefined {
  return list.filter(Boolean).sort((a, b) => sevRank(a) - sevRank(b))[0];
}

export const FIX_LABEL: Record<import('../../src/types').FixKind, string> = {
  'pin-version': 'Pin a safe version',
  'remove-entry': 'Remove from config',
  'move-to-keychain': 'Move secret to Keychain',
  settings: 'Fix the setting',
  'remove-hook': 'Remove the hook',
  quarantine: 'Quarantine',
  'disable-plugin': 'Disable the plugin',
};

/** JSON POST that returns the parsed body (errors carry the server's message). */
export async function post<T>(url: string, body?: unknown, method: 'POST' | 'DELETE' = 'POST'): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: { 'X-AI-BOM': '1', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data as { error?: string }).error ?? `HTTP ${res.status}`);
  return data as T;
}

export const activeFindings = (inv: Inventory) => inv.findings.filter((f) => !f.muted);

/** Keyboard handler for a non-native control: Enter and Space both activate it. */
export const onActivate = (fn: () => void) => (e: { key: string; target: unknown; currentTarget: unknown; preventDefault: () => void }) => {
  if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
    e.preventDefault();
    fn();
  }
};

/** What to tell the reader when something failed: the reason, plus the next step. */
export const RETRY_HINT = 'Try again. If it keeps happening, run ai-bom doctor in a terminal.';
