/**
 * Core AI-BOM data model.
 *
 * An Inventory is made of Clients (AI apps/tools found on the machine),
 * Projects (directories carrying project-level AI config) and Assets
 * (the things those clients load: MCP servers, skills, plugins, hooks...).
 * The same asset configured in several places is merged into one Asset with
 * several Occurrences, which is what lets the dashboard draw a graph.
 */

export type AssetKind =
  | 'mcp-server'
  | 'skill'
  | 'plugin'
  | 'extension'
  | 'agent'
  | 'command'
  | 'hook'
  | 'instructions'
  | 'connector'
  /** Settings that export prompts/tool activity to an OpenTelemetry collector. */
  | 'telemetry'
  /** Local model weights (Ollama, LM Studio, Hugging Face cache…). */
  | 'model'
  /** AI provider API key found in a shell profile or .env file. */
  | 'api-key'
  /** Installed AI desktop app. */
  | 'app'
  /** AI browser extension. */
  | 'browser-extension';

export type Scope = 'user' | 'project' | 'local' | 'managed';

/** Where an asset's definition lives: on disk, or in an online account (cloud connectors you register). */
export type Origin = 'local' | 'cloud';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Transport = 'stdio' | 'http' | 'sse' | 'unknown';

export interface PackageRef {
  ecosystem: 'npm' | 'pypi' | 'docker' | 'local' | 'binary';
  name: string;
  /** Version or tag as written in the config, if any. */
  version?: string;
  /** True when the reference resolves to one immutable artifact (exact version or digest). */
  pinned: boolean;
  /** The runner that fetches the package (npx, uvx, docker...). */
  runner?: string;
  /** Versions found in local caches (npx, uv, pipx): what an unpinned call may actually run. */
  installedVersions?: string[];
  /** Latest release on the registry (online mode only): what an unpinned call fetches when not cached. */
  latestVersion?: string;
}

/** A tool an MCP server declares in its manifest (read statically; servers are never started). */
export interface DeclaredTool {
  name: string;
  description?: string;
  /** What the tool's code does, read statically from the server's source (see analysis/tools.ts). */
  behavior?: ToolBehavior;
}

/** Static read of one tool's handler code compared against its name and description. */
export interface ToolBehavior {
  /** Source file and line where the tool is registered (home paths shown as ~). */
  location?: string;
  capabilities: Capability[];
  /** Hosts the handler (or helpers it calls) sends requests to. */
  hosts: string[];
  /** Environment variables it reads. */
  envVars: string[];
  /** Credential stores it references (~/.ssh, ~/.aws/credentials…). */
  credentialPaths: string[];
  /** matches: behavior fits the description; mismatch: it does things the description doesn't mention. */
  verdict: 'matches' | 'mismatch' | 'unknown';
  /** Plain-language reasons for a mismatch. */
  reasons: string[];
}

export interface McpServerDetails {
  transport: Transport;
  command?: string;
  args?: string[];
  url?: string;
  /** Env var names; values are only kept as redacted placeholders. */
  env?: Record<string, string>;
  headers?: Record<string, string>;
  package?: PackageRef;
  /** Upstream URL when the server is a local proxy to a remote one (e.g. mcp-remote). */
  remoteUrl?: string;
  /** Tools declared in an extension manifest or found in the server's source code. */
  tools?: DeclaredTool[];
  /** Where the tool list came from. */
  toolsFrom?: 'manifest' | 'source' | 'manifest+source';
  /** Last sandboxed live inspection (ai-bom inspect). */
  live?: { at: string; sandbox: string; ok: boolean; error?: string; tools: number; liveOnly: string[]; changedDescriptions: string[]; networkAttempts: string[] };
  /** Env vars loaded from the OS keychain by the ai-bom-secrets launcher (moved there by `ai-bom fix`). */
  keychainEnv?: string[];
  /** Where the server's code was found on disk (npx/uv cache, extension or plugin folder). */
  sourceDir?: string;
}

export interface SkillDetails {
  description?: string;
  /** Tools the skill/agent/command pre-approves via frontmatter. */
  allowedTools?: string[];
  /** Files that make up the asset (relative to its root). */
  files?: string[];
  /** There were more files than were listed, so the rest were not inspected. */
  truncated?: boolean;
  version?: string;
  author?: string;
  /** What the content can do, inferred statically (see checks/capabilities.ts). */
  capabilities?: Capability[];
  /** External hosts referenced by the content. */
  domains?: string[];
}

export type Capability = 'runs-scripts' | 'network' | 'subprocess' | 'file-write' | 'reads-env' | 'credential-access';

export type ConnectorAccess = 'read' | 'read-write' | 'unknown';

/** A cloud connector the user registered (claude.ai, ChatGPT...); no local config exists for these. */
export interface ConnectorDetails {
  /** Id in the connectors registry (used to review/remove it); `detected:` ids were found on disk, not registered. */
  id: string;
  /** Where an automatically detected connector was found. */
  detectedIn?: string;
  platform: string;
  access: ConnectorAccess;
  notes?: string;
  addedAt: string;
  reviewedAt?: string;
}

export interface HookDetails {
  event: string;
  matcher?: string;
  command: string;
  /** Plain-language explanation of what the hook gets and does. */
  explanation?: HookExplanation;
}

export interface HookExplanation {
  /** When it runs, e.g. "Every time you submit a prompt". */
  trigger: string;
  /** What data it is handed, e.g. "The full text of your prompt". */
  receives: string;
  /** Script files the command runs (resolved on disk). */
  scripts: string[];
  /** Hosts it sends data to. */
  sendsTo: string[];
  capabilities: Capability[];
  /** One-sentence summary. */
  summary: string;
}

/** OpenTelemetry export configured for an AI tool. */
export interface TelemetryDetails {
  endpoint?: string;
  protocol?: string;
  /** Prompts you type are included in exported events. */
  logsPrompts: boolean;
  /** Tool names/parameters (file paths, commands) are included. */
  logsToolDetails: boolean;
  /** Custom auth headers are set (values redacted). */
  headersSet: boolean;
  signals: string[];
  /** Set by an admin-managed policy file. */
  managed?: boolean;
}

export interface ModelDetails {
  runtime: string;
  format?: string;
  sizeBytes?: number;
  /** Weights stored as Python pickle (.bin/.pt/.pkl/.ckpt): loading them can run code. */
  pickle?: boolean;
  files?: number;
}

export interface ApiKeyDetails {
  provider: string;
  variable: string;
  /** Masked value, e.g. "sk-p…<redacted:51 chars>". */
  masked: string;
  /** For .env files in a git project: whether git ignores the file. */
  gitignored?: boolean;
}

export interface AppDetails {
  version?: string;
  bundleId?: string;
}

export interface BrowserExtensionDetails {
  browser: string;
  extensionId: string;
  version?: string;
  permissions: string[];
  hostPermissions: string[];
  /** Can read and change every site you visit. */
  allSites: boolean;
}

/** Publisher and package-health signals (online mode, plus offline typosquat/rug-pull checks). */
export interface TrustInfo {
  /** Listed in the official MCP Registry (registry.modelcontextprotocol.io). */
  officialRegistry?: { name: string; url?: string };
  createdAt?: string;
  lastPublishAt?: string;
  maintainers?: number;
  repository?: string;
  license?: string;
  /** Build provenance (npm attestations / PyPI trusted publishing). */
  provenance?: boolean;
  installScripts?: string[];
  deprecated?: string;
  /** Similar-looking well-known package, when the name is a likely typosquat. */
  lookalikeOf?: string;
  /** Tool descriptions changed since the last scan. */
  toolsChanged?: string[];
  level: 'good' | 'mixed' | 'poor' | 'unknown';
  notes: string[];
}

/** What an asset can reach, for blast-radius display. */
export interface Reach {
  files: string[];
  network: string[];
  credentials: string[];
  commands: boolean;
  accounts: string[];
  /** Traits used for dangerous-combination analysis. */
  traits: ('private-data' | 'untrusted-input' | 'exfiltration' | 'shell')[];
  /** Least-privilege suggestions. */
  suggestions: string[];
}

export interface Occurrence {
  client: ClientId;
  scope: Scope;
  /** Absolute path of the config file or asset directory. */
  source: string;
  /** Name the asset was given in that config. */
  name: string;
  project?: string;
  /** Asset id of the plugin/extension that bundled this asset. */
  via?: string;
  enabled?: boolean;
  /** Human-readable status detail, e.g. "not approved yet". */
  note?: string;
  /** Last modification time of the source file (ISO); old dates reveal forgotten config. */
  modifiedAt?: string;
  /** Location of the entry inside a JSON config file, for safe automated fixes. */
  jsonPath?: (string | number)[];
  /** MCP only: env/headers/url as written in this particular config (redacted in output). */
  env?: Record<string, string>;
  headers?: Record<string, string>;
  url?: string;
}

export interface Asset {
  id: string;
  kind: AssetKind;
  name: string;
  origin: Origin;
  occurrences: Occurrence[];
  mcp?: McpServerDetails;
  skill?: SkillDetails;
  hook?: HookDetails;
  connector?: ConnectorDetails;
  telemetry?: TelemetryDetails;
  model?: ModelDetails;
  apiKey?: ApiKeyDetails;
  app?: AppDetails;
  browserExtension?: BrowserExtensionDetails;
  trust?: TrustInfo;
  reach?: Reach;
  /** MCP servers: the dependencies installed with it. */
  deps?: {
    ecosystem: 'npm' | 'pypi';
    scope: 'installed' | 'direct';
    total: number;
    vulnerable: { name: string; version: string; id: string; severity: Severity; summary: string }[];
    licenses: Record<string, number>;
    licenseNotes: string[];
  };
  /** Root dir or file of the asset on disk (skills, plugins, instructions). */
  path?: string;
  /** Ids of assets this one bundles (plugin -> skills, mcp servers...). */
  children?: string[];
  /** Highest severity across this asset's findings. */
  risk?: Severity;
  /** True if the asset was not present in the previous saved scan. */
  isNew?: boolean;
  /** How often it was used: Claude Code's own counters and/or its session logs. */
  usage?: Usage;
  /** Reversible actions `ai-bom fix` can take on the asset itself (remove, quarantine, disable). */
  fixes?: FixKind[];
}

export interface Usage {
  count: number;
  lastUsedAt?: string;
  /** Per-tool call counts (MCP servers, from session logs). */
  tools?: Record<string, number>;
  /** Projects it was used in. */
  projects?: string[];
  source: 'counters' | 'session-logs';
}

export type ClientId =
  | 'claude-desktop'
  | 'claude-code'
  | 'cursor'
  | 'vscode'
  | 'windsurf'
  | 'cline'
  | 'roo-code'
  | 'gemini-cli'
  | 'codex'
  | 'zed'
  | 'continue'
  | 'lm-studio'
  | 'goose'
  | 'amazon-q'
  | 'kiro'
  | 'opencode'
  | 'copilot-cli'
  | 'amp'
  | 'factory-droid'
  | 'qwen-code'
  | 'junie'
  | 'augment'
  | 'trae'
  | 'aider'
  | 'crush'
  | 'kilo-code'
  | 'kilo-cli'
  | 'antigravity'
  | 'generic'
  /** Local model runtimes. */
  | 'ollama'
  | 'huggingface'
  | 'gpt4all'
  | 'jan'
  | 'llama-cpp'
  | 'vllm'
  | 'localai'
  | 'open-webui'
  /** Shell profiles and .env files (API keys). */
  | 'shell'
  /** Installed applications. */
  | 'applications'
  | 'chrome'
  | 'brave'
  | 'edge'
  | 'arc'
  /** A cloud platform holding registered connectors, e.g. `cloud:claude.ai`. */
  | `cloud:${string}`;

export interface Client {
  id: ClientId;
  name: string;
  /** Config files that were found for this client. */
  configFiles: string[];
}

export interface Project {
  path: string;
  name: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  assetId?: string;
  /** File where the issue was found. */
  location?: string;
  /** Short, already-redacted excerpt. */
  evidence?: string;
  owasp?: string[];
  /** MITRE ATLAS techniques, e.g. "AML.T0110 AI Agent Tool Poisoning". */
  atlas?: string[];
  /** Advisory reference URLs for known-vulnerability findings. */
  references?: string[];
  /** Primary advisory id (CVE / GHSA / MAL) for known-vulnerability findings. */
  advisory?: string;
  /** Other assets involved (dangerous combinations). */
  related?: string[];
  /** Triage decision, when the user accepted, snoozed or dismissed this finding. */
  muted?: TriageDecision;
  /** Fix kinds `ai-bom fix` can apply to this finding. */
  fixes?: FixKind[];
  /** Known-vulnerability details, for display. */
  vuln?: {
    cvss?: { score: number; version?: string; vector?: string };
    /** How the affected version was determined for this call. */
    versionSource: 'pinned' | 'installed' | 'latest' | 'unknown';
    version: string;
    fixedVersion?: string;
    /** The same call, rewritten to a safe version. Redacted like all output. */
    fixCommand?: string;
    confidence: 'confirmed' | 'possible';
    sources: string[];
    cwe?: string[];
  };
}

/** Tokens your setup adds to every conversation in one agent (a client, plus a project's own config). */
export interface ContextCost {
  client: ClientId;
  project?: string;
  total: number;
  items: { assetId: string; name: string; kind: AssetKind; tokens: number; estimated?: boolean; unused?: boolean }[];
  suggestions: string[];
}

export type TriageStatus = 'accepted' | 'snoozed' | 'false-positive';

export interface TriageDecision {
  status: TriageStatus;
  reason?: string;
  /** Snoozed until (ISO); the finding comes back after this date. */
  until?: string;
  at: string;
}

export type FixKind = 'pin-version' | 'remove-entry' | 'move-to-keychain' | 'settings' | 'remove-hook' | 'quarantine' | 'disable-plugin';

export interface ScanError {
  file: string;
  message: string;
}

export interface Inventory {
  schemaVersion: 1;
  tool: { name: string; version: string };
  scannedAt: string;
  host: { platform: string; hostname: string; user: string };
  clients: Client[];
  projects: Project[];
  assets: Asset[];
  findings: Finding[];
  errors: ScanError[];
  /** Ids of assets present in the previous saved scan but missing now. */
  removed?: { id: string; kind: AssetKind; name: string }[];
  /** Every location checked, with key names or counts only (`ai-bom doctor`). */
  trace?: { path: string; status: 'found' | 'missing' | 'error'; note?: string }[];
  /** Result of the optional online vulnerability lookup. */
  vulnCheck?: { checkedAt: string; packages: number; sources: string[]; errors: string[] };
  /** Session-log analysis summary (Claude Code). */
  sessions?: { files: number; toolCalls: number; mcpCalls: number; audited: number; since?: string; agents?: Partial<Record<'claude-code' | 'codex' | 'gemini-cli' | 'claude-desktop' | 'copilot-cli' | 'cline', number>> };
  /** Counts of muted findings by status. */
  triage?: { accepted: number; snoozed: number; falsePositive: number; expired: number };
  /** Estimated context each agent loads before you type anything. */
  context?: ContextCost[];
  /** 0-100 security score (active findings only) with the most useful next steps. */
  score?: { value: number; grade: 'A' | 'B' | 'C' | 'D' | 'F'; penalty: number; next: { findingId: string; title: string; fix?: string; gain: number }[] };
  /** Signed advisory feed in use. */
  feed?: { generatedAt: string; advisories: number; verified: boolean };
  /** What this scan did not look at, so a clean result is not mistaken for a complete one. */
  coverage?: { gaps: { what: string; why: string }[] };
}
