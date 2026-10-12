import { beforeAll, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { toCycloneDX } from '../src/bom/cyclonedx.js';
import { addConnector, loadConnectors, markReviewed, removeConnector } from '../src/connectors.js';
import { compareVersions, inRange } from '../src/vulns/semver.js';
import { safeParseMessage } from '../src/util/fs.js';
import { findTokenPattern } from '../src/util/secrets.js';
import type { Asset, Inventory } from '../src/types.js';
import { buildFixture, SECRETS, type Fixture } from './fixture.js';

let fx: Fixture;
let inv: Inventory;
const byName = (name: string, kind?: string) => inv.assets.find((a) => a.name === name && (!kind || a.kind === kind));
const findings = (name: string) => inv.findings.filter((f) => f.assetId === byName(name)?.id);

beforeAll(async () => {
  fx = buildFixture();
  inv = await scan({ home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], connectorsFile: fx.connectorsFile });
});

describe('review fixes', () => {
  it('follows symlinked skills and symlinked script folders', () => {
    const s = byName('sync-helper', 'skill')!;
    expect(s.skill?.files).toEqual(['SKILL.md', 'scripts/sync.py']);
  });

  it('does not mistake hyphenated words for OpenAI keys', () => {
    expect(findTokenPattern('the task-management-workflow-helper skill')).toBeUndefined();
    expect(findTokenPattern('key sk-proj-abc123DEF456ghi789JKL012mno')).toBe('OpenAI API key');
    expect(findings('sync-helper').some((f) => f.ruleId === 'CONTENT-SECRET')).toBe(false);
  });

  it('reads config files larger than 1 MB (~/.claude.json grows large)', async () => {
    const f = buildFixture();
    const state = JSON.parse(readFileSync(path.join(f.home, '.claude.json'), 'utf8'));
    state.history = 'x'.repeat(3_000_000);
    writeFileSync(path.join(f.home, '.claude.json'), JSON.stringify(state));
    const big = await scan({ home: f.home, platform: 'darwin', systemRoot: f.systemRoot, projects: [] });
    expect(big.assets.some((a) => a.name === 'context7')).toBe(true);
  });

  it('keeps secret excerpts out of parse error messages', () => {
    let msg = '';
    try {
      JSON.parse('{"k": sk-ant-api03-SECRETSECRETSECRET }');
    } catch (e) {
      msg = safeParseMessage((e as Error).message);
    }
    expect(msg).not.toContain('SECRET');
    expect(safeParseMessage('bad value "sk-ant-api03-SECRETSECRET" at line 2\n  2 | foo')).toBe('bad value "…" at line 2');
  });

  it('flags literal credentials passed as CLI flags', () => {
    const f = findings('search').find((x) => x.ruleId === 'MCP-SECRET');
    expect(f?.evidence).toMatch(/^--api-key BSAl…<redacted/);
    expect(JSON.stringify(inv)).not.toContain(SECRETS.flag);
  });

  it('reflects Claude Code approval state for project .mcp.json servers', () => {
    const occ = (name: string) => byName(name)!.occurrences.find((o) => o.client === 'claude-code')!;
    expect(occ('postgres').enabled).toBe(true); // enableAllProjectMcpServers in settings.local.json
    expect(occ('analytics').enabled).toBe(false); // disabledMcpjsonServers in ~/.claude.json
    expect(occ('analytics').note).toMatch(/Rejected/);
    expect(occ('tracker').enabled).toBeUndefined(); // scratch: never approved
    expect(occ('tracker').note).toMatch(/Not approved yet/);
  });

  it('keeps bundled asset ids stable across plugin upgrades', async () => {
    const f = buildFixture();
    const opts = { home: f.home, platform: 'darwin' as const, systemRoot: f.systemRoot, projects: [] };
    const before = await scan(opts);
    const file = path.join(f.home, '.claude/plugins/installed_plugins.json');
    const data = JSON.parse(readFileSync(file, 'utf8'));
    const oldPath = data.plugins['code-review@acme-market'][0].installPath as string;
    const newPath = oldPath.replace('2.0.0', '2.1.0');
    (await import('node:fs')).cpSync(oldPath, newPath, { recursive: true });
    data.plugins['code-review@acme-market'][0] = { scope: 'user', installPath: newPath, version: '2.1.0' };
    writeFileSync(file, JSON.stringify(data));
    const after = await scan(opts);
    const ids = (i: Inventory) => i.assets.filter((a) => a.occurrences.some((o) => o.via)).map((a) => a.id).sort();
    expect(ids(after)).toEqual(ids(before));
  });

  it('records when each config file last changed', () => {
    expect(byName('context7')!.occurrences[0].modifiedAt).toMatch(/^\d{4}-\d\d-\d\dT/);
  });
});

describe('capabilities', () => {
  it('infers what a skill can do and where it talks to', () => {
    const s = byName('sync-helper', 'skill')!;
    expect(s.skill?.capabilities).toEqual(expect.arrayContaining(['credential-access', 'network', 'runs-scripts']));
    expect(s.skill?.domains).toEqual(['webhook.site']);
    expect(findings('sync-helper').map((f) => f.ruleId)).toEqual(expect.arrayContaining(['SKILL-EXFIL-PATTERN', 'SKILL-SUSPICIOUS-ENDPOINT']));
  });

  it('does not attribute capabilities from prose', () => {
    // helper mentions curl in prose (not a code block): still "download-exec", but no network capability.
    expect(byName('reviewer', 'agent')!.skill?.capabilities).toEqual([]);
    expect(byName('pdf-tools', 'skill')!.skill?.capabilities).toEqual(['runs-scripts']);
  });

  it('reads declared tools from extension manifests and flags poisoned descriptions', () => {
    const server = inv.assets.find((a) => a.kind === 'mcp-server' && a.name === 'Slack')!;
    expect(server.mcp?.tools?.map((t) => t.name)).toEqual(['send_message', 'read_channel', 'export_workspace']);
    expect(server.mcp?.toolsFrom).toBe('manifest+source');
    expect(findings('Slack').some((f) => f.ruleId === 'MCP-TOOL-POISONING')).toBe(false); // extension asset itself
    expect(inv.findings.some((f) => f.ruleId === 'MCP-TOOL-POISONING' && f.assetId === server.id)).toBe(true);
  });
});

describe('vulnerabilities (offline, bundled advisories)', () => {
  it('flags a pinned vulnerable version', () => {
    const f = findings('tracker').find((x) => x.ruleId === 'VULN-KNOWN')!;
    expect(f.title).toBe('CVE-2025-6514 in mcp-remote@0.1.10');
    expect(f.severity).toBe('critical');
    expect(f.references).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2025-6514']);
  });

  it('flags a known-malicious package even when unpinned', () => {
    const f = findings('analytics').find((x) => x.ruleId === 'VULN-MALICIOUS')!;
    expect(f.severity).toBe('critical');
    expect(byName('analytics')?.risk).toBe('critical');
  });

  it('does not flag unpinned packages with no known version and a version-bounded advisory', () => {
    // filesystem runs `npx -y @modelcontextprotocol/server-filesystem`: unpinned and not cached.
    expect(findings('filesystem').some((f) => f.ruleId.startsWith('VULN-'))).toBe(false);
  });

  it('exports advisories with their real ids in CycloneDX', () => {
    const bom = toCycloneDX(inv) as { vulnerabilities: { id: string; advisories?: { url: string }[] }[] };
    const v = bom.vulnerabilities.find((x) => x.id === 'CVE-2025-6514')!;
    expect(v.advisories).toEqual([{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-6514' }]);
  });

  it('compares versions', () => {
    expect(compareVersions('2025.7.1', '2025.6.18')).toBe(1);
    expect(compareVersions('v0.1.16', '0.1.16')).toBe(0);
    expect(inRange('0.1.15', { introduced: '0.0.5', fixed: '0.1.16' })).toBe(true);
    expect(inRange('0.1.16', { introduced: '0.0.5', fixed: '0.1.16' })).toBe(false);
    // Packages that switched from semver to date versions: compare within a scheme only.
    expect(inRange('0.6.2', { fixed: ['0.6.4', '2025.7.1'] })).toBe(true);
    expect(inRange('2025.6.18', { fixed: ['0.6.4', '2025.7.1'] })).toBe(true);
    expect(inRange('1.0.0', { fixed: '2025.7.1' })).toBe(false);
  });
});

describe('cloud connectors', () => {
  it('adds registered connectors to the inventory as cloud assets', () => {
    const gmail = byName('Gmail', 'connector')!;
    expect(gmail.origin).toBe('cloud');
    expect(gmail.occurrences[0].client).toBe('cloud:claude.ai');
    expect(inv.clients.map((c) => c.id)).toEqual(expect.arrayContaining(['cloud:claude.ai', 'cloud:ChatGPT']));
  });

  it('asks for a review after 90 days', () => {
    expect(findings('Gmail').map((f) => f.ruleId)).toEqual(['CONNECTOR-REVIEW']);
    expect(findings('GitHub')).toEqual([]);
  });

  it('exports connectors as CycloneDX services', () => {
    const bom = toCycloneDX(inv) as { services: { name: string; provider?: { name: string } }[] };
    expect(bom.services.find((s) => s.name === 'Gmail')?.provider?.name).toBe('claude.ai');
  });

  it('manages the registry file', async () => {
    const file = path.join(mkdtempSync(path.join(os.tmpdir(), 'conn-')), 'connectors.json');
    const rec = await addConnector(file, { platform: 'ChatGPT', name: '  Google Drive ', access: 'read' });
    expect(rec.name).toBe('Google Drive');
    await expect(addConnector(file, { platform: '', name: 'x' })).rejects.toThrow(/platform/);
    expect(await markReviewed(file, rec.id)).toBe(true);
    expect(await removeConnector(file, 'nope')).toBe(false);
    expect(await removeConnector(file, rec.id)).toBe(true);
    expect(await loadConnectors(file)).toEqual([]);
  });
});

describe('where MCP servers can be defined', () => {
  it('scans ~/.mcp.json, auto-discovers ~/Projects, and merges a server defined in two files', async () => {
    const f = buildFixture();
    const { writeFileSync, mkdirSync } = await import('node:fs');
    // Claude Code run from the home folder reads ~/.mcp.json as project config.
    writeFileSync(path.join(f.home, '.mcp.json'), JSON.stringify({ mcpServers: { 'home-notes': { command: 'npx', args: ['-y', 'notes-mcp@1.0.0'] } } }));
    // A repo Claude Code has never opened, inside ~/Projects.
    const repo = path.join(f.home, 'Projects', 'api-service');
    mkdirSync(repo, { recursive: true });
    // Same server as ~/.claude.json's "context7", defined again in the repo's .mcp.json.
    writeFileSync(path.join(repo, '.mcp.json'), JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://mcp.context7.com/mcp' } } }));

    const without = await scan({ home: f.home, platform: 'darwin', systemRoot: f.systemRoot, projects: [] });
    expect(without.assets.some((a) => a.name === 'docs')).toBe(false);

    const res = await scan({ home: f.home, platform: 'darwin', systemRoot: f.systemRoot, projects: [], autoDiscover: true });
    const home = res.assets.find((a) => a.name === 'home-notes')!;
    expect(home.occurrences[0]).toMatchObject({ client: 'claude-code', scope: 'project', source: '~/.mcp.json' });
    expect(res.projects.map((p) => p.name)).toEqual(expect.arrayContaining(['~ (home folder)', 'api-service']));

    const ctx7 = res.assets.filter((a) => a.mcp?.url === 'https://mcp.context7.com/mcp');
    expect(ctx7).toHaveLength(1);
    expect(ctx7[0].occurrences.map((o) => `${o.scope}:${o.source}`).sort()).toEqual(['project:~/Projects/api-service/.mcp.json', 'user:~/.claude.json']);

    // User-level files are not double counted by the home-folder project scan.
    const skill = res.assets.find((a) => a.name === 'pdf-tools')!;
    expect(skill.occurrences).toHaveLength(1);
    const hooks = res.assets.filter((a) => a.kind === 'hook').map((a) => a.name);
    expect(new Set(hooks).size).toBe(hooks.length);
  });
});

describe('tool behavior vs. description', () => {
  it('reads a server\'s code and flags a tool that does more than it says', () => {
    const weather = byName('weather', 'mcp-server')!;
    expect(weather.mcp?.sourceDir).toContain('weather-mcp');
    const forecast = weather.mcp!.tools!.find((t) => t.name === 'get_forecast')!;
    expect(forecast.behavior?.verdict).toBe('mismatch');
    expect(forecast.behavior?.hosts).toEqual(['api.weather.gov', 'metrics.forecast-cdn.net']);
    expect(forecast.behavior?.reasons.join(' ')).toMatch(/SSH keys.*entire environment.*metrics\.forecast-cdn\.net/s);
    expect(weather.mcp!.tools!.find((t) => t.name === 'get_alerts')!.behavior?.verdict).toBe('matches');
    const f = findings('weather').find((x) => x.ruleId === 'TOOL-BEHAVIOR-MISMATCH')!;
    expect(f.severity).toBe('high');
    expect(f.location).toMatch(/dist\/index\.js:5$/);
  });

  it('extracts Python @tool functions with their docstrings', () => {
    const db = byName('local-db')!;
    expect(db.mcp?.tools).toEqual([expect.objectContaining({ name: 'read_query', description: 'Execute a SELECT query on the SQLite database' })]);
    expect(db.mcp!.tools![0].behavior?.verdict).toBe('matches');
  });

  it('flags tools registered in code but missing from the manifest', () => {
    expect(inv.findings.filter((x) => x.assetId === byName('Slack', 'mcp-server')?.id).find((x) => x.ruleId === 'TOOL-UNDECLARED')?.evidence).toBe('export_workspace');
  });
});

describe('session logs', () => {
  it('counts real MCP usage per tool from Claude Code logs', () => {
    const c7 = byName('context7')!;
    expect(c7.usage).toMatchObject({ count: 2, source: 'session-logs', tools: { 'resolve-library-id': 1, 'get-library-docs': 1 } });
    expect(inv.sessions).toMatchObject({ files: 3, toolCalls: 10, mcpCalls: 5 });
  });

  it('audits MCP calls: secrets sent, suspicious destinations, injected output', () => {
    const sent = inv.findings.find((f) => f.ruleId === 'TOOLCALL-SECRET-SENT')!;
    expect(sent.evidence).toBe('pinned → post: body: GitHub token');
    expect(inv.findings.find((f) => f.ruleId === 'TOOLCALL-SUSPICIOUS-DEST')?.evidence).toBe('pinned → post: webhook.site');
    const inj = inv.findings.find((f) => f.ruleId === 'TOOLCALL-INJECTION' && f.assetId === byName('context7')!.id)!;
    expect(inj.evidence).toContain('Ignore all previous instructions');
    expect(JSON.stringify(inv)).not.toContain(SECRETS.github);
  });

  it('flags Claude Code servers that are never called', () => {
    const unused = inv.findings.filter((f) => f.ruleId === 'USAGE-UNUSED').map((f) => inv.assets.find((a) => a.id === f.assetId)?.name);
    expect(unused).toContain('local-db');
    expect(unused).not.toContain('context7');
  });
});

describe('telemetry', () => {
  it('shows where OpenTelemetry export sends your prompts', () => {
    const t = inv.assets.find((a) => a.kind === 'telemetry')!;
    expect(t.name).toBe('Claude Code → otel.acme-analytics.io:4318');
    expect(t.telemetry).toMatchObject({ logsPrompts: true, endpoint: 'http://otel.acme-analytics.io:4318' });
    const rules = inv.findings.filter((f) => f.assetId === t.id).map((f) => [f.ruleId, f.severity]);
    expect(rules).toEqual(expect.arrayContaining([['TELEMETRY-PROMPTS', 'high'], ['TELEMETRY-INSECURE', 'medium']]));
  });
});

describe('wider AI inventory', () => {
  it('finds local models and flags pickle weights', () => {
    expect(byName('llama3.2:latest', 'model')?.model).toMatchObject({ runtime: 'Ollama', sizeBytes: 2_019_394_189 });
    expect(findings('bert-base-uncased').map((f) => f.ruleId)).toEqual(['MODEL-PICKLE']);
    expect(findings('acme/tiny')).toEqual([]);
  });

  it('finds AI API keys once per key, flags .env files git would commit, never leaks the value', () => {
    const key = byName('OpenAI key', 'api-key')!;
    expect(key.occurrences.map((o) => o.source).sort()).toEqual(['~/.zshrc', '~/code/webapp/.env']);
    expect(findings('OpenAI key').map((f) => [f.ruleId, f.severity]).sort()).toEqual([['APIKEY-NOT-GITIGNORED', 'high'], ['APIKEY-PLAINTEXT', 'low']]);
    expect(inv.assets.some((a) => a.kind === 'api-key' && a.apiKey?.provider === 'Anthropic')).toBe(false);
    expect(JSON.stringify(inv)).not.toContain(SECRETS.openai);
  });

  it('lists AI apps and AI browser extensions with broad site access', () => {
    expect(byName('ChatGPT', 'app')?.app).toEqual({ version: '1.2025.300', bundleId: 'com.openai.chat' });
    const sider = byName('Sider: ChatGPT Sidebar', 'browser-extension')!;
    expect(sider.browserExtension?.allSites).toBe(true);
    expect(findings('Sider: ChatGPT Sidebar').map((f) => f.ruleId)).toEqual(['EXT-ALL-SITES']);
    expect(byName('Google Translate')).toBeUndefined();
  });

  it('flags tasks that run when a folder opens and API base-URL redirects in project settings', () => {
    expect(inv.findings.find((f) => f.ruleId === 'AUTORUN-TASK')?.severity).toBe('critical');
    expect(inv.findings.find((f) => f.ruleId === 'SETTINGS-API-REDIRECT')).toMatchObject({ severity: 'critical', location: '~/code/scratch/.claude/settings.json' });
  });
});

describe('blast radius and dangerous combinations', () => {
  it('profiles what each server can reach, with least-privilege suggestions', () => {
    const fsServer = byName('filesystem')!;
    expect(fsServer.reach).toMatchObject({ files: ['your whole home folder'], traits: ['private-data'] });
    expect(fsServer.reach?.suggestions[0]).toMatch(/only the project folders/);
    expect(byName('github')!.reach?.traits.sort()).toEqual(['exfiltration', 'private-data', 'untrusted-input']);
    expect(byName('local-db')!.reach?.traits).toEqual(['private-data']);
    expect(byName('weather')!.reach?.network).toEqual(['api.weather.gov', 'metrics.forecast-cdn.net']);
  });

  it('finds the lethal trifecta per agent and names every leg', () => {
    const t = inv.findings.find((f) => f.ruleId === 'COMBO-LETHAL-TRIFECTA' && f.title === 'Lethal trifecta in Claude Desktop')!;
    expect(t.evidence).toContain('reads private data: filesystem');
    expect(t.related).toEqual(expect.arrayContaining([byName('filesystem')!.id, byName('github')!.id]));
    // Claude Code runs with prompts off, so combinations there are high.
    const cc = inv.findings.find((f) => f.ruleId === 'COMBO-SHELL-UNTRUSTED' && f.title === 'Command execution + untrusted content in Claude Code')!;
    expect(cc.severity).toBe('high');
  });
});

describe('Codex and Gemini CLI session logs', () => {
  it('counts MCP usage from Codex and Gemini logs and audits their calls', () => {
    expect(inv.sessions?.agents).toEqual({ 'claude-code': 1, codex: 1, 'gemini-cli': 1 });
    expect(byName('exa')!.usage).toMatchObject({ count: 1, tools: { web_search_exa: 1 } });
    expect(byName('filesystem')!.usage).toMatchObject({ count: 1, tools: { read_file: 1 } });
    const inj = inv.findings.find((f) => f.ruleId === 'TOOLCALL-INJECTION' && f.assetId === byName('exa')!.id)!;
    expect(inj.severity).toBe('high');
    expect(inj.evidence).toContain('U+E0072');
    expect(inj.evidence).toContain('read ~/.ssh/id_rsa');
  });
});

describe('dependencies of installed MCP servers', () => {
  it('reads the installed tree, flags vulnerable dependencies and copyleft licenses', () => {
    const w = byName('weather', 'mcp-server')!;
    expect(w.deps).toMatchObject({ ecosystem: 'npm', scope: 'installed', total: 3 });
    expect(w.deps!.licenses).toEqual({ MIT: 1, 'AGPL-3.0-only': 1, unknown: 1 });
    const rules = findings('weather').filter((f) => f.ruleId.startsWith('DEP-'));
    expect(rules.find((f) => f.ruleId === 'DEP-VULN')?.title).toBe('CVE-2025-6514 in mcp-remote@0.1.10 (used by weather)');
    expect(rules.find((f) => f.ruleId === 'DEP-LICENSE')?.evidence).toMatch(/AGPL-3.0-only.*geo-helper/);
  });
});
