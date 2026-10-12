import { beforeAll, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { toCycloneDX } from '../src/bom/cyclonedx.js';
import type { Inventory } from '../src/types.js';
import { buildFixture, SECRETS } from './fixture.js';

let inv: Inventory;
let fx: ReturnType<typeof buildFixture>;

beforeAll(async () => {
  fx = buildFixture();
  inv = await scan({ home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], connectorsFile: fx.connectorsFile });
});

const byName = (name: string, kind?: string) => inv.assets.find((a) => a.name === name && (!kind || a.kind === kind));
/** Config-level findings (session-log findings are tested in features.test.ts). */
const rules = (assetName?: string) =>
  inv.findings.filter((f) => (!assetName || f.assetId === byName(assetName)?.id) && !/^(TOOLCALL|USAGE)-/.test(f.ruleId)).map((f) => f.ruleId);

describe('discovery', () => {
  it('detects clients', () => {
    const ids = inv.clients.map((c) => c.id);
    for (const id of ['claude-desktop', 'claude-code', 'cursor', 'codex', 'gemini-cli', 'windsurf', 'zed', 'vscode', 'cline', 'lm-studio', 'generic']) {
      expect(ids).toContain(id);
    }
  });

  it('merges the same MCP server configured in several clients', () => {
    const gh = inv.assets.filter((a) => a.mcp?.package?.name === '@modelcontextprotocol/server-github');
    expect(gh).toHaveLength(1);
    expect(gh[0].occurrences.map((o) => o.client).sort()).toEqual(['claude-desktop', 'cursor', 'gemini-cli']);

    const fs = inv.assets.filter((a) => a.mcp?.package?.name === '@modelcontextprotocol/server-filesystem');
    expect(fs).toHaveLength(1);
    expect(fs[0].occurrences.map((o) => o.client).sort()).toEqual(['claude-desktop', 'gemini-cli']);

    const pg = inv.assets.filter((a) => a.mcp?.package?.name === '@modelcontextprotocol/server-postgres');
    expect(pg).toHaveLength(1);
    expect(pg[0].occurrences.every((o) => o.scope === 'project')).toBe(true);
  });

  it('parses every client config shape', () => {
    expect(byName('context7')?.mcp?.transport).toBe('http');
    expect(byName('exa')?.mcp?.package).toMatchObject({ ecosystem: 'npm', name: 'exa-mcp-server', version: 'latest', pinned: false });
    expect(byName('fetch')?.mcp?.package).toMatchObject({ ecosystem: 'pypi', name: 'mcp-server-fetch', pinned: true });
    expect(byName('zed-shell')?.mcp?.command).toBe('bash');
    expect(byName('playwright')?.occurrences[0].client).toBe('vscode');
    expect(byName('linear-remote')?.mcp?.remoteUrl).toBe('https://mcp.linear.app/sse');
    expect(byName('sandbox')?.mcp?.package).toMatchObject({ ecosystem: 'docker', name: 'ghcr.io/acme/mcp-sandbox', version: 'latest' });
    expect(byName('local-db')?.occurrences[0]).toMatchObject({ scope: 'local', client: 'claude-code' });
  });

  it('finds skills, agents, commands, hooks and instructions', () => {
    expect(byName('pdf-tools', 'skill')?.skill?.files).toEqual(['SKILL.md', 'scripts/extract.py']);
    expect(byName('pdf-tools', 'skill')?.skill?.allowedTools).toEqual(['Read', 'Bash(python:*)']);
    expect(byName('reviewer', 'agent')).toBeDefined();
    expect(byName('deploy', 'command')).toBeDefined();
    expect(byName('migrations', 'skill')?.occurrences[0].scope).toBe('project');
    expect(inv.assets.filter((a) => a.kind === 'hook').map((a) => a.name).sort()).toEqual(['PostToolUse [Edit|Write]', 'SessionStart', 'UserPromptSubmit', 'folderOpen [bootstrap]', 'statusLine']);
    const instr = inv.assets.filter((a) => a.kind === 'instructions').map((a) => a.name);
    expect(instr).toEqual(expect.arrayContaining(['webapp/AGENTS.md', 'webapp/CLAUDE.md', 'webapp/.cursor/rules/style.mdc']));
  });

  it('links plugin and extension children', () => {
    const plugin = byName('code-review@acme-market', 'plugin')!;
    expect(plugin.occurrences[0].enabled).toBe(true);
    const children = plugin.children!.map((id) => inv.assets.find((a) => a.id === id)!);
    expect(children.map((c) => c.kind).sort()).toEqual(['command', 'hook', 'mcp-server', 'skill']);

    const ext = byName('Slack', 'extension')!;
    expect(ext.children).toHaveLength(1);
    const server = inv.assets.find((a) => a.id === ext.children![0])!;
    expect(server.mcp?.args?.[0]).toBe('~/Library/Application Support/Claude/Claude Extensions/ant.dir.slack/server/index.js');
  });

  it('records parse errors without failing the scan', () => {
    expect(inv.errors.some((e) => e.file.endsWith('.lmstudio/mcp.json'))).toBe(true);
  });

  it('only lists projects that have assets', () => {
    expect(inv.projects.map((p) => p.name)).toEqual(['scratch', 'webapp']);
  });
});

describe('checks', () => {
  it('flags MCP misconfigurations', () => {
    expect(rules('github')).toContain('MCP-SECRET');
    expect(rules('github')).toContain('MCP-UNPINNED');
    // A secret in any merged occurrence is reported against its own file.
    const secretFiles = inv.findings.filter((f) => f.ruleId === 'MCP-SECRET' && f.assetId === byName('github')?.id).map((f) => f.location);
    expect(secretFiles.sort()).toEqual(['~/.gemini/settings.json', '~/Library/Application Support/Claude/claude_desktop_config.json']);
    expect(rules('exa')).toEqual(expect.arrayContaining(['MCP-SECRET', 'MCP-UNPINNED']));
    expect(rules('internal-api')).toEqual(expect.arrayContaining(['MCP-INSECURE-TRANSPORT', 'MCP-SECRET']));
    expect(rules('sandbox')).toContain('MCP-CONTAINER-PRIVILEGED');
    expect(rules('filesystem')).toContain('MCP-BROAD-FS');
    expect(rules('zed-shell')).toContain('MCP-SHELL-COMMAND');
    expect(rules('pinned')).toEqual([]);
    expect(rules('fetch')).toEqual([]);
    expect(rules('context7')).toEqual([]);
  });

  it('flags permission and settings issues', () => {
    const all = inv.findings;
    expect(all.find((f) => f.ruleId === 'PERM-BYPASS')?.severity).toBe('high');
    expect(all.find((f) => f.ruleId === 'PERM-BROAD-ALLOW' && f.evidence === 'Bash(*)')?.severity).toBe('high');
    expect(all.find((f) => f.ruleId === 'PERM-BROAD-ALLOW' && f.evidence === 'Bash(curl:*)')?.severity).toBe('medium');
    expect(all.some((f) => f.ruleId === 'PERM-AUTO-PROJECT-MCP')).toBe(true);
    expect(all.filter((f) => f.ruleId === 'SETTINGS-SECRET').map((f) => f.location)).toEqual(
      expect.arrayContaining(['~/.claude/settings.json', '~/Library/Application Support/Claude/Claude Extensions Settings/ant.dir.slack.json']),
    );
  });

  it('flags hooks', () => {
    const egress = inv.findings.filter((f) => f.ruleId === 'HOOK-DATA-EGRESS');
    expect(egress.map((f) => f.title).sort()).toEqual(['SessionStart hook sends session data to t.plugin-stats.dev', 'UserPromptSubmit hook sends your prompts to collector.example.com']);
    expect(inv.findings.filter((f) => f.ruleId === 'HOOK-EXEC')).toHaveLength(2);
    const prompt = byName('UserPromptSubmit')!;
    expect(prompt.hook?.explanation).toMatchObject({ trigger: 'Every time you submit a prompt', sendsTo: ['collector.example.com'] });
    const start = byName('SessionStart')!;
    expect(start.hook?.explanation?.scripts[0]).toMatch(/hooks\/start\.sh$/);
    expect(byName('statusLine')!.hook?.explanation?.summary).toMatch(/^Every time the status line refreshes, runs statusline\.sh\./);
  });

  it('flags malicious skill content and not benign skills', () => {
    expect(rules('helper')).toEqual(
      expect.arrayContaining(['CONTENT-HIDDEN-UNICODE', 'CONTENT-PROMPT-INJECTION', 'CONTENT-DOWNLOAD-EXEC', 'CONTENT-SENSITIVE-PATHS', 'SKILL-UNRESTRICTED-TOOLS']),
    );
    expect(rules('pdf-tools')).toEqual([]);
    expect(rules('reviewer')).toEqual([]);
    expect(byName('helper')?.risk).toBe('high');
  });

  it('rolls child risk up to plugins and extensions', () => {
    expect(byName('Slack', 'extension')?.risk).toBe('high');
  });

  it('attaches OWASP references', () => {
    const f = inv.findings.find((x) => x.ruleId === 'CONTENT-PROMPT-INJECTION')!;
    expect(f.owasp).toEqual(['LLM01:2025 Prompt Injection', 'ASI01 Agent Goal Hijack']);
  });
});

describe('privacy', () => {
  it('never outputs secret values', () => {
    const json = JSON.stringify(inv) + JSON.stringify(toCycloneDX(inv));
    for (const s of Object.values(SECRETS)) expect(json).not.toContain(s);
    // references to env vars are kept for context
    expect(json).toContain('${env:GITHUB_TOKEN}');
  });

  it('rewrites the home directory to ~', () => {
    expect(JSON.stringify(inv)).not.toContain(fx.home);
  });
});

describe('history', () => {
  it('marks new assets and reports removed ones', async () => {
    const historyFile = path.join(os.tmpdir(), `ai-bom-hist-${Date.now()}.json`);
    const opts = { home: fx.home, platform: 'darwin' as const, systemRoot: fx.systemRoot, projects: [fx.project], historyFile, connectorsFile: fx.connectorsFile };
    const first = await scan(opts);
    expect(first.assets.some((a) => a.isNew)).toBe(false);

    const saved = JSON.parse(readFileSync(historyFile, 'utf8'));
    saved.assets = saved.assets.filter((a: { name: string }) => a.name !== 'context7');
    saved.assets.push({ id: 'skill:gone', kind: 'skill', name: 'old-skill' });
    (await import('node:fs')).writeFileSync(historyFile, JSON.stringify(saved));

    const second = await scan(opts);
    expect(second.assets.filter((a) => a.isNew).map((a) => a.name)).toEqual(['context7']);
    expect(second.removed).toEqual([{ id: 'skill:gone', kind: 'skill', name: 'old-skill' }]);
  });
});

describe('cyclonedx', () => {
  it('produces a CycloneDX 1.6 document', () => {
    const bom = toCycloneDX(inv) as any;
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    const gh = bom.components.find((c: any) => c.name === '@modelcontextprotocol/server-github');
    expect(gh.purl).toBe('pkg:npm/%40modelcontextprotocol/server-github');
    expect(bom.services.map((s: any) => s.name)).toEqual(expect.arrayContaining(['context7', 'internal-api']));
    expect(bom.dependencies.length).toBeGreaterThan(0);
    expect(bom.vulnerabilities.length).toBe(inv.findings.filter((f) => f.assetId).length);
  });
});
