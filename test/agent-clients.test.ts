import { beforeAll, describe, expect, it } from 'vitest';
import path from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import type { Inventory } from '../src/types.js';
import { buildFixture } from './fixture.js';

/**
 * Config locations taken from each tool's current documentation:
 * GitHub Copilot CLI (~/.copilot/mcp-config.json, .github/mcp.json), Gemini CLI skills,
 * Windsurf's Devin-era ~/.config/devin/mcp_config.json, and opencode's plural
 * agents/commands/skills/plugins folders in ~/.config/opencode and a project's .opencode.
 */
function write(root: string, rel: string, content: string | object) {
  const file = path.join(root, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
}
const skill = (name: string) => `---\nname: ${name}\ndescription: ${name} skill\n---\nBody\n`;

let inv: Inventory;
let project: string;
const find = (name: string, kind?: string) => inv.assets.filter((a) => a.name === name && (!kind || a.kind === kind));
const clientsOf = (name: string, kind?: string) => find(name, kind).flatMap((a) => a.occurrences.map((o) => o.client)).sort();

beforeAll(async () => {
  const fx = buildFixture();
  const h = fx.home;
  project = fx.project;

  write(h, '.copilot/mcp-config.json', { mcpServers: { 'copilot-user-srv': { command: 'npx', args: ['-y', 'some-copilot-pkg@1.0.0'] } } });
  write(project, '.github/mcp.json', { mcpServers: { 'copilot-shared-srv': { type: 'http', url: 'https://mcp.example.com/mcp' } } });

  write(h, '.gemini/skills/gem-user/SKILL.md', skill('gem-user'));
  write(project, '.gemini/skills/gem-proj/SKILL.md', skill('gem-proj'));

  write(h, '.config/devin/mcp_config.json', { mcpServers: { 'devin-srv': { command: 'node', args: ['devin.js'] } } });

  const oc = path.join(h, '.config', 'opencode');
  write(oc, 'opencode.json', { mcp: { 'oc-global': { type: 'remote', url: 'https://oc.example.com/mcp' } } });
  write(oc, 'agents/oc-reviewer.md', '---\ndescription: Reviews code\n---\nReview.\n');
  write(oc, 'agent/legacy-agent.md', '---\ndescription: Old layout\n---\nHi.\n');
  write(oc, 'commands/oc-deploy.md', '---\ndescription: Deploy\n---\nDeploy.\n');
  write(oc, 'skills/oc-user-skill/SKILL.md', skill('oc-user-skill'));
  write(oc, 'plugins/notify.ts', 'export default async () => ({ event: async () => { await fetch("https://hooks.example.com/x"); } });\n');
  write(oc, 'plugins/readme.md', 'not a plugin');

  write(project, '.opencode/opencode.json', { mcp: { 'oc-project': { type: 'local', command: ['node', 'srv.js'] } } });
  write(project, '.opencode/skills/oc-proj-skill/SKILL.md', skill('oc-proj-skill'));
  write(project, '.opencode/plugins/guard.js', 'module.exports = async () => ({});\n');

  inv = await scan({ home: h, platform: 'darwin', systemRoot: fx.systemRoot, projects: [project] });
});

describe('GitHub Copilot CLI', () => {
  it('reads ~/.copilot/mcp-config.json', () => {
    expect(clientsOf('copilot-user-srv', 'mcp-server')).toEqual(['copilot-cli']);
    expect(inv.clients.map((c) => c.id)).toContain('copilot-cli');
  });
  it('reads a project .github/mcp.json', () => {
    const o = find('copilot-shared-srv', 'mcp-server')[0].occurrences[0];
    expect(o).toMatchObject({ client: 'copilot-cli', scope: 'project' });
  });
});

describe('Gemini CLI skills', () => {
  it('finds user and project skills', () => {
    expect(clientsOf('gem-user', 'skill')).toEqual(['gemini-cli']);
    expect(find('gem-proj', 'skill')[0].occurrences[0]).toMatchObject({ client: 'gemini-cli', scope: 'project' });
  });
});

describe('Windsurf (Devin-era path)', () => {
  it('reads ~/.config/devin/mcp_config.json', () => {
    expect(clientsOf('devin-srv', 'mcp-server')).toEqual(['windsurf']);
  });
});

describe('opencode', () => {
  it('reads plural and legacy singular agent/command folders', () => {
    expect(clientsOf('oc-reviewer', 'agent')).toEqual(['opencode']);
    expect(clientsOf('legacy-agent', 'agent')).toEqual(['opencode']);
    expect(clientsOf('oc-deploy', 'command')).toEqual(['opencode']);
  });
  it('reads user and project skills', () => {
    expect(clientsOf('oc-user-skill', 'skill')).toEqual(['opencode']);
    expect(find('oc-proj-skill', 'skill')[0].occurrences[0]).toMatchObject({ scope: 'project' });
  });
  it('lists plugin code files as plugins, user and project, and ignores other files', () => {
    expect(find('notify', 'plugin')[0].occurrences[0].note).toMatch(/code inside opencode/);
    expect(find('guard', 'plugin')[0].occurrences[0].scope).toBe('project');
    expect(find('readme')).toHaveLength(0);
  });
  it('reads MCP servers from the global config and from .opencode/opencode.json', () => {
    expect(find('oc-global', 'mcp-server')[0].mcp?.url).toBe('https://oc.example.com/mcp');
    expect(find('oc-project', 'mcp-server')[0].mcp?.command).toBe('node');
  });
});
