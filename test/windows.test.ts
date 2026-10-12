import { describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';

function write(root: string, rel: string, content: string | object) {
  const file = path.join(root, ...rel.split('/'));
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
}

describe('Windows locations', () => {
  it('finds config in %APPDATA%, %LOCALAPPDATA%, PowerShell profiles and Program Files', async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-win-'));
    const home = path.join(root, 'Users', 'sam');
    write(home, 'AppData/Roaming/Claude/claude_desktop_config.json', { mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', 'C:\\\\Users\\\\sam'] } } });
    write(home, 'AppData/Roaming/Code/User/mcp.json', { servers: { pw: { command: 'npx', args: ['@playwright/mcp@0.0.40'] } } });
    write(home, 'AppData/Roaming/Zed/settings.json', { context_servers: { zedsrv: { command: { path: 'node', args: ['srv.js'] } } } });
    write(home, '.cursor/mcp.json', { mcpServers: { gh: { url: 'https://api.githubcopilot.com/mcp/' } } });
    write(home, 'Documents/PowerShell/Microsoft.PowerShell_profile.ps1', '# my profile\n$env:OPENAI_API_KEY = "sk-proj-Q1w2E3r4T5y6U7i8O9p0A1s2D3f4"\n$env:PATH += ";C:\\\\tools"\n');
    write(home, 'AppData/Local/Google/Chrome/User Data/Default/Extensions/abc/1.0_0/manifest.json', { name: 'Claude', version: '1.0', host_permissions: ['<all_urls>'] });
    mkdirSync(path.join(home, 'AppData/Local/Programs/cursor'), { recursive: true });
    write(root, 'sys/Program Files/ClaudeCode/managed-settings.json', { permissions: { defaultMode: 'bypassPermissions' } });

    const inv = await scan({ home, platform: 'win32', systemRoot: path.join(root, 'sys'), projects: [], sessionLogs: false });
    const names = inv.assets.map((a) => `${a.kind}:${a.name}`);
    expect(names).toEqual(expect.arrayContaining(['mcp-server:fs', 'mcp-server:pw', 'mcp-server:zedsrv', 'mcp-server:gh', 'api-key:OpenAI key', 'browser-extension:Claude', 'app:Cursor']));
    expect(inv.clients.map((c) => c.id)).toEqual(expect.arrayContaining(['claude-desktop', 'vscode', 'zed', 'cursor', 'shell', 'chrome', 'applications']));
    expect(inv.findings.some((f) => f.ruleId === 'PERM-BYPASS' && f.location?.includes('Program Files'))).toBe(true);
    expect(JSON.stringify(inv)).not.toContain('Q1w2E3r4T5y6U7i8O9p0');
  });
});
