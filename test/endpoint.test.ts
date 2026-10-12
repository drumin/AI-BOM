import { describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { parseLsof, parsePs, type EndpointSnapshot } from '../src/analysis/endpoint.js';

const home = () => mkdtempSync(path.join(os.tmpdir(), 'ai-bom-ep-'));

describe('endpoint parsing', () => {
  it('reads ps and lsof output', () => {
    expect(parsePs('  101 /usr/bin/ollama serve\n 7 node a.js\n\nbad')).toEqual([{ pid: 101, command: '/usr/bin/ollama serve' }, { pid: 7, command: 'node a.js' }]);
    expect(parseLsof('p101\nn*:11434\nn[::1]:11434\np7\nn127.0.0.1:3000\nnnot-a-socket')).toEqual([
      { pid: 101, address: '*', port: 11434 },
      { pid: 101, address: '[::1]', port: 11434 },
      { pid: 7, address: '127.0.0.1', port: 3000 },
    ]);
  });
});

describe('running model servers and MCP servers', () => {
  const snap: EndpointSnapshot = {
    processes: [
      { pid: 101, command: '/opt/homebrew/bin/ollama serve' },
      { pid: 102, command: '/usr/local/bin/llama-server -m model.gguf --host 0.0.0.0' },
      { pid: 103, command: '/Applications/LM Studio.app/Contents/MacOS/LM Studio' },
      { pid: 104, command: 'node /Users/alex/.npm/_npx/abc/node_modules/.bin/some-mcp-server --token ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
      { pid: 105, command: 'npx -y @modelcontextprotocol/server-filesystem /tmp' },
      { pid: 106, command: 'claude --mcp-config /tmp/mcp.json --dangerously-skip-permissions' },
      { pid: 107, command: 'python3 -m http.server 8000' },
    ],
    listeners: [
      { pid: 101, address: '127.0.0.1', port: 11434 },
      { pid: 102, address: '*', port: 8080 },
      { pid: 103, address: '*', port: 1234 },
      { pid: 107, address: '*', port: 8000 },
      { pid: 999, address: '0.0.0.0', port: 4891 }, // unknown process on an AI-only port
    ],
  };

  it('finds model servers by port and program, flags those open to the network, and lists unlisted MCP servers', async () => {
    const h = home();
    // One MCP server is in a config, so its running process is not "unlisted".
    mkdirSync(path.join(h, '.cursor'), { recursive: true });
    writeFileSync(path.join(h, '.cursor/mcp.json'), JSON.stringify({ mcpServers: { filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] } } }));
    const inv = await scan({ home: h, platform: 'darwin', sessionLogs: false, endpoint: async () => snap });
    const apps = inv.assets.filter((a) => a.kind === 'app').map((a) => a.name);
    expect(apps).toEqual(expect.arrayContaining(['Ollama', 'llama.cpp', 'LM Studio']));
    expect(apps.some((n) => n.includes('port 4891'))).toBe(true);
    const exposed = inv.findings.filter((f) => f.ruleId === 'MODEL-SERVER-EXPOSED');
    // Ollama listens on loopback only; the other three listen on every interface.
    expect(exposed.map((f) => f.evidence).sort()).toEqual(['GPT4All: listening on every network interface:4891', 'LM Studio: listening on every network interface:1234', 'llama.cpp: listening on every network interface:8080']);
    expect(exposed[0].atlas?.[0]).toContain('AML.T0132');
    // A web server on port 8000 is not an AI service.
    expect(apps).not.toContain('Open WebUI');
    const unlisted = inv.findings.filter((f) => f.ruleId === 'MCP-UNLISTED-RUNNING');
    expect(unlisted).toHaveLength(1);
    expect(unlisted[0].title).toContain('some-mcp-server');
    expect(JSON.stringify(unlisted)).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz');
    expect(inv.coverage!.gaps.some((g) => g.what === 'Running programs and open ports')).toBe(false);
  });

  it('is skipped by default for a scan of another home, and reported as not covered', async () => {
    const inv = await scan({ home: home(), platform: 'darwin', sessionLogs: false });
    expect(inv.findings.some((f) => f.ruleId === 'MODEL-SERVER-EXPOSED' || f.ruleId === 'MCP-UNLISTED-RUNNING')).toBe(false);
    const gaps = inv.coverage!.gaps.map((g) => g.what);
    expect(gaps).toEqual(expect.arrayContaining(['Running programs and open ports', 'Agent session logs', 'Online vulnerability and publisher lookups', 'Containers, WSL and other computers', 'Cloud-hosted and scheduled agents']));
  });

  it('says so when the system tools are unavailable', async () => {
    const inv = await scan({ home: home(), platform: 'darwin', sessionLogs: false, endpoint: async () => undefined });
    expect(inv.coverage!.gaps.find((g) => g.what === 'Running programs and open ports')?.why).toMatch(/ps, lsof/);
  });
});
