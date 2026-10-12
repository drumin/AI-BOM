import { beforeAll, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import type { Inventory } from '../src/types.js';

/** Tools and model servers added after comparing against another discovery catalog. */
function write(root: string, rel: string, content: string | object) {
  const file = path.join(root, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
}

let inv: Inventory;
const clientsOf = (name: string, kind?: string) => inv.assets.filter((a) => a.name === name && (!kind || a.kind === kind)).flatMap((a) => a.occurrences.map((o) => o.client));

beforeAll(async () => {
  const h = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-more-'));
  const project = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-more-proj-'));
  write(h, '.config/crush/crush.json', { mcp: { 'crush-fs': { type: 'stdio', command: 'npx', args: ['-y', 'crush-fs@1.0.0'] }, 'crush-remote': { type: 'http', url: 'https://mcp.example.com/crush' } } });
  write(project, 'crush.json', { mcp: { 'crush-proj': { type: 'sse', url: 'https://mcp.example.com/sse' } } });
  write(project, 'CRUSH.md', '# Crush notes\nUse pnpm.\n');
  write(h, 'Library/Application Support/Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json', { mcpServers: { 'kilo-user': { command: 'node', args: ['k.js'] } } });
  write(project, '.kilocode/mcp.json', { mcpServers: { 'kilo-proj': { url: 'https://mcp.example.com/kilo' } } });
  write(project, '.kilocode/rules/style.md', '# Style\nTwo spaces.\n');
  write(h, '.gemini/antigravity/mcp_config.json', { mcpServers: { 'ag-user': { command: 'node', args: ['a.js'] } } });
  write(h, '.gemini/antigravity/skills/ag-skill/SKILL.md', '---\nname: ag-skill\ndescription: a skill\n---\nBody\n');
  write(project, '.agent/rules/ag-rule.md', '# Rule\nBe brief.\n');
  // Model servers with no config file: found by the folder they leave behind.
  mkdirSync(path.join(h, '.cache/vllm'), { recursive: true });
  mkdirSync(path.join(h, '.local/share/uv/tools/open-webui'), { recursive: true });
  write(h, '.localai/config.yaml', 'threads: 4\n');
  write(h, '.cache/llama.cpp/ggml-org_gemma-3-1b-it-GGUF_gemma-3-1b-it-Q4_K_M.gguf', 'weights');
  inv = await scan({ home: h, platform: 'darwin', projects: [project], sessionLogs: false });
});

describe('more agents and model servers', () => {
  it('reads Crush, Kilo Code and Antigravity configuration', () => {
    expect(clientsOf('crush-fs', 'mcp-server')).toEqual(['crush']);
    expect(inv.assets.find((a) => a.name === 'crush-remote')?.mcp?.url).toBe('https://mcp.example.com/crush');
    expect(clientsOf('crush-proj', 'mcp-server')).toEqual(['crush']);
    expect(inv.assets.some((a) => a.kind === 'instructions' && a.occurrences.some((o) => o.client === 'crush'))).toBe(true);
    expect(clientsOf('kilo-user', 'mcp-server')).toEqual(['kilo-code']);
    expect(clientsOf('kilo-proj', 'mcp-server')).toEqual(['kilo-code']);
    expect(inv.assets.some((a) => a.kind === 'instructions' && a.occurrences.some((o) => o.client === 'kilo-code'))).toBe(true);
    expect(clientsOf('ag-user', 'mcp-server')).toEqual(['antigravity']);
    expect(clientsOf('ag-skill', 'skill')).toEqual(['antigravity']);
    expect(inv.assets.some((a) => a.kind === 'instructions' && a.occurrences.some((o) => o.client === 'antigravity'))).toBe(true);
    expect(inv.clients.map((c) => c.id)).toEqual(expect.arrayContaining(['crush', 'kilo-code', 'antigravity']));
  });

  it('finds model servers by what they leave behind, and the models llama.cpp downloaded', () => {
    for (const name of ['vLLM', 'LocalAI', 'Open WebUI', 'llama.cpp']) expect(inv.assets.some((a) => a.kind === 'app' && a.name === name), name).toBe(true);
    const model = inv.assets.find((a) => a.kind === 'model' && a.model?.runtime === 'llama.cpp')!;
    expect(model.name).toBe('ggml-org_gemma-3-1b-it-GGUF_gemma-3-1b-it-Q4_K_M');
    expect(model.model?.pickle).toBeFalsy();
  });
});
