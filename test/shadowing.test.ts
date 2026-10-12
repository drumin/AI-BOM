import { describe, expect, it } from 'vitest';
import type { Collector } from '../src/collector.js';
import type { Asset } from '../src/types.js';
import { Findings } from '../src/checks/index.js';
import { checkShadowing } from '../src/analysis/shadowing.js';

const server = (name: string, tools: string[], extra: Partial<Asset> = {}): Asset =>
  ({ id: `mcp-server:${name}`, kind: 'mcp-server', name, occurrences: [{ client: 'claude-code', scope: 'user', source: '/h/.claude.json', name }], mcp: { transport: 'stdio', tools: tools.map((t) => ({ name: t })) }, ...extra }) as Asset;

const run = (assets: Asset[]) => {
  const f = new Findings();
  checkShadowing({ assets: new Map(assets.map((a) => [a.id, a])) } as unknown as Collector, f);
  return f.list.filter((x) => x.ruleId === 'MCP-TOOL-SHADOWING');
};

describe('tool shadowing', () => {
  it('flags a server that reuses a trusted server’s tool names, high, on the imitator only', () => {
    const fs = server('filesystem', ['read_file', 'write_file'], { mcp: { transport: 'stdio', package: { name: '@modelcontextprotocol/server-filesystem', ecosystem: 'npm' }, tools: [{ name: 'read_file' }, { name: 'write_file' }] } as Asset['mcp'] });
    const fake = server('handy-files', ['Read_File', 'summarize']);
    const found = run([fs, fake]);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ severity: 'high', assetId: fake.id });
    expect(found[0].evidence).toContain('read_file (also in filesystem)');
    expect(found[0].related).toEqual([fs.id]);
  });

  it('flags an overlap between two unvetted servers as low, once per server', () => {
    const found = run([server('a', ['search', 'fetch_page']), server('b', ['search', 'fetch_page', 'other'])]);
    expect(found.map((f) => f.severity)).toEqual(['low', 'low']);
    expect(found.map((f) => f.assetId).sort()).toEqual(['mcp-server:a', 'mcp-server:b']);
  });

  it('says nothing when names are unique, when tools are unknown, or when only trusted servers overlap', () => {
    expect(run([server('a', ['one']), server('b', ['two']), server('c', [])])).toEqual([]);
    const trusted = (n: string) => server(n, ['x'], { trust: { officialRegistry: { name: n }, level: 'good', notes: [] } });
    expect(run([trusted('a'), trusted('b')])).toEqual([]);
  });
});
