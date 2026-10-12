import { beforeAll, describe, expect, it } from 'vitest';
import path from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import type { Inventory } from '../src/types.js';
import { buildFixture, type Fixture } from './fixture.js';

/**
 * Layouts observed on real Claude Code installs that the synthetic fixture
 * did not cover: account-synced skills/plugins nested one level deeper,
 * plugins enabled in settings but absent from installed_plugins.json,
 * plugin manifests that point to their files, the connector sign-in cache,
 * launcher-settings.json and usage counters.
 */
function write(root: string, rel: string, content: string | object) {
  const file = path.join(root, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content, null, 2));
}

let fx: Fixture;
let inv: Inventory;
const byName = (n: string, kind?: string) => inv.assets.find((a) => a.name === n && (!kind || a.kind === kind));

beforeAll(async () => {
  fx = buildFixture();
  const claude = path.join(fx.home, '.claude');
  const acct = 'cf09a6e7-0000-4000-8000-000000000000_cccd8f26-0000-4000-8000-000000000000';

  // skills/synced/<account>/<skill>/SKILL.md
  write(claude, `skills/synced/${acct}/apple-design/SKILL.md`, '---\nname: apple-design\ndescription: Apple-style UI\n---\nBody\n');
  write(claude, `skills/synced/.bucket-${acct}`, '');
  // plugins/synced/<account>/<plugin>/…
  write(claude, `plugins/synced/${acct}/marketing/.claude-plugin/plugin.json`, { name: 'marketing', mcpServers: './servers.json' });
  write(claude, `plugins/synced/${acct}/marketing/servers.json`, { mcpServers: { amplitude: { type: 'http', url: 'https://mcp.amplitude.com/mcp' } } });

  // Enabled in settings, not in installed_plugins.json; files in cache/<mkt>/<name>/<version>/ with manifest paths.
  const settings = JSON.parse((await import('node:fs')).readFileSync(path.join(claude, 'settings.json'), 'utf8'));
  settings.enabledPlugins['zoom-plugin@knowledge-work'] = true;
  settings.enabledPlugins['figma@design-market'] = true;
  write(claude, 'settings.json', settings);
  write(claude, 'plugins/cache/knowledge-work/zoom-plugin/1.0.0/.claude-plugin/plugin.json', { name: 'zoom-plugin', version: '1.0.0' });
  write(claude, 'plugins/cache/knowledge-work/zoom-plugin/1.2.0/.claude-plugin/plugin.json', {
    name: 'zoom-plugin',
    version: '1.2.0',
    mcpServers: './config/mcp.json',
    agents: ['./team/scheduler.md'],
    hooks: './config/hooks.json',
  });
  write(claude, 'plugins/cache/knowledge-work/zoom-plugin/1.2.0/config/mcp.json', { zoom: { type: 'http', url: 'https://mcp.zoom.us/mcp' } });
  write(claude, 'plugins/cache/knowledge-work/zoom-plugin/1.2.0/team/scheduler.md', '---\nname: scheduler\ndescription: Books meetings\n---\n');
  write(claude, 'plugins/cache/knowledge-work/zoom-plugin/1.2.0/config/hooks.json', { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo hi' }] }] } });
  // Marketplace checkout resolved through marketplace.json.
  write(claude, 'plugins/marketplaces/design-market/.claude-plugin/marketplace.json', { name: 'design-market', plugins: [{ name: 'figma', source: './tools/figma' }] });
  write(claude, 'plugins/marketplaces/design-market/tools/figma/.mcp.json', { mcpServers: { figma: { type: 'http', url: 'https://mcp.figma.com/mcp' } } });

  // installed_plugins.json entry whose installPath moved: found again through the cache.
  const installed = JSON.parse((await import('node:fs')).readFileSync(path.join(claude, 'plugins/installed_plugins.json'), 'utf8'));
  installed.plugins['stale@knowledge-work'] = [{ scope: 'user', installPath: '/nonexistent/stale', version: '0.1.0' }];
  write(claude, 'plugins/installed_plugins.json', installed);
  write(claude, 'plugins/cache/knowledge-work/stale/0.1.0/commands/tidy.md', '---\ndescription: Tidy\n---\n');

  // Connectors waiting for sign-in, launcher hooks, usage counters.
  write(claude, 'mcp-needs-auth-cache.json', { Cloudflare_Developer_Platform: { timestamp: 1790000000000 } });
  write(claude, 'launcher-settings.json', { hooks: { Stop: [{ hooks: [{ type: 'command', command: '~/.claude/stop-hook.sh' }] }] }, permissions: { allow: ['Read'] } });
  const state = JSON.parse((await import('node:fs')).readFileSync(path.join(fx.home, '.claude.json'), 'utf8'));
  state.skillUsage = { 'apple-design': { usageCount: 7, lastUsedAt: 1790000000000 }, 'anthropic-skills:pdf-tools': { usageCount: 2, lastUsedAt: 1780000000000 } };
  state.pluginUsage = { 'code-review@acme-market': { usageCount: 3, lastUsedAt: 1785000000000, lastUsedNumStartups: 4 } };
  write(fx.home, '.claude.json', state);

  inv = await scan({ home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [fx.project], trace: true });
});

describe('real-world Claude Code layouts', () => {
  it('finds skills synced from a Claude account', () => {
    const s = byName('apple-design', 'skill')!;
    expect(s.occurrences[0].note).toBe('Synced from your Claude account');
  });

  it('finds synced plugins and follows manifest paths', () => {
    expect(byName('marketing@synced', 'plugin')).toBeDefined();
    expect(byName('amplitude')?.occurrences[0].via).toBe(byName('marketing@synced')!.id);
  });

  it('resolves plugins enabled only in settings, choosing the newest cached version', () => {
    const p = byName('zoom-plugin@knowledge-work', 'plugin')!;
    expect(p.path).toMatch(/zoom-plugin\/1\.2\.0$/);
    const kids = p.children!.map((id) => inv.assets.find((a) => a.id === id)!.name).sort();
    expect(kids).toEqual(['SessionStart', 'scheduler', 'zoom']);
    expect(byName('figma')?.mcp?.url).toBe('https://mcp.figma.com/mcp');
  });

  it('finds a plugin whose recorded installPath no longer exists', () => {
    expect(byName('tidy', 'command')?.occurrences[0].via).toBe(byName('stale@knowledge-work')!.id);
  });

  it('detects claude.ai connectors from the sign-in cache without review nags', () => {
    const c = byName('Cloudflare Developer Platform', 'connector')!;
    expect(c.connector).toMatchObject({ platform: 'claude.ai', detectedIn: 'Claude Code' });
    expect(c.occurrences[0].note).toMatch(/waiting for you to sign in/);
    expect(inv.findings.some((f) => f.assetId === c.id)).toBe(false);
  });

  it('reads hooks from launcher-settings.json', () => {
    expect(inv.assets.some((a) => a.kind === 'hook' && a.hook?.command === '~/.claude/stop-hook.sh')).toBe(true);
  });

  it('attaches usage counters to skills and plugins', () => {
    expect(byName('apple-design')!.usage).toEqual({ source: 'counters', count: 7, lastUsedAt: new Date(1790000000000).toISOString() });
    expect(byName('pdf-tools')!.usage?.count).toBe(2);
    expect(byName('code-review@acme-market')!.usage?.count).toBe(3);
    expect(byName('reviewer')!.usage).toBeUndefined();
  });

  it('records a trace for `ai-bom doctor` with names and counts only', () => {
    const t = inv.trace!;
    expect(t.find((x) => x.path.endsWith('.claude/plugins'))?.note).toMatch(/5 plugin\(s\) scanned \(2 listed in installed_plugins\.json, 2 only in enabledPlugins\)/);
    expect(t.some((x) => x.path.endsWith('mcp-needs-auth-cache.json') && x.note === 'keys: Cloudflare_Developer_Platform')).toBe(true);
    expect(JSON.stringify(t)).not.toContain('sk-ant');
  });
});
