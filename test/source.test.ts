import { describe, expect, it } from 'vitest';
import { scan } from '../src/scan.js';
import { assetSource } from '../src/review/source.js';
import { buildFixture, SECRETS } from './fixture.js';

describe('assetSource (view file)', () => {
  it('returns redacted files for skills and one server entry for MCP servers', async () => {
    const fx = buildFixture();
    const inv = await scan({ home: fx.home });
    const skill = inv.assets.find((a) => a.kind === 'skill' && a.path);
    expect(skill).toBeTruthy();
    const files = await assetSource(skill!, fx.home);
    expect(files.length).toBeGreaterThan(0);
    expect(files.some((f) => f.format === 'markdown')).toBe(true);

    for (const a of inv.assets.filter((x) => x.kind === 'mcp-server')) {
      const out = await assetSource(a, fx.home);
      for (const f of out) for (const v of Object.values(SECRETS)) expect(f.text).not.toContain(v);
    }
    const mcp = inv.assets.find((a) => a.kind === 'mcp-server' && !a.path && a.occurrences.some((o) => o.source.endsWith('.json')));
    if (mcp) {
      const [f] = await assetSource(mcp, fx.home);
      expect(f.format).toBe('json');
      expect(f.text).toContain(`"${mcp.occurrences[0].name}"`);
    }
  });
});
