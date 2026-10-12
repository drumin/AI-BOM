import { readFileSync, existsSync } from 'node:fs';
import { VERSION } from '../src/scan.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { serve } from '../src/server/serve.js';
import type { Inventory } from '../src/types.js';

const inv = { schemaVersion: 1, assets: [], findings: [] } as unknown as Inventory;
let base = '';
let close = () => {};
const calls: string[] = [];

beforeAll(async () => {
  const s = await serve({
    port: 17650,
    requireAssets: false,
    getInventory: async () => inv,
    rescan: async (o) => (calls.push(`rescan:${o.online}`), inv),
    connectors: {
      add: async (input) => {
        calls.push(`add:${JSON.stringify(input)}`);
        if (!(input as { name?: string }).name) throw new Error('name is required');
      },
      remove: async (id) => id === 'known',
      review: async (id) => id === 'known',
    },
  });
  base = s.url.replace(/\/$/, '');
  close = s.close;
});
afterAll(() => close());

const req = (path: string, init: RequestInit = {}) => fetch(base + path, init);
const withHeader = (init: RequestInit = {}): RequestInit => ({ ...init, headers: { 'X-AI-BOM': '1', ...(init.headers ?? {}) } });

describe('local API', () => {
  it('serves the inventory', async () => {
    expect((await req('/api/inventory')).status).toBe(200);
  });

  it('rejects mutations without the custom header (CSRF)', async () => {
    expect((await req('/api/rescan', { method: 'POST' })).status).toBe(403);
    expect((await req('/api/connectors', { method: 'POST', body: '{}' })).status).toBe(403);
  });

  it('passes the online switch through, keeping the mode when omitted', async () => {
    await req('/api/rescan?online=1', withHeader({ method: 'POST' }));
    await req('/api/rescan', withHeader({ method: 'POST' }));
    await req('/api/rescan?online=0', withHeader({ method: 'POST' }));
    expect(calls.filter((c) => c.startsWith('rescan'))).toEqual(['rescan:true', 'rescan:undefined', 'rescan:false']);
  });

  it('validates connector requests', async () => {
    expect((await req('/api/connectors', withHeader({ method: 'POST', body: '{oops' }))).status).toBe(400);
    expect((await req('/api/connectors', withHeader({ method: 'POST', body: '{}' }))).status).toBe(400);
    expect((await req('/api/connectors', withHeader({ method: 'POST', body: JSON.stringify({ name: 'x'.repeat(20000) }) }))).status).toBe(413);
    expect((await req('/api/connectors', withHeader({ method: 'POST', body: '{"name":"Gmail","platform":"claude.ai"}' }))).status).toBe(200);
    expect((await req('/api/connectors/known/review', withHeader({ method: 'POST' }))).status).toBe(200);
    expect((await req('/api/connectors/unknown', withHeader({ method: 'DELETE' }))).status).toBe(404);
    expect((await req('/api/connectors/..%2f..%2fetc', withHeader({ method: 'DELETE' }))).status).toBe(404);
  });

  it('rejects requests for a foreign Host (DNS rebinding)', async () => {
    const http = await import('node:http');
    const status = await new Promise<number>((resolve) => {
      http.get(`${base}/api/inventory`, { headers: { Host: 'attacker.example:17650' } }, (res) => resolve(res.statusCode ?? 0));
    });
    expect(status).toBe(403);
  });

  it.skipIf(!existsSync('dist/web/index.html'))('answers a folder URL with the app, not a 500', async () => {
    const r = await fetch(base + '/assets');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
  });

  it('reports the version in package.json', () => {
    expect(VERSION).toBe(JSON.parse(readFileSync('package.json', 'utf8')).version);
  });
});
