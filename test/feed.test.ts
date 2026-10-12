import { beforeEach, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync, sign } from 'node:crypto';
import { loadCachedFeed, updateFeed, type BytesFetch } from '../src/feed/index.js';
import { scan } from '../src/scan.js';
import { buildFixture } from './fixture.js';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519').privateKey;

function signed(generatedAt: string, advisories: unknown[], key = privateKey) {
  const body = Buffer.from(JSON.stringify({ schema: 1, generatedAt, advisories }));
  return { body, sig: sign(null, body, key).toString('base64') };
}
const serve = (f: { body: Buffer; sig: string }): BytesFetch => async (url) => ({
  ok: true,
  status: 200,
  arrayBuffer: async () => {
    const b = url.endsWith('.sig') ? Buffer.from(f.sig) : f.body;
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
  },
});

const WEATHER = { id: 'GHSA-feed-0001', ecosystem: 'npm', package: 'weather-mcp', fixed: '1.0.4', severity: 'critical', summary: 'Exfiltrates SSH keys.', references: ['https://example.org/a'] };

beforeEach(() => {
  process.env.AI_BOM_HOME = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-feed-'));
  process.env.AI_BOM_FEED_PUBKEY = publicKey.export({ type: 'spki', format: 'pem' }).toString();
});

describe('signed advisory feed', () => {
  it('installs a correctly signed feed and uses it in scans', async () => {
    const r = await updateFeed(serve(signed(new Date().toISOString(), [WEATHER, { id: 'bad', severity: 'x' }])));
    expect(r.status).toBe('updated');
    expect((await loadCachedFeed())?.advisories).toHaveLength(1);
    const fx = buildFixture();
    const inv = await scan({ home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [] });
    expect(inv.feed).toMatchObject({ advisories: 1, verified: true });
    const f = inv.findings.find((x) => x.advisory === 'GHSA-feed-0001')!;
    expect(f.severity).toBe('critical');
    expect(f.vuln?.fixCommand).toBe('npx -y weather-mcp@1.0.4');
  });

  it('rejects feeds signed by someone else, tampered caches, and rollbacks', async () => {
    expect((await updateFeed(serve(signed(new Date().toISOString(), [WEATHER], other)))).status).toBe('error');
    await updateFeed(serve(signed('2026-09-01T00:00:00Z', [WEATHER])));
    const rollback = await updateFeed(serve(signed('2026-08-01T00:00:00Z', [])));
    expect(rollback).toMatchObject({ status: 'error' });
    expect(rollback.message).toMatch(/older feed/);
    const file = path.join(process.env.AI_BOM_HOME!, 'feed', 'advisories.json');
    writeFileSync(file, readFileSync(file, 'utf8').replace('critical', 'low'));
    expect(await loadCachedFeed()).toBeUndefined();
  });

  it('stays off until a signing key is configured', async () => {
    delete process.env.AI_BOM_FEED_PUBKEY;
    expect((await updateFeed(serve(signed(new Date().toISOString(), [WEATHER])))).status).toBe('not-configured');
  });
});
