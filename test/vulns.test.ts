import { beforeAll, describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync } from 'node:fs';
import { scan } from '../src/scan.js';
import { checkOsv, type Fetch } from '../src/vulns/index.js';
import { isAffected, matchStrength, parseNvd, searchTerms, versionsFromDescription } from '../src/vulns/nvd.js';
import { pinnedCommand } from '../src/vulns/fix.js';
import { indexInstalled, installedVersions } from '../src/vulns/installed.js';
import type { Asset, Finding, Inventory } from '../src/types.js';
import { buildFixture, SECRETS, type Fixture } from './fixture.js';

/* NVD API 2.0 response shapes (trimmed to the fields the scanner reads). */
const nvdCve = (id: string, description: string, extra: Record<string, unknown> = {}) => ({ cve: { id, vulnStatus: 'Analyzed', descriptions: [{ lang: 'en', value: description }], ...extra } });

const CVE_2025_6514 = nvdCve(
  'CVE-2025-6514',
  'mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers due to crafted input from the authorization_endpoint response URL',
  {
    metrics: { cvssMetricV31: [{ type: 'Secondary', cvssData: { baseScore: 9.6, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H' } }] },
    weaknesses: [{ description: [{ lang: 'en', value: 'CWE-78' }] }],
    configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:glama:mcp-remote:*:*:*:*:*:node.js:*:*', versionStartIncluding: '0.0.5', versionEndExcluding: '0.1.16' }] }] }],
    references: [{ url: 'https://github.com/geelen/mcp-remote/security' }],
  },
);
// Same keyword, different product: must not match.
const OTHER_PRODUCT = nvdCve('CVE-2099-1111', 'mcp-remote-proxy before 2.0 allows SSRF.', {
  metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }] },
});
const REJECTED = { cve: { id: 'CVE-2099-2222', vulnStatus: 'Rejected', descriptions: [{ lang: 'en', value: 'mcp-remote duplicate' }] } };
// Product-phrase match only (no package name): reported as "possible".
const FS_PHRASE = nvdCve(
  'CVE-2099-3333',
  'Filesystem MCP Server is a Model Context Protocol (MCP) server for filesystem operations. Versions prior to 2026.12.1 allow reading files outside allowed directories.',
);
const SQLITE = nvdCve('CVE-2099-4444', 'SQL injection in mcp-server-sqlite prior to 0.6.3 via the query tool.', {
  metrics: { cvssMetricV40: [{ type: 'Primary', cvssData: { baseScore: 8.7, baseSeverity: 'HIGH' } }] },
});

function mockFetch(log: string[], nvdStatus = 200): Fetch {
  return async (url, init) => {
    log.push(url + (init?.headers?.apiKey ? ' [key]' : ''));
    const json = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
    if (url.startsWith('https://services.nvd.nist.gov/')) {
      if (nvdStatus !== 200) return json({}, nvdStatus);
      const term = new URL(url).searchParams.get('keywordSearch');
      if (term === 'mcp-remote') return json({ vulnerabilities: [CVE_2025_6514, OTHER_PRODUCT, REJECTED] });
      if (term === 'filesystem MCP server') return json({ vulnerabilities: [FS_PHRASE] });
      if (term === 'mcp-server-sqlite') return json({ vulnerabilities: [SQLITE] });
      return json({ vulnerabilities: [] });
    }
    if (url.includes('registry.npmjs.org/mcp-remote/')) return json({ version: '0.14.3' });
    if (url.includes('registry.npmjs.org/%40modelcontextprotocol%2fserver-filesystem/')) return json({ version: '2026.8.31' });
    if (url.includes('registry.npmjs.org/exa-mcp-server/')) return json({ version: '3.1.0' });
    if (url.includes('registry.npmjs.org/postmark-mcp/')) return json({}, 404);
    if (url.includes('pypi.org/pypi/mcp-server-sqlite/')) return json({ info: { version: '0.6.9' } });
    if (url.includes('registry.npmjs.org') || url.includes('pypi.org')) return json({ version: '1.0.0', info: { version: '1.0.0' } });
    if (url.endsWith('/v1/querybatch')) {
      const { queries } = JSON.parse(init!.body!);
      return json({
        results: queries.map((q: { package: { name: string } }) =>
          q.package.name === 'exa-mcp-server'
            ? { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }
            : q.package.name === 'mcp-remote'
              ? { vulns: [{ id: 'GHSA-6xpm-ggf7-wc3p' }] }
              : q.package.name === 'postmark-mcp'
                ? { vulns: [{ id: 'MAL-2025-7777' }] }
                : {},
        ),
      });
    }
    if (url.includes('/v1/vulns/GHSA-aaaa-bbbb-cccc'))
      return json({ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2099-0001'], summary: 'Path traversal', database_specific: { severity: 'HIGH' }, affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.2.0' }] }] }] });
    if (url.includes('/v1/vulns/GHSA-6xpm-ggf7-wc3p'))
      return json({ id: 'GHSA-6xpm-ggf7-wc3p', aliases: ['CVE-2025-6514'], summary: 'mcp-remote OS command injection', database_specific: { severity: 'CRITICAL' } });
    if (url.includes('/v1/vulns/MAL-2025-7777')) return json({ id: 'MAL-2025-7777', summary: 'Malicious code in postmark-mcp' });
    return json({}, 404);
  };
}

let fx: Fixture;
let offline: Inventory;
let online: Inventory;
let log: string[];
const sleeps: number[] = [];
const vulns = (inv: Inventory, assetName: string) => {
  const ids = new Set(inv.assets.filter((a) => a.name === assetName).map((a) => a.id));
  return inv.findings.filter((f) => f.assetId && ids.has(f.assetId) && f.ruleId.startsWith('VULN-'));
};

beforeAll(async () => {
  fx = buildFixture();
  const base = { home: fx.home, platform: 'darwin' as const, systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], connectorsFile: fx.connectorsFile };
  offline = await scan(base);
  log = [];
  online = await scan({
    ...base,
    online: true,
    fetchImpl: mockFetch(log),
    nvdCacheFile: path.join(mkdtempSync(path.join(os.tmpdir(), 'nvd-')), 'nvd.json'),
    sleep: async (ms) => void sleeps.push(ms),
  });
});

describe('what version does a call really run?', () => {
  it('indexes npx and uv caches', async () => {
    const idx = await indexInstalled(fx.home);
    expect(installedVersions(idx, 'npm', 'mcp-remote')).toEqual(['0.1.10']);
    expect(installedVersions(idx, 'npm', '@scope/other')).toEqual(['2.0.0']);
    expect(installedVersions(idx, 'pypi', 'MCP_Server.SQLite')).toEqual(['0.6.2']);
  });

  it('flags an unpinned call that can reuse a vulnerable cached copy, offline', () => {
    const [f] = vulns(offline, 'linear-remote');
    expect(f.title).toBe('CVE-2025-6514 in mcp-remote@0.1.10');
    expect(f.vuln).toMatchObject({ versionSource: 'installed', version: '0.1.10', fixedVersion: '0.1.16', confidence: 'confirmed' });
    expect(f.description).toMatch(/does not pin a version, and npx has mcp-remote@0\.1\.10 cached on disk/);
    expect(f.description).toMatch(/connects to https:\/\/mcp\.linear\.app\/sse/);
  });

  it('recommends the exact fixed call', () => {
    const [off] = vulns(offline, 'linear-remote');
    expect(off.vuln?.fixCommand).toBe('npx -y mcp-remote@0.1.16 https://mcp.linear.app/sse');
    expect(off.remediation).toBe('Change the call to: npx -y mcp-remote@0.1.16 https://mcp.linear.app/sse');
    // Online we know the latest release, which is past the fix: recommend that.
    const [on] = vulns(online, 'linear-remote');
    expect(on.vuln?.fixCommand).toBe('npx -y mcp-remote@0.14.3 https://mcp.linear.app/sse');
  });

  it('rewrites package specs in every supported form', () => {
    const m = (command: string, args: string[], name: string, ecosystem: 'npm' | 'pypi' | 'local' = 'npm') => ({ transport: 'stdio' as const, command, args, package: { ecosystem, name, pinned: false } });
    expect(pinnedCommand(m('npx', ['-y', '@a/b@1.0.0', '--flag'], '@a/b'), '1.2.0')).toBe('npx -y @a/b@1.2.0 --flag');
    expect(pinnedCommand(m('npx', ['-y', '--package=@a/b', 'bin'], '@a/b'), '2.0.0')).toBe('npx -y --package=@a/b@2.0.0 bin');
    expect(pinnedCommand(m('uvx', ['--from', 'pkg>=1', 'cmd'], 'pkg', 'pypi'), '1.5')).toBe('uvx --from pkg==1.5 cmd');
    expect(pinnedCommand(m('uvx', ['pkg'], 'pkg', 'pypi'), '1.5')).toBe('uvx pkg==1.5');
    expect(pinnedCommand(m('node', ['/x/index.js'], '/x/index.js', 'local'), '1.0')).toBeUndefined();
  });
});

describe('NVD', () => {
  it('parses API 2.0 responses and skips rejected CVEs', () => {
    const cves = parseNvd({ vulnerabilities: [CVE_2025_6514, REJECTED] });
    expect(cves.map((c) => c.id)).toEqual(['CVE-2025-6514']);
    expect(cves[0]).toMatchObject({ cvss: { score: 9.6, severity: 'CRITICAL', version: '3.1' }, cwe: ['CWE-78'] });
    expect(cves[0].ranges[0]).toMatchObject({ product: 'mcp-remote', startIncl: '0.0.5', endExcl: '0.1.16' });
  });

  it('matches on package name or CPE product, not on look-alike names', () => {
    const [cve, other, fs] = parseNvd({ vulnerabilities: [CVE_2025_6514, OTHER_PRODUCT, FS_PHRASE] });
    expect(matchStrength(cve, 'mcp-remote')).toBe('strong');
    expect(matchStrength(other, 'mcp-remote')).toBeUndefined();
    expect(matchStrength(fs, '@modelcontextprotocol/server-filesystem')).toBe('weak');
    expect(matchStrength(fs, 'mcp-remote')).toBeUndefined();
    expect(searchTerms('@modelcontextprotocol/server-filesystem')).toEqual([
      { term: 'server-filesystem', strength: 'strong' },
      { term: 'filesystem MCP server', strength: 'weak' },
    ]);
  });

  it('does not treat a CVE for another MCP server as a match just because the words appear', () => {
    const scattered = nvdCve('CVE-2099-5001', 'A path traversal in the git MCP server lets a client escape the allowed filesystem root.');
    const otherProduct = nvdCve('CVE-2099-5002', 'Filesystem MCP Server in another project allows reading any file.', {
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:acme:acme-files-mcp:*:*:*:*:*:node.js:*:*', versionEndExcluding: '2.0' }] }] }],
    });
    const [a, b, phrase] = parseNvd({ vulnerabilities: [scattered, otherProduct, FS_PHRASE] });
    const name = '@modelcontextprotocol/server-filesystem';
    expect(matchStrength(a, name)).toBeUndefined();
    expect(matchStrength(b, name)).toBeUndefined();
    expect(matchStrength(phrase, name)).toBe('weak');
  });

  it('collapses several unconfirmed matches into one finding per package', async () => {
    const many = [1, 2, 3].map((n) => nvdCve(`CVE-2099-600${n}`, `Filesystem MCP Server issue number ${n} allows reading files.`));
    const base = { home: fx.home, platform: 'darwin' as const, systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], connectorsFile: fx.connectorsFile };
    const fetchImpl: Fetch = async (url, init) => {
      if (url.startsWith('https://services.nvd.nist.gov/') && new URL(url).searchParams.get('keywordSearch') === 'filesystem MCP server') return { ok: true, status: 200, json: async () => ({ vulnerabilities: many }) };
      return mockFetch([])(url, init);
    };
    const inv = await scan({ ...base, online: true, fetchImpl, nvdCacheFile: path.join(mkdtempSync(path.join(os.tmpdir(), 'nvd-')), 'nvd.json'), sleep: async () => {} });
    const possible = vulns(inv, 'filesystem').filter((f) => f.ruleId === 'VULN-POSSIBLE');
    expect(possible).toHaveLength(1);
    expect(possible[0].title).toMatch(/^Possibly related advisories: @modelcontextprotocol\/server-filesystem/);
    expect(possible[0].severity).toBe('low');
    expect(possible[0].description).toContain('CVE-2099-6001');
    expect(possible[0].description).toContain('CVE-2099-6003');
    expect(possible[0].references).toHaveLength(3);
  });

  it('evaluates versions from CPE ranges, then from the description', () => {
    const [cve, , , sqlite] = parseNvd({ vulnerabilities: [CVE_2025_6514, OTHER_PRODUCT, FS_PHRASE, SQLITE] });
    expect(isAffected(cve, 'mcp-remote', '0.1.10')).toEqual({ affected: true, fixed: '0.1.16' });
    expect(isAffected(cve, 'mcp-remote', '0.1.16')).toEqual({ affected: false, fixed: '0.1.16' });
    expect(isAffected(sqlite, 'mcp-server-sqlite', '0.6.2')).toEqual({ affected: true, fixed: '0.6.3' });
    expect(versionsFromDescription('Fixed in version 1.4.2. Versions 1.3 and earlier are affected.')).toEqual({ fixed: '1.4.2', lastAffected: '1.3' });
    expect(versionsFromDescription('In versions below 0.6.4 or 2025.7.01, …', '2025.6.1').fixed).toBe('2025.7.01');
  });

  it('merges NVD, OSV and bundled reports of the same CVE into one finding with CVSS', () => {
    const f = vulns(online, 'tracker');
    expect(f).toHaveLength(1);
    expect(f[0].title).toBe('CVE-2025-6514 in mcp-remote@0.1.10');
    expect(f[0].vuln).toMatchObject({
      cvss: { score: 9.6, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H' },
      versionSource: 'pinned',
      fixCommand: 'npx -y mcp-remote@0.1.16 https://mcp.tracker.dev/sse',
      cwe: ['CWE-78'],
    });
    expect(f[0].vuln?.sources.sort()).toEqual(['bundled', 'nvd', 'osv']);
    expect(f[0].references).toContain('https://nvd.nist.gov/vuln/detail/CVE-2025-6514');
  });

  it('checks uvx calls through their cached version', () => {
    const [f] = vulns(online, 'local-db');
    expect(f.title).toBe('CVE-2099-4444 in mcp-server-sqlite@0.6.2');
    expect(f.vuln).toMatchObject({ versionSource: 'installed', fixCommand: 'uvx mcp-server-sqlite==0.6.9 --db-path dev.db' });
    expect(f.severity).toBe('high');
  });

  it('reports phrase-only matches as "possible", never as confirmed', () => {
    const f = vulns(online, 'filesystem').find((x) => x.advisory === 'CVE-2099-3333')!;
    expect(f.ruleId).toBe('VULN-POSSIBLE');
    expect(f.severity).toBe('low');
    expect(f.title).toMatch(/^Possibly affected by CVE-2099-3333/);
  });

  it('respects the NVD rate limit and caches results', async () => {
    const nvdCalls = log.filter((l) => l.includes('services.nvd.nist.gov'));
    expect(nvdCalls.length).toBeGreaterThan(3);
    expect(sleeps.filter((s) => s === 6500)).toHaveLength(nvdCalls.length - 1);

    const cacheFile = path.join(mkdtempSync(path.join(os.tmpdir(), 'nvd-')), 'nvd.json');
    const opts = { home: fx.home, platform: 'darwin' as const, systemRoot: fx.systemRoot, projects: [fx.project, fx.scratch], online: true, nvdCacheFile: cacheFile, nvdApiKey: 'k', sleep: async (ms: number) => void sleeps.push(ms) };
    const first: string[] = [];
    await scan({ ...opts, fetchImpl: mockFetch(first) });
    expect(first.filter((l) => l.includes('nvd')).every((l) => l.endsWith('[key]'))).toBe(true);
    const second: string[] = [];
    await scan({ ...opts, fetchImpl: mockFetch(second) });
    expect(second.filter((l) => l.includes('nvd'))).toEqual([]);
  });

  it('keeps going when the NVD is unavailable', async () => {
    const res = await scan({
      home: fx.home, platform: 'darwin', systemRoot: fx.systemRoot, projects: [fx.scratch], online: true,
      fetchImpl: mockFetch([], 503), sleep: async () => {},
    });
    expect(res.vulnCheck?.errors).toEqual(['NVD returned HTTP 503']);
    expect(vulns(res, 'tracker').map((f) => f.advisory)).toEqual(['CVE-2025-6514']); // bundled + OSV still work
  });
});

describe('OSV', () => {
  it('queries every version a call can run and reports sources', async () => {
    const f = vulns(online, 'exa').find((x) => x.advisory === 'CVE-2099-0001')!;
    expect(f.title).toBe('CVE-2099-0001 in exa-mcp-server@3.1.0');
    expect(f.vuln).toMatchObject({ versionSource: 'latest', fixedVersion: '3.2.0', fixCommand: 'npx -y exa-mcp-server@3.2.0' });
    expect(online.findings.filter((x) => x.ruleId === 'VULN-MALICIOUS').length).toBeGreaterThanOrEqual(1);
  });

  it('reports OSV being unreachable instead of failing', async () => {
    const res = await checkOsv(
      [{ id: 'x', kind: 'mcp-server', name: 'x', origin: 'local', occurrences: [], mcp: { transport: 'stdio', package: { ecosystem: 'npm', name: 'a', version: '1.0.0', pinned: true } } } as Asset],
      async () => {
        throw new Error('ENOTFOUND api.osv.dev');
      },
    );
    expect(res.error).toMatch(/Could not reach OSV\.dev/);
  });

  it('sends only package names and versions', () => {
    const sent = log.filter((l) => !l.includes('/v1/vulns/')).join('\n');
    expect(sent).not.toContain(fx.home);
    for (const s of Object.values(SECRETS)) expect(sent).not.toContain(s);
  });
});

describe('fix commands are redacted', () => {
  it('never carries secrets from the original call', () => {
    const all = JSON.stringify(online.findings.map((f: Finding) => f.vuln));
    for (const s of Object.values(SECRETS)) expect(all).not.toContain(s);
  });
});
