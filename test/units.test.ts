import { describe, expect, it } from 'vitest';
import { detectPackage, normalizeMcpEntry } from '../src/mcp.js';
import { classifySecret, redactArgs, redactText, redactUrl } from '../src/util/secrets.js';
import { stripJsonc } from '../src/util/fs.js';

describe('detectPackage', () => {
  it.each([
    ['npx', ['-y', '@scope/pkg@1.2.3'], { ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3', pinned: true }],
    ['npx', ['-y', '@scope/pkg'], { ecosystem: 'npm', name: '@scope/pkg', pinned: false }],
    ['npx', ['pkg@^1.0.0'], { ecosystem: 'npm', name: 'pkg', version: '^1.0.0', pinned: false }],
    ['npx', ['-y', '--package', 'real-pkg@2.0.0', 'bin'], { ecosystem: 'npm', name: 'real-pkg', pinned: true }],
    ['pnpm', ['dlx', 'tool@1.0.0'], { ecosystem: 'npm', name: 'tool', pinned: true }],
    ['bunx', ['tool'], { ecosystem: 'npm', name: 'tool', pinned: false }],
    ['uvx', ['mcp-server-git==0.6.2'], { ecosystem: 'pypi', name: 'mcp-server-git', version: '0.6.2', pinned: true }],
    ['uvx', ['--from', 'pkg>=1.0', 'cmd'], { ecosystem: 'pypi', name: 'pkg', pinned: false }],
    ['uvx', ['mcp-server-time'], { ecosystem: 'pypi', name: 'mcp-server-time', pinned: false }],
    ['docker', ['run', '-i', '--rm', '-e', 'TOKEN', 'mcp/github'], { ecosystem: 'docker', name: 'mcp/github', pinned: false }],
    ['docker', ['run', 'img@sha256:abc'], { ecosystem: 'docker', name: 'img', pinned: true }],
    ['docker', ['run', 'localhost:5000/img:1.0'], { ecosystem: 'docker', name: 'localhost:5000/img', version: '1.0', pinned: false }],
    ['/usr/local/bin/node', ['/opt/server/index.js'], { ecosystem: 'local', name: '/opt/server/index.js' }],
    ['/opt/bin/my-server', [], { ecosystem: 'binary', name: '/opt/bin/my-server' }],
  ])('%s %j', (cmd, args, expected) => {
    expect(detectPackage(cmd, args as string[])).toMatchObject(expected);
  });

  it('returns nothing for shells', () => {
    expect(detectPackage('bash', ['-c', 'x'])).toBeUndefined();
  });
});

describe('normalizeMcpEntry', () => {
  it('handles remote shapes', () => {
    expect(normalizeMcpEntry({ serverUrl: 'https://x/sse', type: 'sse' })?.details.transport).toBe('sse');
    expect(normalizeMcpEntry({ httpUrl: 'https://x/mcp' })?.details.transport).toBe('http');
    expect(normalizeMcpEntry({ url: 'https://x/mcp', disabled: true })?.enabled).toBe(false);
    expect(normalizeMcpEntry({})).toBeUndefined();
  });
});

describe('secrets', () => {
  it('classifies literals but not references or placeholders', () => {
    expect(classifySecret('API_KEY', 'abcd1234efgh5678')).toBeTruthy();
    expect(classifySecret('API_KEY', '${API_KEY}')).toBeUndefined();
    expect(classifySecret('API_KEY', '${env:API_KEY}')).toBeUndefined();
    expect(classifySecret('API_KEY', 'your-api-key-here')).toBeUndefined();
    expect(classifySecret('TOKEN_URL', 'https://auth.example.com/token')).toBeUndefined();
    expect(classifySecret('LOG_LEVEL', 'debug')).toBeUndefined();
    expect(classifySecret('Authorization', 'Bearer abcdefghijkl')).toBeTruthy();
    expect(classifySecret('whatever', 'ghp_' + 'a'.repeat(36))).toBe('GitHub token');
  });

  it('redacts text, args and urls', () => {
    const tok = 'sk-ant-' + 'a'.repeat(40);
    expect(redactText(`key ${tok}`)).not.toContain(tok);
    expect(redactArgs(['--api-key', 'plainsecret99'])).toEqual(['--api-key', 'plai…<redacted:13 chars>']);
    expect(redactUrl('https://u:p4ss@x.com/mcp?token=abcdefgh123&q=1')).toBe('https://u:redacted@x.com/mcp?token=redacted&q=1');
  });
});

describe('stripJsonc', () => {
  it('removes comments and trailing commas but not // in strings', () => {
    expect(JSON.parse(stripJsonc('{ // c\n "a": "http://x", /* b */ "b": [1,], }'))).toEqual({ a: 'http://x', b: [1] });
  });
});
