import { describe, expect, it } from 'vitest';
import { fixLine, quoteArg, splitCommand } from '../extensions/vscode/src/command.js';

describe('VS Code extension command handling', () => {
  it('splits a plain command on spaces', () => {
    expect(splitCommand('ai-bom')).toEqual(['ai-bom']);
    expect(splitCommand('  node  /opt/ai-bom/cli.js ')).toEqual(['node', '/opt/ai-bom/cli.js']);
  });

  it('keeps paths with spaces together when quoted', () => {
    expect(splitCommand('node "/Users/Jane Doe/ai-scanner/dist/cli.js"')).toEqual(['node', '/Users/Jane Doe/ai-scanner/dist/cli.js']);
    expect(splitCommand("'/Program Files/nodejs/node.exe' cli.js")).toEqual(['/Program Files/nodejs/node.exe', 'cli.js']);
    expect(splitCommand('ai-bom ""')).toEqual(['ai-bom', '']);
    expect(splitCommand('')).toEqual([]);
  });

  it('quotes terminal arguments only when needed', () => {
    expect(quoteArg('abc123', 'darwin')).toBe('abc123');
    expect(quoteArg('/Users/Jane Doe/my project', 'darwin')).toBe('"/Users/Jane Doe/my project"');
    expect(quoteArg('/tmp/a$b"c', 'darwin')).toBe('"/tmp/a\\$b\\"c"');
    expect(quoteArg('C:\\Users\\Jane Doe\\proj', 'win32')).toBe('"C:\\Users\\Jane Doe\\proj"');
  });

  it('builds a fix line that names the workspace', () => {
    expect(fixLine('ai-bom', '3a5d0365ca85', '/work/app', 'darwin')).toBe('ai-bom fix 3a5d0365ca85 -p /work/app');
    expect(fixLine('node "/Users/Jane Doe/cli.js"', 'abc', '/Users/Jane Doe/app', 'darwin')).toBe('node "/Users/Jane Doe/cli.js" fix abc -p "/Users/Jane Doe/app"');
    expect(fixLine('ai-bom', 'abc', undefined, 'darwin')).toBe('ai-bom fix abc');
  });
});
