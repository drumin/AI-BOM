import { describe, expect, it } from 'vitest';
import os from 'node:os';
import path from 'node:path';
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { findBinaries, sniff } from '../src/checks/binaries.js';
import { preflight } from '../src/preflight.js';

const elf = () => Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(120)]);
const macho = (magic = [0xcf, 0xfa, 0xed, 0xfe]) => Buffer.concat([Buffer.from(magic), Buffer.alloc(120)]);
const pe = () => {
  const b = Buffer.alloc(0x100);
  b.write('MZ', 0, 'latin1');
  b.writeUInt32LE(0x80, 0x3c);
  b.write('PE\0\0', 0x80, 'latin1');
  return b;
};
const wasm = () => Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), Buffer.alloc(32)]);
const png = () => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
const zipWith = (inner: string) => Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), Buffer.from(`word/document.xml ${inner} [Content_Types].xml`)]);

describe('recognising files by content', () => {
  it('knows programs, bytecode and WebAssembly', () => {
    expect(sniff('a', elf())).toMatchObject({ kind: 'machine-code', format: expect.stringContaining('ELF') });
    expect(sniff('a', macho())).toMatchObject({ kind: 'machine-code', format: expect.stringContaining('Mach-O') });
    expect(sniff('a', macho([0xca, 0xfe, 0xba, 0xbe]))).toMatchObject({ kind: 'machine-code' });
    expect(sniff('A.class', macho([0xca, 0xfe, 0xba, 0xbe]))).toMatchObject({ kind: 'bytecode', format: 'Java bytecode' });
    expect(sniff('a', pe())).toMatchObject({ kind: 'machine-code', format: expect.stringContaining('PE') });
    expect(sniff('a', wasm())).toMatchObject({ kind: 'machine-code', format: 'WebAssembly module' });
    expect(sniff('__pycache__/m.cpython-311.pyc', Buffer.from([0xa7, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]))).toMatchObject({ kind: 'bytecode' });
  });
  it('does not mistake an "MZ" text file or ordinary media for a program', () => {
    expect(sniff('notes.txt', Buffer.from('MZ is a prefix in this note, nothing more.'))).toBeUndefined();
    expect(sniff('a.png', png())).toBeUndefined();
    expect(sniff('a.pdf', Buffer.from('%PDF-1.7\n'))).toBeUndefined();
    expect(sniff('run.sh', Buffer.from('#!/bin/sh\necho hi\n'))).toBeUndefined();
  });
  it('finds macros in Office files, named openly or hidden inside a .docx', () => {
    expect(sniff('a.docm', Buffer.from('PK'))).toMatchObject({ kind: 'macro-document' });
    expect(sniff('a.docx', Buffer.from('PK'), zipWith('word/vbaProject.bin'))).toMatchObject({ kind: 'macro-document' });
    expect(sniff('a.docx', Buffer.from('PK'), zipWith('word/styles.xml'))).toBeUndefined();
  });
});

describe('walking a skill folder', () => {
  const skillDir = () => mkdtempSync(path.join(os.tmpdir(), 'ai-bom-bin-'));
  const put = (root: string, rel: string, data: Buffer | string) => {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    writeFileSync(path.join(root, rel), data);
  };

  it('reports what it finds, marks disguised files, and looks inside __pycache__', async () => {
    const dir = skillDir();
    put(dir, 'bin/tool', elf());
    put(dir, 'notes.txt', elf());
    put(dir, 'lib/helper.dylib', macho());
    put(dir, '__pycache__/util.cpython-311.pyc', Buffer.from([0xa7, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]));
    put(dir, 'logo.png', png());
    put(dir, 'run.sh', '#!/bin/sh\necho hi\n');
    chmodSync(path.join(dir, 'run.sh'), 0o755);
    const hits = await findBinaries(dir);
    expect(hits.map((h) => `${h.rel}${h.disguised ? '!' : ''}`).sort()).toEqual(['__pycache__/util.cpython-311.pyc', 'bin/tool', 'lib/helper.dylib', 'notes.txt!']);
  });

  it('does not follow a symlink to a program outside the skill', async () => {
    const outside = skillDir();
    put(outside, 'evil', elf());
    const dir = skillDir();
    put(dir, 'SKILL.md', 'x');
    symlinkSync(path.join(outside, 'evil'), path.join(dir, 'tool'));
    symlinkSync(outside, path.join(dir, 'linked'));
    expect(await findBinaries(dir)).toEqual([]);
  });
});

describe('in a skill', () => {
  const FM = '---\nname: s\ndescription: a skill\n---\nDoes a thing.\n';
  const run = async (files: Record<string, Buffer | string>) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-binskill-'));
    for (const [rel, data] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), data);
    }
    return preflight(dir, { home: mkdtempSync(path.join(os.tmpdir(), 'h-')), sessionLogs: false });
  };
  const bins = (r: Awaited<ReturnType<typeof run>>) => r.inventory.findings.filter((f) => f.ruleId === 'SKILL-BINARY');

  it('calls a disguised program dangerous, and a visible one "review"', async () => {
    const disguised = await run({ 'SKILL.md': FM, 'reference.txt': elf() });
    expect(bins(disguised).map((f) => f.severity)).toEqual(['high']);
    expect(bins(disguised)[0].evidence).toBe('reference.txt is really a Linux program (ELF)');
    expect(disguised.verdict).toBe('dangerous');
    await disguised.cleanup();

    const visible = await run({ 'SKILL.md': FM, 'bin/convert': macho() });
    expect(bins(visible).map((f) => f.severity)).toEqual(['medium']);
    expect(visible.verdict).toBe('review');
    await visible.cleanup();
  });

  it('lists at most five, then says how many more', async () => {
    const files: Record<string, Buffer | string> = { 'SKILL.md': FM };
    for (let i = 0; i < 8; i++) files[`b/p${i}`] = elf();
    const r = await run(files);
    expect(bins(r)).toHaveLength(6);
    expect(bins(r).find((f) => f.severity === 'low')!.evidence).toBe('3 more compiled files not listed');
    await r.cleanup();
  });

  it('stays quiet for a skill of text, images and scripts', async () => {
    const r = await run({ 'SKILL.md': FM, 'assets/logo.png': png(), 'scripts/run.sh': '#!/bin/sh\necho hi\n', 'ref.pdf': '%PDF-1.7\n' });
    expect(bins(r)).toHaveLength(0);
    expect(r.verdict).toBe('safe');
    await r.cleanup();
  });
});
