import path from 'node:path';
import { promises as fs } from 'node:fs';

/**
 * Compiled code hiding among a skill's text files: programs, bytecode, macro-enabled documents.
 * Text scanners cannot read these, so they pass them silently. Files are recognised by their first
 * bytes, not by their name, which is how a program renamed notes.txt is caught.
 */

export type BinaryKind = 'machine-code' | 'bytecode' | 'macro-document';

export interface BinaryHit {
  /** Path relative to the skill folder. */
  rel: string;
  kind: BinaryKind;
  /** What it is, in plain words. */
  format: string;
  /** The file name says it is something harmless. */
  disguised: boolean;
}

const BINARY_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.node', '.bin', '.o', '.a', '.wasm', '.pyc', '.pyo', '.class', '.jar', '.docm', '.xlsm', '.pptm', '.xlam', '']);
const MACRO_EXT = new Set(['.docm', '.xlsm', '.pptm', '.xlam']);
const OOXML_EXT = new Set(['.docx', '.xlsx', '.pptx']);
const SKIP = new Set(['node_modules', '.git']);
const MAX_ENTRIES = 3000;
const MAX_DEPTH = 6;
const MAX_DOC_BYTES = 20 * 1024 * 1024;

/** Recognise a file from its first bytes (and, for Office files, the names stored inside the zip). */
export function sniff(name: string, head: Buffer, whole?: Buffer): { kind: BinaryKind; format: string } | undefined {
  const ext = path.extname(name).toLowerCase();
  const u32 = (o: number) => (head.length >= o + 4 ? head.readUInt32BE(o) : -1);
  if (u32(0) === 0x7f454c46) return { kind: 'machine-code', format: 'Linux program (ELF)' };
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(u32(0))) return { kind: 'machine-code', format: 'macOS program (Mach-O)' };
  // CAFEBABE is both a universal macOS binary and Java bytecode; the extension tells them apart.
  if (u32(0) === 0xcafebabe) return ext === '.class' ? { kind: 'bytecode', format: 'Java bytecode' } : { kind: 'machine-code', format: 'macOS program (universal binary)' };
  if (head.length >= 0x40 && head[0] === 0x4d && head[1] === 0x5a) {
    const pe = head.readUInt32LE(0x3c);
    if (pe > 0 && pe + 4 <= head.length && head.toString('latin1', pe, pe + 4) === 'PE\0\0') return { kind: 'machine-code', format: 'Windows program (PE)' };
  }
  if (head.length >= 4 && head[0] === 0x00 && head[1] === 0x61 && head[2] === 0x73 && head[3] === 0x6d) return { kind: 'machine-code', format: 'WebAssembly module' };
  if (ext === '.pyc' || ext === '.pyo' || (head.length >= 4 && head[2] === 0x0d && head[3] === 0x0a && /__pycache__/.test(name))) return { kind: 'bytecode', format: 'compiled Python (.pyc)' };
  if (ext === '.class') return { kind: 'bytecode', format: 'Java bytecode' };
  if (MACRO_EXT.has(ext)) return { kind: 'macro-document', format: 'Office document with macros' };
  if (OOXML_EXT.has(ext) && whole?.includes('vbaProject.bin')) return { kind: 'macro-document', format: 'Office document with hidden macros' };
  return undefined;
}

export async function findBinaries(root: string): Promise<BinaryHit[]> {
  const out: BinaryHit[] = [];
  let seen = 0;
  const visit = async (dir: string, depth: number) => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (++seen > MAX_ENTRIES) return;
      const full = path.join(dir, e.name);
      // Never through a symlink: a skill must not point the scan at files outside itself.
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (depth < MAX_DEPTH && !SKIP.has(e.name)) await visit(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      const rel = path.relative(root, full);
      let fh;
      try {
        fh = await fs.open(full, 'r');
        const head = Buffer.alloc(4096);
        const { bytesRead } = await fh.read(head, 0, 4096, 0);
        const size = (await fh.stat()).size;
        const ext = path.extname(e.name).toLowerCase();
        const whole = OOXML_EXT.has(ext) && size <= MAX_DOC_BYTES ? await fh.readFile() : undefined;
        const hit = sniff(rel, head.subarray(0, bytesRead), whole);
        if (hit) out.push({ rel, ...hit, disguised: ext !== '' && !BINARY_EXT.has(ext) });
      } catch {
        /* unreadable: not our concern here */
      } finally {
        await fh?.close();
      }
    }
  };
  await visit(root, 0);
  return out;
}
