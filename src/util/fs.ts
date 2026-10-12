import { promises as fs } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';

/** Skill/rule content bigger than this is not scanned (it is prose or small scripts). */
export const MAX_FILE_BYTES = 1024 * 1024;
/**
 * Config files can be much larger: ~/.claude.json keeps per-project history
 * and regularly grows past several MB. Skipping it would silently hide MCP servers.
 */
export const MAX_CONFIG_BYTES = 64 * 1024 * 1024;

export class TooLargeError extends Error {}

export async function mtime(p: string): Promise<string | undefined> {
  try {
    return (await fs.stat(p)).mtime.toISOString();
  } catch {
    return undefined;
  }
}

export async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

export async function isDir(p: string): Promise<boolean> {
  try {
    return (await fs.stat(p)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Read a text file; undefined if missing or not a file. Files over `limit`
 * throw TooLargeError so callers can report them instead of silently skipping.
 */
export async function readText(p: string, limit = MAX_FILE_BYTES): Promise<string | undefined> {
  let st;
  try {
    st = await fs.stat(p);
  } catch {
    return undefined;
  }
  if (!st.isFile()) return undefined;
  if (st.size > limit) throw new TooLargeError(`${path.basename(p)} is ${(st.size / 1048576).toFixed(1)} MB; skipped (limit ${(limit / 1048576).toFixed(0)} MB)`);
  try {
    return await fs.readFile(p, 'utf8');
  } catch {
    return undefined;
  }
}

/** Like readSmallText, but says why nothing came back when the file exists and was too large to read. */
export async function readTextChecked(p: string): Promise<{ text?: string; skipped?: string }> {
  try {
    return { text: await readText(p) };
  } catch (e) {
    return e instanceof TooLargeError ? { skipped: e.message } : {};
  }
}

/** Most files listed per skill; a skill with more is only partly inspected. */
export const SKILL_FILE_CAP = 200;

/** Like readText, but returns undefined for oversized files (used for content checks). */
export async function readSmallText(p: string): Promise<string | undefined> {
  try {
    return await readText(p);
  } catch {
    return undefined;
  }
}

export async function listDir(p: string): Promise<string[]> {
  try {
    return await fs.readdir(p);
  } catch {
    return [];
  }
}

/** Remove // and /* comments and trailing commas (VS Code, Zed, Cursor use JSONC). */
export function stripJsonc(text: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (inString) {
      out += c;
      if (c === '\\') {
        out += n ?? '';
        i++;
      } else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
    } else if (c === '/' && n === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && n === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i++;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

export class ParseError extends Error {}

/**
 * Parser errors quote the offending source (JSON.parse: `"…" is not valid JSON`,
 * YAML/TOML: a code frame). The broken line is often the one holding a key, so
 * keep only the first line with quoted excerpts removed.
 */
export function safeParseMessage(message: string): string {
  let first = message.split('\n')[0];
  // JSON.parse: `Unexpected token 's', "{"k": sk-ant-api"... is not valid JSON` — drop the excerpt entirely.
  if (/is not valid JSON/.test(first)) first = first.replace(/,?\s*["'].*$/, '');
  return first.replace(/(["'`]).{12,}?\1/g, '"…"').trim();
}

export async function readStructured(p: string): Promise<unknown | undefined> {
  const text = await readText(p, MAX_CONFIG_BYTES);
  if (text === undefined) return undefined;
  if (!text.trim()) return {};
  const ext = path.extname(p).toLowerCase();
  try {
    if (ext === '.yaml' || ext === '.yml') return YAML.parse(text);
    if (ext === '.toml') return parseToml(text);
    try {
      return JSON.parse(text);
    } catch {
      return JSON.parse(stripJsonc(text));
    }
  } catch (e) {
    throw new ParseError(`Could not parse ${path.basename(p)}: ${safeParseMessage((e as Error).message)}`);
  }
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export function asStringArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.filter((x): x is string => typeof x === 'string');
}

export function asStringRecord(v: unknown): Record<string, string> | undefined {
  if (!isObject(v)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) {
    if (val === null || val === undefined) continue;
    out[k] = typeof val === 'string' ? val : JSON.stringify(val);
  }
  return out;
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.venv',
  'venv',
  '__pycache__',
  'dist',
  'build',
  '.next',
  'target',
  '.cache',
  'Library',
]);

/**
 * List files under `root` (relative paths), bounded by depth and count.
 * Symlinks are followed (skills are often symlinked in from a repo); the
 * real path of every visited directory is tracked so cycles terminate.
 */
export async function walkFiles(root: string, maxDepth = 4, maxFiles = 200): Promise<string[]> {
  const out: string[] = [];
  const seen = new Set<string>();
  async function visit(dir: string, depth: number) {
    if (out.length >= maxFiles) return;
    try {
      const real = await fs.realpath(dir);
      if (seen.has(real)) return;
      seen.add(real);
    } catch {
      return;
    }
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      const full = path.join(dir, e.name);
      let isDirectory = e.isDirectory();
      let isFile = e.isFile();
      if (e.isSymbolicLink()) {
        try {
          const st = await fs.stat(full);
          isDirectory = st.isDirectory();
          isFile = st.isFile();
        } catch {
          continue; // dangling link
        }
      }
      if (isDirectory) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name)) await visit(full, depth + 1);
      } else if (isFile) {
        out.push(path.relative(root, full));
      }
    }
  }
  await visit(root, 0);
  return out.sort();
}

/**
 * Find directories under `root` that look like projects with AI config.
 * Used by `--discover` to sweep a folder such as ~/code.
 */
export async function discoverProjects(root: string, markers: string[], maxDepth = 4): Promise<string[]> {
  const found: string[] = [];
  async function visit(dir: string, depth: number) {
    for (const m of markers) {
      if (await exists(path.join(dir, m))) {
        found.push(dir);
        break;
      }
    }
    if (depth >= maxDepth) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() || SKIP_DIRS.has(e.name)) continue;
      if (e.name.startsWith('.') ) continue;
      await visit(path.join(dir, e.name), depth + 1);
    }
  }
  await visit(root, 0);
  return found;
}
