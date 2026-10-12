import path from 'node:path';
import { promises as fs } from 'node:fs';
import { parse, type ParseError } from 'jsonc-parser';
import type { Asset } from '../types.js';
import { redactLine } from '../fix/jsonedit.js';
import { classifySecret, maskValue, redactArgs } from '../util/secrets.js';
import { walkFiles } from '../util/fs.js';

export interface SourceFile {
  name: string;
  format: 'markdown' | 'json' | 'text';
  text: string;
  truncated?: boolean;
}

const TEXT = /\.(md|mdc|markdown|txt|py|js|mjs|cjs|ts|sh|bash|zsh|json|jsonc|ya?ml|toml|ps1|rb|pl)$/i;
const MAX_FILES = 12;
const MAX_FILE_CHARS = 100_000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

const formatOf = (name: string): SourceFile['format'] => (/\.(md|mdc|markdown)$/i.test(name) ? 'markdown' : /\.jsonc?$/i.test(name) ? 'json' : 'text');

function clean(text: string): { text: string; truncated: boolean } {
  const redacted = text.split('\n').map(redactLine).join('\n');
  return redacted.length > MAX_FILE_CHARS ? { text: redacted.slice(0, MAX_FILE_CHARS), truncated: true } : { text: redacted, truncated: false };
}

/** Mask secrets by structure: flag values in arg lists, and values under secret-looking keys. Line redaction alone misses `"--api-key", "value"`. */
function redactTree(v: unknown): unknown {
  if (Array.isArray(v)) return v.every((x) => typeof x === 'string') ? redactArgs(v as string[]) : v.map(redactTree);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, typeof x === 'string' ? (classifySecret(k, x) ? maskValue(x) : x) : redactTree(x)]),
    );
  }
  return v;
}

/** Pretty-print JSON with structural redaction; undefined when it does not parse (the caller then redacts line by line). */
function safeJson(raw: string): string | undefined {
  const errors: ParseError[] = [];
  const v = parse(raw, errors, { allowTrailingComma: true }) as unknown;
  return errors.length || v === undefined ? undefined : JSON.stringify(redactTree(v), null, 2);
}

/** An MCP config file holds every server; show just this one's entry. */
function serverEntry(raw: string, name: string): string | undefined {
  const root = parse(raw, [], { allowTrailingComma: true }) as unknown;
  const find = (v: unknown, depth: number): unknown => {
    if (!v || typeof v !== 'object' || depth > 4) return undefined;
    const o = v as Record<string, unknown>;
    for (const k of ['mcpServers', 'servers', 'context_servers', 'mcp_servers']) {
      const group = o[k];
      if (group && typeof group === 'object' && name in (group as object)) return (group as Record<string, unknown>)[name];
    }
    for (const child of Object.values(o)) {
      const hit = find(child, depth + 1);
      if (hit !== undefined) return hit;
    }
    return undefined;
  };
  const hit = find(root, 0);
  return hit === undefined ? undefined : JSON.stringify(redactTree({ [name]: hit }), null, 2);
}

/** The files behind an asset, redacted, for the dashboard's "view file" button. Read-only. */
export async function assetSource(a: Asset, home: string): Promise<SourceFile[]> {
  const expand = (p: string) => (p.startsWith('~/') ? path.join(home, p.slice(2)) : p);
  const out: SourceFile[] = [];
  const add = async (file: string, name: string, pick?: (raw: string) => string | undefined) => {
    if (out.length >= MAX_FILES) return;
    try {
      const st = await fs.stat(file);
      if (!st.isFile() || st.size > MAX_FILE_BYTES) return;
      const raw = await fs.readFile(file, 'utf8');
      const picked = pick?.(raw);
      const json = picked === undefined && formatOf(file) === 'json' ? safeJson(raw) : undefined;
      const shown = clean(picked ?? json ?? raw);
      out.push({ name, format: picked !== undefined ? 'json' : formatOf(file), ...shown });
    } catch {
      /* unreadable */
    }
  };

  if (a.path) {
    const root = expand(a.path);
    const st = await fs.stat(root).catch(() => undefined);
    if (st?.isDirectory()) {
      const files = (await walkFiles(root, 4, 200)).filter((f) => TEXT.test(f)).sort((x, y) => Number(/skill\.md$|readme/i.test(path.basename(y))) - Number(/skill\.md$|readme/i.test(path.basename(x))) || x.localeCompare(y));
      for (const rel of files) await add(path.join(root, rel), rel);
    } else if (st) await add(root, path.basename(root));
  }
  if (!out.length) {
    for (const src of [...new Set(a.occurrences.map((o) => o.source))]) {
      const file = expand(src);
      const st = await fs.stat(file).catch(() => undefined);
      if (st?.isDirectory()) continue;
      await add(file, path.basename(file), a.kind === 'mcp-server' && /\.jsonc?$/i.test(file) ? (raw) => serverEntry(raw, a.occurrences.find((o) => o.source === src)?.name ?? a.name) : undefined);
    }
  }
  return out;
}
