import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { applyEdits, createScanner, modify, parse, SyntaxKind, type ParseError, type FormattingOptions } from 'jsonc-parser';
import { classifySecret, maskValue, redactText } from '../util/secrets.js';

export type JsonPath = (string | number)[];

export const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

export interface JsonDoc {
  file: string;
  text: string;
  data: unknown;
  hash: string;
}

/** Read a JSON/JSONC file for editing. Comments and formatting are preserved by later edits. */
export async function readJsonDoc(file: string): Promise<JsonDoc> {
  const text = await fs.readFile(file, 'utf8');
  const errors: ParseError[] = [];
  const data = parse(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length) throw new Error(`${file} is not valid JSON; fix it by hand first.`);
  return { file, text, data, hash: sha256(text) };
}

export function getAt(data: unknown, p: JsonPath): unknown {
  let cur = data;
  for (const k of p) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string | number, unknown>)[k];
  }
  return cur;
}

export function hasAt(data: unknown, p: JsonPath): boolean {
  if (!p.length) return true;
  const parent = getAt(data, p.slice(0, -1));
  const last = p[p.length - 1];
  if (Array.isArray(parent)) return typeof last === 'number' && last >= 0 && last < parent.length;
  return !!parent && typeof parent === 'object' && Object.prototype.hasOwnProperty.call(parent, last);
}

function formatting(text: string): FormattingOptions {
  const m = text.match(/\n([ \t]+)"/);
  const indent = m?.[1] ?? '  ';
  return { insertSpaces: !indent.includes('\t'), tabSize: indent.includes('\t') ? 1 : indent.length, eol: text.includes('\r\n') ? '\r\n' : '\n' };
}

/**
 * Set (value !== undefined) or remove (value === undefined) the node at `p`,
 * keeping the rest of the file byte-for-byte. `insert` inserts into an array
 * at the index instead of replacing.
 */
export function editText(text: string, p: JsonPath, value: unknown, insert = false): string {
  const attempt = (src: string) => {
    const out = applyEdits(src, modify(src, p, value, { formattingOptions: formatting(src), isArrayInsertion: insert }));
    const errors: ParseError[] = [];
    parse(out, errors, { allowTrailingComma: true });
    return errors.length ? undefined : out;
  };
  // jsonc-parser can leave a dangling comma when removing the last member of an object that
  // ends in a trailing comma (common in VS Code / Windsurf configs); retry without trailing commas.
  const out = attempt(text) ?? attempt(stripTrailingCommas(text));
  if (out === undefined) throw new Error('The edit would produce invalid JSON; nothing was changed.');
  return out;
}

/** Remove commas directly before a closing brace/bracket, leaving strings and comments untouched. */
export function stripTrailingCommas(text: string): string {
  const sc = createScanner(text, false);
  const drop: number[] = [];
  let pendingComma = -1;
  for (let k = sc.scan(); k !== SyntaxKind.EOF; k = sc.scan()) {
    if (k === SyntaxKind.Trivia || k === SyntaxKind.LineBreakTrivia || k === SyntaxKind.LineCommentTrivia || k === SyntaxKind.BlockCommentTrivia) continue;
    if ((k === SyntaxKind.CloseBraceToken || k === SyntaxKind.CloseBracketToken) && pendingComma >= 0) drop.push(pendingComma);
    pendingComma = k === SyntaxKind.CommaToken ? sc.getTokenOffset() : -1;
  }
  let out = text;
  for (const i of drop.reverse()) out = out.slice(0, i) + out.slice(i + 1);
  return out;
}

export function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).sort(([x], [y]) => x.localeCompare(y)).map(([k, x]) => [k, sortKeys(x)]));
  return v;
}

/** A compact line diff (changed region plus two lines of context), with secrets redacted. */
export function lineDiff(before: string, after: string, context = 2): string {
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length - 1;
  let endB = b.length - 1;
  while (endA >= start && endB >= start && a[endA] === b[endB]) {
    endA--;
    endB--;
  }
  const out: string[] = [];
  const from = Math.max(0, start - context);
  out.push(`@@ line ${from + 1} @@`);
  for (let i = from; i < start; i++) out.push(`  ${a[i]}`);
  for (let i = start; i <= endA; i++) out.push(`- ${a[i]}`);
  for (let i = start; i <= endB; i++) out.push(`+ ${b[i]}`);
  for (let i = endA + 1; i <= Math.min(a.length - 1, endA + context); i++) out.push(`  ${a[i]}`);
  const lines = out.map(redactLine);
  // ~/.claude.json can have enormous lines; keep the preview readable.
  return lines.map((l) => (l.length > 400 ? `${l.slice(0, 399)}…` : l)).slice(0, 120).join('\n');
}

/** Redact `"KEY": "value"` pairs whose value is a literal secret, plus known token formats. */
export function redactLine(line: string): string {
  const pairs = line.replace(/"([^"\\]{1,100})"(\s*:\s*)"((?:[^"\\]|\\.)*)"/g, (m, k: string, sep: string, v: string) =>
    classifySecret(k, v) ? `"${k}"${sep}"${maskValue(v)}"` : m,
  );
  return redactText(pairs);
}

/**
 * The one region of a file a fix changed, so undo can put the original bytes back
 * (formatting included) instead of re-deriving them from values. Only that region is
 * kept, never the whole file, and any secret in it is swapped for a placeholder.
 */
export interface Splice {
  file: string;
  start: number;
  /** Original text of the region (secrets as placeholders). */
  removed: string;
  /** Text the fix wrote in its place. */
  inserted: string;
  beforeHash: string;
  afterHash: string;
}

export const secretPlaceholder = (service: string) => `\u0000ai-bom-secret:${service}\u0000`;

/** Returns undefined when a secret cannot be kept out of the stored region; undo then works from values. */
export function makeSplice(file: string, before: string, after: string, secrets: Map<string, string>): Splice | undefined {
  let start = 0;
  const max = Math.min(before.length, after.length);
  while (start < max && before[start] === after[start]) start++;
  let tail = 0;
  while (tail < max - start && before[before.length - 1 - tail] === after[after.length - 1 - tail]) tail++;
  let removed = before.slice(start, before.length - tail);
  const inserted = after.slice(start, after.length - tail);
  for (const [service, secret] of secrets) {
    if (!secret) continue;
    removed = removed.split(JSON.stringify(secret)).join(secretPlaceholder(service));
    if (removed.includes(secret) || inserted.includes(secret)) return undefined;
  }
  return { file, start, removed, inserted, beforeHash: sha256(before), afterHash: sha256(after) };
}

/** The file as it was before the fix, or undefined if it changed since or cannot be rebuilt exactly. */
export async function restoreSplice(sp: Splice, current: string, secretFor: (service: string) => Promise<string | undefined>): Promise<string | undefined> {
  if (sha256(current) !== sp.afterHash || current.slice(sp.start, sp.start + sp.inserted.length) !== sp.inserted) return undefined;
  let removed = sp.removed;
  for (const m of new Set(removed.match(/\u0000ai-bom-secret:[^\u0000]+\u0000/g) ?? [])) {
    const value = await secretFor(m.slice('\u0000ai-bom-secret:'.length, -1));
    if (value === undefined) return undefined;
    removed = removed.split(m).join(JSON.stringify(value));
  }
  const out = current.slice(0, sp.start) + removed + current.slice(sp.start + sp.inserted.length);
  return sha256(out) === sp.beforeHash ? out : undefined;
}
