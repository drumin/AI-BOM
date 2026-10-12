/**
 * Small, dependency-free helpers for reading JS/TS and Python source
 * statically: bracket matching that skips strings and comments, Python
 * blocks by indentation, and extraction of function bodies by name.
 * Heuristic by design: good enough to find a tool's handler, never executed.
 */

export type Lang = 'js' | 'py';

export const langOf = (file: string): Lang | undefined =>
  /\.(m|c)?[jt]sx?$/i.test(file) && !/\.d\.ts$/i.test(file) ? 'js' : /\.py$/i.test(file) ? 'py' : undefined;

const MAX_REGION = 40_000;

/** Index just past the bracket matching the one at `open` (JS-ish syntax), or -1. */
export function matchBracket(text: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  const end = Math.min(text.length, open + MAX_REGION);
  for (let i = open; i < end; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (c === '/' && n === '/') {
      const nl = text.indexOf('\n', i);
      i = nl < 0 ? end : nl;
      continue;
    }
    if (c === '/' && n === '*') {
      const close = text.indexOf('*/', i + 2);
      i = close < 0 ? end : close + 1;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      i++;
      while (i < end && text[i] !== c) {
        if (text[i] === '\\') i++;
        else if (c !== '`' && text[i] === '\n') break;
        i++;
      }
      continue;
    }
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === ')' || c === '}' || c === ']') {
      if (stack.pop() !== c) return -1;
      if (!stack.length) return i + 1;
    }
  }
  return -1;
}

/** The indented block following the line at `index` (Python). */
export function pyBlock(text: string, index: number): string {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  const indent = (text.slice(lineStart).match(/^[ \t]*/)?.[0] ?? '').length;
  const lines = text.slice(lineStart).split('\n');
  const out = [lines[0]];
  // The def line may continue over several lines until the colon.
  let i = 1;
  let headerDone = /:\s*(#.*)?$/.test(lines[0]);
  for (; i < lines.length && !headerDone; i++) {
    out.push(lines[i]);
    headerDone = /:\s*(#.*)?$/.test(lines[i]);
  }
  for (; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() && (l.match(/^[ \t]*/)?.[0] ?? '').length <= indent) break;
    out.push(l);
    if (out.join('\n').length > MAX_REGION) break;
  }
  return out.join('\n');
}

/** First string literal in `s` (quotes, backticks, Python triple quotes). */
export function firstString(s: string): string | undefined {
  const m = s.match(/^\s*(?:[rbuf]{0,2})("""|'''|"|'|`)([\s\S]*?)(?<!\\)\1/);
  return m ? unescape(m[2]) : undefined;
}

/** A concatenation of adjacent string literals (`"a" + "b"`, or Python implicit concat). */
export function stringExpr(s: string): string | undefined {
  const parts: string[] = [];
  let rest = s;
  for (let k = 0; k < 20; k++) {
    const m = rest.match(/^\s*(?:[rbuf]{0,2})("""|'''|"|'|`)([\s\S]*?)(?<!\\)\1/);
    if (!m) break;
    parts.push(unescape(m[2]));
    rest = rest.slice(m[0].length);
    const plus = rest.match(/^\s*\+?\s*(?=["'`]|[rbuf]{1,2}["'])/);
    if (!plus) break;
    rest = rest.slice(plus[0].length);
  }
  return parts.length ? parts.join('') : undefined;
}

function unescape(s: string): string {
  return s.replace(/\\n/g, '\n').replace(/\\(["'`\\])/g, '$1').trim();
}

/** Map of function/method name -> body, for following calls one or two levels deep. */
export function functionBodies(text: string, lang: Lang): Map<string, string> {
  const out = new Map<string, string>();
  if (lang === 'py') {
    for (const m of text.matchAll(/^[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/gm)) {
      if (!out.has(m[1])) out.set(m[1], pyBlock(text, m.index!));
    }
    return out;
  }
  const patterns = [
    /\bfunction\s*\*?\s*(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{/g,
    /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*\w*\s*)?\([^)]*\)\s*(?::[^=]+)?(?:=>)?\s*\{/g,
    /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\w+\s*=>\s*\{/g,
    /^[ \t]+(?:(?:public|private|protected|static|async)\s+)*(\w+)\s*\([^)]*\)\s*(?::[^{]+)?\{/gm,
  ];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) {
      if (['if', 'for', 'while', 'switch', 'catch', 'function', 'return'].includes(m[1]) || out.has(m[1])) continue;
      const open = m.index! + m[0].length - 1;
      const close = matchBracket(text, open);
      if (close > 0) out.set(m[1], text.slice(m.index!, close));
    }
  }
  return out;
}

/** Module-level string constants (`const API = "https://…"`, `API_BASE = "…"`). */
export function stringConstants(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of text.matchAll(/(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_]\w*)\s*(?::\s*\w+\s*)?=\s*([rbuf]{0,2}["'`][^\n]{0,400})/g)) {
    const v = stringExpr(m[2]);
    if (v && !out.has(m[1])) out.set(m[1], v);
  }
  return out;
}

/** Names called in a region: `foo(`, `this.foo(`, `self.foo(`, `await foo(`. */
export function calledNames(region: string): Set<string> {
  const out = new Set<string>();
  for (const m of region.matchAll(/(?:\b|this\.|self\.)([A-Za-z_]\w*)\s*\(/g)) out.add(m[1]);
  return out;
}

/** Identifiers referenced in a region. */
export function identifiers(region: string): Set<string> {
  return new Set(region.match(/\b[A-Za-z_]\w*\b/g) ?? []);
}
