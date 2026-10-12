/** `~` for the home folder, matched on a folder boundary so /Users/dru does not match /Users/drumin. */
export function tilde(p: string, home: string): string {
  if (!home || !p.startsWith(home)) return p;
  const next = p[home.length];
  return next === undefined ? '~' : next === '/' || next === '\\' ? `~${p.slice(home.length)}` : p;
}

/** Inverse of `tilde` for every string in a value: `~`, `~/x` and `~\x` (Windows) become real paths. */
export function untildeDeep<T>(value: T, home: string): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return v === '~' || /^~[\\/]/.test(v) ? home + v.slice(1) : v;
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}
