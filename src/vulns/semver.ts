/**
 * Minimal version ordering for npm/PyPI release strings (1.2.3, 2025.7.1, v0.1.16).
 * Pre-release / local suffixes are ignored; that is precise enough for
 * "is this below the fixed version" checks against bundled advisories.
 */
export function parseVersion(v: string): number[] | undefined {
  const m = v.trim().replace(/^v/, '').match(/^(\d+(?:\.\d+)*)/);
  return m ? m[1].split('.').map(Number) : undefined;
}

export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a) ?? [];
  const y = parseVersion(b) ?? [];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

/**
 * Date-based (2025.7.1) and semver (0.6.4) releases of the same package can't
 * be ordered against each other; some MCP servers switched schemes.
 */
export function versionScheme(v: string): 'date' | 'semver' {
  return (parseVersion(v)?.[0] ?? 0) >= 1000 ? 'date' : 'semver';
}

/**
 * True when `version` is in [introduced, fixed). Missing bounds are open.
 * `fixed` may list one fixed version per scheme; a bound in the other scheme is ignored,
 * and if no bound matches the version's scheme at all the answer is a conservative false.
 */
export function inRange(version: string, range: { introduced?: string; fixed?: string | string[] }): boolean {
  if (!parseVersion(version)) return false;
  const s = versionScheme(version);
  const fixed = [range.fixed ?? []].flat().filter((f) => versionScheme(f) === s);
  const hasFixed = [range.fixed ?? []].flat().length > 0;
  if (hasFixed && !fixed.length) return false;
  if (range.introduced && versionScheme(range.introduced) === s && compareVersions(version, range.introduced) < 0) return false;
  if (fixed.length && compareVersions(version, fixed.sort(compareVersions)[fixed.length - 1]) >= 0) return false;
  return true;
}

/** The fixed version matching `version`'s scheme (or the first one). */
export function fixedFor(fixed: string | string[] | undefined, version?: string): string | undefined {
  const list = [fixed ?? []].flat();
  return (version && list.find((f) => versionScheme(f) === versionScheme(version))) || list[0];
}
