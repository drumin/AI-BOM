import type { McpServerDetails } from '../types.js';
import { compareVersions } from './semver.js';

/**
 * Rewrite an MCP server invocation so it runs `version` of its package,
 * keeping every other argument. Returns undefined if the package spec
 * cannot be located in the arguments (e.g. a local script).
 */
export function pinnedCommand(m: McpServerDetails, version: string): string | undefined {
  const args = pinnedArgs(m, version);
  return args && [m.command, ...args].join(' ');
}

/** The argument list of `pinnedCommand`, for editing configs. */
export function pinnedArgs(m: McpServerDetails, version: string): string[] | undefined {
  const p = m.package;
  if (!p || !m.command || (p.ecosystem !== 'npm' && p.ecosystem !== 'pypi')) return undefined;
  const args = [...(m.args ?? [])];
  const isSpec = (a: string) =>
    p.ecosystem === 'npm'
      ? a === p.name || a.startsWith(`${p.name}@`)
      : a === p.name || new RegExp(`^${p.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*(==|>=|<=|~=|>|<|@)`).test(a);
  let i = args.findIndex(isSpec);
  // npx --package=name@x / -p name@x, uvx --from name==x
  if (i < 0) {
    const flag = args.findIndex((a, j) => ['-p', '--package', '--from'].includes(a) && isSpec(args[j + 1] ?? ''));
    if (flag >= 0) i = flag + 1;
  }
  if (i < 0) {
    const eq = args.findIndex((a) => a.startsWith('--package=') && isSpec(a.slice(10)));
    if (eq >= 0) {
      args[eq] = `--package=${p.name}@${version}`;
      return args;
    }
    return undefined;
  }
  args[i] = p.ecosystem === 'npm' ? `${p.name}@${version}` : `${p.name}==${version}`;
  return args;
}

/** Upgrade target: the latest release when it is at least the fixed version, else the fixed version. */
export function upgradeTarget(fixed?: string, latest?: string): string | undefined {
  if (!fixed) return latest;
  if (latest && compareVersions(latest, fixed) >= 0) return latest;
  return fixed;
}
