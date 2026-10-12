import path from 'node:path';
import { promises as fs } from 'node:fs';

/**
 * Which versions of a package are actually on disk.
 *
 * An unpinned call like `npx -y mcp-remote` does not necessarily run the
 * latest release: npx keeps copies in ~/.npm/_npx and can keep reusing an
 * old one. uvx does the same in uv's cache. Reading those caches tells us
 * what the call really runs, without executing anything or going online.
 */
export interface InstalledIndex {
  npm: Map<string, Set<string>>;
  pypi: Map<string, Set<string>>;
}

const MAX_ENTRIES = 3000;

async function dirs(p: string): Promise<string[]> {
  try {
    return (await fs.readdir(p, { withFileTypes: true })).filter((d) => d.isDirectory() || d.isSymbolicLink()).map((d) => d.name).slice(0, MAX_ENTRIES);
  } catch {
    return [];
  }
}

function add(map: Map<string, Set<string>>, name: string, version: string) {
  if (!map.has(name)) map.set(name, new Set());
  map.get(name)!.add(version);
}

/** PyPI names compare case-insensitively with -, _ and . equivalent (PEP 503). */
export const normalizePypi = (n: string) => n.toLowerCase().replace(/[-_.]+/g, '-');

async function npmModules(nodeModules: string, index: InstalledIndex) {
  for (const entry of await dirs(nodeModules)) {
    const names = entry.startsWith('@') ? (await dirs(path.join(nodeModules, entry))).map((n) => `${entry}/${n}`) : [entry];
    for (const name of names) {
      try {
        const pkg = JSON.parse(await fs.readFile(path.join(nodeModules, name, 'package.json'), 'utf8'));
        if (typeof pkg.version === 'string') add(index.npm, name, pkg.version);
      } catch {
        /* not a package */
      }
    }
  }
}

/** site-packages/<name>-<version>.dist-info */
async function sitePackages(root: string, index: InstalledIndex) {
  for (const lib of ['lib', 'Lib']) {
    for (const py of await dirs(path.join(root, lib))) {
      for (const d of await dirs(path.join(root, lib, py, 'site-packages'))) {
        const m = d.match(/^(.+?)-(\d[^-]*)\.dist-info$/);
        if (m) add(index.pypi, normalizePypi(m[1]), m[2]);
      }
    }
  }
}

export async function indexInstalled(home: string): Promise<InstalledIndex> {
  const index: InstalledIndex = { npm: new Map(), pypi: new Map() };
  // npx: ~/.npm/_npx/<hash>/node_modules/<pkg>
  const npx = path.join(home, '.npm', '_npx');
  for (const h of await dirs(npx)) await npmModules(path.join(npx, h, 'node_modules'), index);

  // uvx: ~/.cache/uv/archive-v0/<hash>/lib/pythonX/site-packages (same path on macOS and Linux)
  const uvArchive = path.join(home, '.cache', 'uv', 'archive-v0');
  for (const h of await dirs(uvArchive)) await sitePackages(path.join(uvArchive, h), index);
  // `uv tool install` and pipx virtualenvs
  for (const base of [path.join(home, '.local', 'share', 'uv', 'tools'), path.join(home, '.local', 'pipx', 'venvs'), path.join(home, '.local', 'share', 'pipx', 'venvs')]) {
    for (const t of await dirs(base)) await sitePackages(path.join(base, t), index);
  }
  return index;
}

export function installedVersions(index: InstalledIndex, ecosystem: 'npm' | 'pypi', name: string): string[] {
  const set = ecosystem === 'npm' ? index.npm.get(name) : index.pypi.get(normalizePypi(name));
  return set ? [...set] : [];
}
