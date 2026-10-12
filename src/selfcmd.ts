import path from 'node:path';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * A command line that runs this ai-bom again later (from a hook, launchd or
 * systemd). Uses absolute paths to node and the built CLI so it works with a
 * minimal PATH. Warns when running from the npx cache, which can be cleaned.
 */
export function selfInvocation(): { node: string; cli: string; ephemeral: boolean } {
  const here = realpathSync(fileURLToPath(import.meta.url));
  // dist/selfcmd.js -> dist/cli.js ; src/selfcmd.ts (tsx) -> dist/cli.js
  const cli = here.endsWith('.ts') ? path.resolve(path.dirname(here), '..', 'dist', 'cli.js') : path.join(path.dirname(here), 'cli.js');
  return { node: process.execPath, cli, ephemeral: /[\\/]_npx[\\/]/.test(cli) };
}

const q = (s: string) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function selfCommand(args: string[]): string {
  const { node, cli } = selfInvocation();
  return [node, cli, ...args].map(q).join(' ');
}
