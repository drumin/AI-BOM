import path from 'node:path';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { dataDir, writeAtomic } from '../util/store.js';

/**
 * Where secrets moved out of config files go: the macOS login Keychain
 * (`security`) or the freedesktop Secret Service on Linux (`secret-tool`).
 * Secrets are passed to those tools on stdin, never on the command line
 * (argv is visible to every process via `ps`).
 */
export interface SecretStore {
  name: string;
  available(): Promise<boolean>;
  set(service: string, secret: string): Promise<void>;
  get(service: string): Promise<string | undefined>;
  remove(service: string): Promise<void>;
  /** Shell command that prints the secret, for tools with a "helper command" setting (apiKeyHelper). */
  lookupCommand(service: string): string;
}

export const ACCOUNT = 'ai-bom';

function run(cmd: string, args: string[], input?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let child;
    try {
      child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      return resolve({ code: 127, stdout, stderr: `${cmd} not found` });
    }
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', () => resolve({ code: 127, stdout, stderr: `${cmd} not found` }));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input ?? '');
  });
}

const SAFE = /^[A-Za-z0-9._\/:@+=-]+$/;

function macKeychain(): SecretStore {
  return {
    name: 'macOS Keychain',
    available: async () => (await run('security', ['help'])).code !== 127,
    async set(service, secret) {
      // `security -i` reads commands from stdin, which keeps the secret out of argv.
      if (!SAFE.test(service) || /["\\\n\r]/.test(secret)) throw new Error('This value contains characters that cannot be stored safely; move it by hand.');
      const r = await run('security', ['-i'], `add-generic-password -U -a ${ACCOUNT} -s "${service}" -w "${secret}"\n`);
      if (r.code !== 0 || /error/i.test(r.stderr)) throw new Error(`Keychain rejected the secret: ${r.stderr.split('\n')[0]}`);
    },
    async get(service) {
      const r = await run('security', ['find-generic-password', '-a', ACCOUNT, '-s', service, '-w']);
      return r.code === 0 ? r.stdout.replace(/\n$/, '') : undefined;
    },
    async remove(service) {
      await run('security', ['delete-generic-password', '-a', ACCOUNT, '-s', service]);
    },
    lookupCommand: (service) => `security find-generic-password -a ${ACCOUNT} -s '${service}' -w`,
  };
}

function secretService(): SecretStore {
  return {
    name: 'Secret Service (secret-tool)',
    available: async () => (await run('secret-tool', ['--version'])).code !== 127,
    async set(service, secret) {
      if (!SAFE.test(service)) throw new Error('Invalid secret name.');
      const r = await run('secret-tool', ['store', `--label=${service}`, 'service', service, 'account', ACCOUNT], secret);
      if (r.code !== 0) throw new Error(`secret-tool failed: ${r.stderr.split('\n')[0]}`);
    },
    async get(service) {
      const r = await run('secret-tool', ['lookup', 'service', service, 'account', ACCOUNT]);
      return r.code === 0 && r.stdout ? r.stdout.replace(/\n$/, '') : undefined;
    },
    async remove(service) {
      await run('secret-tool', ['clear', 'service', service, 'account', ACCOUNT]);
    },
    lookupCommand: (service) => `secret-tool lookup service '${service}' account ${ACCOUNT}`,
  };
}

export function defaultSecretStore(platform = process.platform): SecretStore | undefined {
  if (platform === 'darwin') return macKeychain();
  if (platform === 'linux') return secretService();
  return undefined;
}

/** In-memory store for tests and dry runs. */
export function memoryStore(): SecretStore & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    name: 'memory',
    items,
    available: async () => true,
    set: async (s, v) => void items.set(s, v),
    get: async (s) => items.get(s),
    remove: async (s) => void items.delete(s),
    lookupCommand: (s) => `echo-secret '${s}'`,
  };
}

export const LAUNCHER_NAME = 'ai-bom-secrets';

/**
 * A tiny POSIX launcher MCP configs can point at: it loads NAME=service pairs
 * from the keychain into the environment and execs the real server command.
 */
const LAUNCHER = `#!/bin/sh
# ai-bom-secrets: load secrets from the OS keychain into environment variables,
# then run the MCP server. Written by ai-bom (https://github.com/drumin/ai-scanner).
# Usage: ai-bom-secrets NAME=service [NAME=service ...] -- command [args...]
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  name=\${1%%=*}
  service=\${1#*=}
  case "$name" in
    ''|*[!A-Za-z0-9_]*|[0-9]*) echo "ai-bom-secrets: invalid variable name: $name" >&2; exit 64 ;;
  esac
  if command -v security >/dev/null 2>&1; then
    value=$(security find-generic-password -a ${ACCOUNT} -s "$service" -w) || { echo "ai-bom-secrets: '$service' not found in Keychain" >&2; exit 1; }
  elif command -v secret-tool >/dev/null 2>&1; then
    value=$(secret-tool lookup service "$service" account ${ACCOUNT}) || { echo "ai-bom-secrets: '$service' not found in Secret Service" >&2; exit 1; }
  else
    echo "ai-bom-secrets: no keychain tool found" >&2; exit 1
  fi
  export "$name=$value"
  shift
done
[ "$1" = "--" ] && shift
exec "$@"
`;

export const launcherPath = () => path.join(dataDir(), 'bin', LAUNCHER_NAME);

/** Install (or refresh) the launcher; returns its absolute path. */
export async function ensureLauncher(): Promise<string> {
  const file = launcherPath();
  let current: string | undefined;
  try {
    current = await fs.readFile(file, 'utf8');
  } catch {
    /* not installed yet */
  }
  if (current !== LAUNCHER) await writeAtomic(file, LAUNCHER, 0o700);
  return file;
}

/** Keychain item name for a secret moved out of an MCP config. */
export function serviceName(scope: string, variable: string): string {
  return `ai-bom/${scope.replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 60)}/${variable.replace(/[^A-Za-z0-9_]/g, '_')}`;
}
