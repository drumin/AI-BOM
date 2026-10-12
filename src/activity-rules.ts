import { DOWNLOAD_EXEC } from './checks/index.js';
import { CREDENTIAL_PATHS } from './checks/capabilities.js';

/**
 * Which shell commands in an agent's log deserve a flag, why, and which part of the
 * command triggered it (so the dashboard can highlight it). First matching rule wins.
 */
export interface CommandFlag {
  flag: string;
  /** One plain-language sentence: what this does and why it matters. */
  why: string;
  /** The part of the command that matched. */
  match: string;
  /** The command touched credentials: its output is never shown. */
  sensitive?: boolean;
}

const CLOUD = 'Deletes cloud or infrastructure resources';
const CLOUD_WHY = 'This removes real resources (servers, buckets, databases, clusters) and usually can’t be undone. Check it was what you asked for.';

/** Folders that are routine to delete (build output, caches, dependencies). */
const DISPOSABLE = /^(?:\.\/)?(?:node_modules|dist|build|out|\.next|\.nuxt|\.cache|\.turbo|\.parcel-cache|coverage|target|__pycache__|\.pytest_cache|\.venv|venv|tmp)\/?$/;

function riskyRm(cmd: string): string | undefined {
  for (const m of cmd.matchAll(/\brm\s+((?:-\S+\s+)+)([^\n;|&]+)/g)) {
    const flags = m[1];
    if (!/-[a-z]*r[a-z]*|--recursive/i.test(flags) || !/-[a-z]*f[a-z]*|--force/i.test(flags)) continue;
    const targets = m[2].trim().split(/\s+/).filter((t) => !t.startsWith('-'));
    if (targets.length && targets.every((t) => DISPOSABLE.test(t.replace(/^["']|["']$/g, '')))) continue;
    return m[0].trim();
  }
  return undefined;
}

const RULES: { flag: string; why: string; re: RegExp }[] = [
  { flag: CLOUD, why: CLOUD_WHY, re: /\baws\s+s3\s+(?:rm|rb)\b[^\n;|&]*(?:--recursive|--force)|\baws\s+s3\s+rb\b|\baws\s+(?:\S+\s+)?(?:delete|terminate|destroy|remove|purge|deregister)-[\w-]+/ },
  { flag: CLOUD, why: CLOUD_WHY, re: /\b(?:gcloud|az|doctl|heroku|fly|flyctl|vercel|netlify|wrangler)\s+(?:\S+\s+){0,3}(?:delete|destroy|remove)\b/ },
  { flag: CLOUD, why: CLOUD_WHY, re: /\bkubectl\s+delete\b|\bhelm\s+(?:uninstall|delete)\b|\bterraform\s+destroy\b|\bpulumi\s+destroy\b|\bterraform\s+apply\b[^\n;|&]*-auto-approve/ },
  { flag: 'Deletes database data', why: 'This drops tables or wipes rows, which can’t be undone without a backup.', re: /\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b|\bdelete\s+from\s+\w+\s*(?:;|"|'|$)|\bdropdb\b|\bFLUSHALL\b|\bdb\.dropDatabase\(/i },
  { flag: 'Overwrites remote git history', why: 'A force push replaces what teammates (or the remote) have, and can erase other people’s commits.', re: /\bgit\s+push\b[^\n;|&]*(?:--force\b|--force-with-lease\b|\s-f\b)/ },
  { flag: 'Discards uncommitted work', why: 'This throws away changes you haven’t committed, with no way to get them back.', re: /\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*f|\bgit\s+checkout\s+(?:--\s+)?\.\s*(?:$|[;&|])|\bgit\s+restore\s+\.\s*(?:$|[;&|])/ },
  { flag: 'Overwrites a disk or filesystem', why: 'Writing straight to a disk device can erase everything on it.', re: /\bdd\s+[^\n;|&]*\bof=\/dev\/|\bmkfs(?:\.\w+)?\s|>\s*\/dev\/(?:sd|nvme|disk)\w*/ },
  { flag: 'Opens file permissions to everyone', why: 'chmod 777 lets every user and program on this computer read, change and run those files.', re: /\bchmod\s+(?:-\w+\s+)*(?:-R\s+)?0?777\b|\bchmod\s+-R\s+a\+rwx\b/ },
  { flag: 'Runs with administrator rights', why: 'sudo gives the command full control of this computer, beyond what the agent normally has.', re: /\bsudo\b/ },
];

export function commandFlag(cmd: string): CommandFlag | undefined {
  for (const re of DOWNLOAD_EXEC) {
    const m = re.exec(cmd);
    if (m) return { flag: 'Downloads and runs code', why: 'It fetched a script from the internet and ran it straight away, so whatever that server sends gets executed here.', match: m[0] };
  }
  const cred = CREDENTIAL_PATHS.map((re) => re.exec(cmd)).find(Boolean);
  if (cred) {
    const send = /\b(curl|wget|nc|scp|rsync)\b|https?:\/\//.exec(cmd);
    return send
      ? { flag: 'Reads credentials and sends data out', why: 'It read a file that holds passwords or keys and the same command talks to the network, which is how secrets get stolen.', match: cred[0], sensitive: true }
      : { flag: 'Touches credential files', why: 'It accessed a file that normally holds passwords or keys.', match: cred[0], sensitive: true };
  }
  const rm = riskyRm(cmd);
  if (rm) return { flag: 'Deletes files recursively', why: '`rm -rf` removes a folder and everything inside it without asking. It can’t be undone.', match: rm };
  for (const r of RULES) {
    const m = r.re.exec(cmd);
    if (m) return { flag: r.flag, why: r.why, match: m[0] };
  }
  return undefined;
}
