/**
 * Does this code arrange to keep running, or to change your AI tools' settings, after the skill is gone?
 * Looks only at code (scripts, and fenced blocks in Markdown), never at prose, and only at *writes*:
 * reading a shell profile or listing cron jobs is normal; appending to one is the hallmark of persistence.
 */

export type PersistenceKind = 'shell-profile' | 'ssh-keys' | 'cron' | 'launchd' | 'systemd' | 'git-hook' | 'agent-config';

export interface PersistenceHit {
  kind: PersistenceKind;
  severity: 'high' | 'medium';
  /** What it does, in plain words. */
  what: string;
  index: number;
}

const HOME = String.raw`(?:~|\$\{?HOME\}?|\$\{?USERPROFILE\}?|/Users/[^/\s'"]+|/home/[^/\s'"]+)`;

const TARGETS: { kind: PersistenceKind; severity: PersistenceHit['severity']; what: string; target: string; codeTarget?: string }[] = [
  { kind: 'ssh-keys', severity: 'high', what: 'adds an SSH key that lets someone log in to your machine', target: String.raw`${HOME}/\.ssh/authorized_keys2?`, codeTarget: String.raw`['"/]authorized_keys2?\b` },
  { kind: 'agent-config', severity: 'high', what: 'rewrites an AI tool\'s settings or hooks', target: String.raw`(?:(?:${HOME}|\.)/)?\.claude/settings(?:\.local)?\.json|${HOME}/\.claude\.json|(?:(?:${HOME}|\.)/)?\.cursor/hooks\.json|(?:(?:${HOME}|\.)/)?\.codex/config\.toml|(?:(?:${HOME}|\.)/)?\.gemini/settings\.json|(?:(?:${HOME}|\.)/)?\.vscode/tasks\.json` },
  { kind: 'agent-config', severity: 'medium', what: 'adds an MCP server to an AI tool', target: String.raw`(?:(?:${HOME}|\.)/)?\.cursor/mcp\.json|(?:(?:${HOME}|\.)/)?\.vscode/mcp\.json|(?:(?:${HOME}|\.)/)?\.mcp\.json` },
  { kind: 'cron', severity: 'high', what: 'schedules itself to run again', target: String.raw`/etc/cron\.\w+/\S+|/etc/crontab|/var/spool/cron/\S+` },
  { kind: 'launchd', severity: 'high', what: 'installs a macOS background job that starts at login', target: String.raw`(?:${HOME})?/Library/Launch(?:Agents|Daemons)/\S+` },
  { kind: 'systemd', severity: 'high', what: 'installs a background service', target: String.raw`${HOME}/\.config/systemd/user/\S+|/etc/systemd/system/\S+` },
  { kind: 'git-hook', severity: 'high', what: 'plants a git hook that runs when you commit or pull', target: String.raw`\.git/hooks/[\w.-]+` },
  { kind: 'shell-profile', severity: 'medium', what: 'edits your shell startup file, so it runs in every new terminal', target: String.raw`${HOME}/\.(?:zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|bash_login|profile)|${HOME}/\.config/fish/config\.fish`, codeTarget: String.raw`['"/]\.(?:zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|bash_login|profile)\b` },
];

/** A shell write whose destination is the target: redirect, tee, sed -i, or cp/mv/install with the target last. */
const shellWrite = (t: string) =>
  new RegExp(
    String.raw`(?:>>?\s*["']?(?:${t})|\btee\s+(?:-\w+\s+)*["']?(?:${t})|\bsed\s+-i\S*\s+[^\n]*?["']?(?:${t})|\b(?:cp|mv|install)\s+(?:-\w+\s+)*\S+\s+["']?(?:${t})["']?\s*(?:$|[;&|)]))`,
    'im',
  );

/** Script writes: open(...,'a'), writeFileSync(...), Path(...).write_text(...), with the target on the same line. */
const codeWrite = (t: string) =>
  new RegExp(String.raw`(?:\bopen\s*\(|\bappendFile(?:Sync)?\s*\(|\bwriteFile(?:Sync)?\s*\(|\.write_text\s*\()[^\n]*?(?:${t})|(?:${t})[^\n]*?(?:\.write_text\s*\(|\.write\s*\()`, 'im');

const COMMANDS: { kind: PersistenceKind; what: string; re: RegExp }[] = [
  // Installing a crontab (`crontab -`, `crontab file`, `... | crontab -`); `crontab -l/-r/-e` are not installs.
  { kind: 'cron', what: 'schedules itself to run again', re: /\bcrontab\s+(?:-\s*(?:$|[;&|)])|(?!-)[^\s;&|]+)|\|\s*crontab\s+-/im },
  { kind: 'launchd', what: 'installs a macOS background job that starts at login', re: /\blaunchctl\s+(?:load|bootstrap|submit|enable)\b/i },
  { kind: 'systemd', what: 'installs a background service', re: /\bsystemctl\s+(?:--user\s+)?(?:enable|link)\b/i },
  { kind: 'git-hook', what: 'points git at a hooks folder it controls', re: /\bgit\s+config\b[^\n]*\bcore\.hooksPath\b/i },
];

/** Keep only code: whole file for scripts, only fenced blocks for Markdown. Offsets and line breaks are preserved. */
export function codeOnly(text: string, isCode: boolean, isMarkdown: boolean): string {
  if (isCode) return text;
  if (!isMarkdown) return '';
  let inFence = false;
  return text
    .split('\n')
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) {
        inFence = !inFence;
        return ' '.repeat(line.length);
      }
      return inFence ? line : ' '.repeat(line.length);
    })
    .join('\n');
}

export function findPersistence(code: string): PersistenceHit[] {
  const hits: PersistenceHit[] = [];
  const seen = new Set<string>();
  const add = (kind: PersistenceKind, severity: PersistenceHit['severity'], what: string, index: number) => {
    if (seen.has(what)) return;
    seen.add(what);
    hits.push({ kind, severity, what, index });
  };
  for (const t of TARGETS) {
    const m = shellWrite(t.target).exec(code) ?? codeWrite(t.codeTarget ? `${t.target}|${t.codeTarget}` : t.target).exec(code);
    if (m) add(t.kind, t.severity, t.what, m.index);
  }
  for (const c of COMMANDS) {
    const m = c.re.exec(code);
    if (m) add(c.kind, 'high', c.what, m.index);
  }
  return hits.sort((a, b) => a.index - b.index);
}
