/**
 * Pure helpers for running the ai-bom CLI from the extension (no vscode import, so they can be tested).
 */

/** Split `aiBom.command` into program + arguments, honouring "double" and 'single' quotes (paths with spaces). */
export function splitCommand(input: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: '"' | "'" | undefined;
  let started = false;
  for (const ch of input.trim()) {
    if (quote) {
      if (ch === quote) quote = undefined;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started || cur) out.push(cur);
      cur = '';
      started = false;
    } else {
      cur += ch;
      started = true;
    }
  }
  if (started || cur) out.push(cur);
  return out;
}

/** Quote one argument for the integrated terminal (bash/zsh/PowerShell/cmd all accept double quotes). */
export function quoteArg(arg: string, platform: string = process.platform): string {
  if (/^[\w@%+=:,./-]+$/.test(arg)) return arg;
  return platform === 'win32' ? `"${arg.replace(/"/g, '""')}"` : `"${arg.replace(/(["\\$`])/g, '\\$1')}"`;
}

/** The terminal line for `ai-bom fix <id>` scoped to the workspace the finding came from. */
export function fixLine(command: string, id: string, folder: string | undefined, platform: string = process.platform): string {
  const tokens = [...splitCommand(command), 'fix', id];
  if (folder) tokens.push('-p', folder);
  return tokens.map((t, i) => (i === 0 && !/\s/.test(t) ? t : quoteArg(t, platform))).join(' ');
}
