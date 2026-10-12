import path from 'node:path';
import { readSmallText } from '../util/fs.js';

/** An environment variable set in a shell startup file. */
export interface ShellExport {
  file: string;
  line: number;
  name: string;
  value: string;
  /** The value is computed ($(…), `…`, $OTHER) rather than written literally. */
  computed: boolean;
}

export const SHELL_FILES = [
  '.zshrc', '.zshenv', '.zprofile', '.bashrc', '.bash_profile', '.profile', path.join('.config', 'fish', 'config.fish'),
  // PowerShell profiles (Windows, and pwsh anywhere)
  path.join('Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1'),
  path.join('Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'),
  path.join('.config', 'powershell', 'Microsoft.PowerShell_profile.ps1'),
];

function unquote(v: string): string {
  const t = v.trim().replace(/\s+#.*$/, '');
  const m = t.match(/^(["'])([\s\S]*)\1$/);
  return m ? m[2] : t;
}

/** Parse `export NAME=value`, `NAME=value` and fish `set -gx NAME value` lines. Never evaluates anything. */
export function parseExports(file: string, text: string): ShellExport[] {
  const out: ShellExport[] = [];
  text.split('\n').forEach((raw, i) => {
    const l = raw.trim();
    if (!l || l.startsWith('#')) return;
    let m = l.match(/^(?:export\s+|declare\s+-x\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) m = l.match(/^set\s+(?:-[a-zA-Z]*x[a-zA-Z]*\s+)+([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$/);
    // PowerShell: $env:NAME = "value"  /  [Environment]::SetEnvironmentVariable("NAME", "value", …)
    if (!m) m = l.match(/^\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/i);
    if (!m) {
      const ps = l.match(/SetEnvironmentVariable\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*,\s*(["'][^"']*["'])/i);
      if (ps) m = ps;
    }
    if (!m) return;
    const rawValue = m[2];
    const value = unquote(rawValue);
    const computed = (/\$\(|`|\$\{?[A-Za-z_]|\(\s*security\b|Get-Secret|ConvertFrom-SecureString/i.test(rawValue) && !/^'[^']*'$/.test(rawValue.trim())) || /^\(/.test(rawValue.trim());
    out.push({ file, line: i + 1, name: m[1], value, computed });
  });
  return out;
}

export async function readShellExports(home: string): Promise<ShellExport[]> {
  const out: ShellExport[] = [];
  for (const f of SHELL_FILES) {
    const file = path.join(home, f);
    const text = await readSmallText(file);
    if (text) out.push(...parseExports(file, text));
  }
  return out;
}
