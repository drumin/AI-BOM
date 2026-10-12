import type { Capability } from '../types.js';

/**
 * Static capability inference for skills, agents and commands.
 *
 * Only code is inspected for behaviour: script files, and fenced code blocks
 * inside markdown. Prose that merely *mentions* curl is not a capability.
 */

const CODE_EXT = /\.(py|js|mjs|cjs|ts|sh|bash|zsh|ps1|rb|pl)$/i;

const PATTERNS: [Exclude<Capability, 'runs-scripts' | 'credential-access'>, RegExp][] = [
  ['network', /\b(curl|wget|nc|ncat)\s|requests\.(get|post|put|patch|delete)\(|\bfetch\(|\baxios\b|urllib\.request|http\.client|\bhttpx\.|Invoke-(WebRequest|RestMethod)|\bsocket\.(connect|create_connection)/],
  ['subprocess', /\bsubprocess\.|child_process|\bos\.(system|popen|exec\w*)\(|\bexecSync\(|\bspawn(Sync)?\(|\beval\s*\(|Start-Process/],
  ['file-write', /\bwriteFile(Sync)?\(|\bopen\([^)\n]*['"][wax]\+?b?['"]|\brm\s+-[a-z]*r[a-z]*\b|shutil\.rmtree|\bfs\.(unlink|rm|appendFile)|\bunlink\(|Remove-Item|\bchmod\s+[0-7]{3}/],
  ['reads-env', /process\.env\b|os\.environ|\bgetenv\(|\$\{?[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)\}?|\bprintenv\b|\benv\s*\|/],
];

export const CREDENTIAL_PATHS: RegExp[] = [
  /~\/\.ssh\b|\$HOME\/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b/,
  /\.aws\/credentials\b/,
  /\.config\/gcloud\b|application_default_credentials\.json/,
  /\.kube\/config\b/,
  /\.docker\/config\.json\b/,
  /\.(npmrc|pypirc|netrc)\b/,
  /\.config\/gh\/hosts\.yml/,
  /\bsecurity\s+(find|dump)-(generic|internet)-password\b|login\.keychain/,
  /(Google\/Chrome|BraveSoftware|Firefox\/Profiles)[^\n]*(Login Data|Cookies|logins\.json)/,
  /\bwallet\.dat\b|\/\.?(Exodus|electrum)\//i,
];

/** Endpoints commonly used to receive exfiltrated data or to tunnel out. */
export const SUSPICIOUS_HOSTS =
  /(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|pastebin\.com|paste\.ee|transfer\.sh|hastebin\.com|interact\.sh|oast\.(fun|pro|live|site|online|me)|burpcollaborator\.net|discord(app)?\.com\/api\/webhooks)$/i;

const IGNORED_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.(com|org|net)|.*\.example\.(com|org|net)|.*\.local)$/i;

export function codeOf(file: string, text: string): string {
  if (CODE_EXT.test(file)) return text;
  const blocks = text.match(/```[^\n]*\n[\s\S]*?```/g) ?? [];
  // Claude Code commands run `!`cmd`` lines as shell before the prompt is sent.
  const bang = text.match(/^!`[^`]+`/gm) ?? [];
  return [...blocks, ...bang].join('\n');
}

export interface CapabilityReport {
  capabilities: Set<Capability>;
  domains: Set<string>;
  suspiciousHosts: Set<string>;
  rawIpHosts: Set<string>;
}

export function newReport(): CapabilityReport {
  return { capabilities: new Set(), domains: new Set(), suspiciousHosts: new Set(), rawIpHosts: new Set() };
}

/** Analyze one file's text and accumulate into `r`. Returns the capabilities found in this file alone. */
export function analyzeFile(file: string, text: string, r: CapabilityReport): Set<Capability> {
  const local = new Set<Capability>();
  const code = codeOf(file, text);
  if (CODE_EXT.test(file) || /```(bash|sh|zsh|shell|console|python|py|js|javascript|ts|typescript|powershell|ps1)?\s*\n/.test(text) || /^!`/m.test(text)) {
    if (code.trim()) local.add('runs-scripts');
  }
  for (const [cap, re] of PATTERNS) if (re.test(code)) local.add(cap);
  if (CREDENTIAL_PATHS.some((re) => re.test(text))) local.add('credential-access');

  for (const m of text.matchAll(/https?:\/\/([A-Za-z0-9.-]+(?::\d+)?)(\/[^\s)"'`<>]*)?/g)) {
    const host = m[1].toLowerCase().replace(/:\d+$/, '');
    if (IGNORED_HOSTS.test(host)) continue;
    r.domains.add(host);
    if (SUSPICIOUS_HOSTS.test(host) || SUSPICIOUS_HOSTS.test(`${host}${m[2] ?? ''}`.replace(/\/[^/]*$/, ''))) r.suspiciousHosts.add(host);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && !/^(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(host)) r.rawIpHosts.add(host);
  }
  for (const c of local) r.capabilities.add(c);
  return local;
}
