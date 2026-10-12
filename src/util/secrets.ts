/**
 * Secret detection and redaction. Everything that leaves the scanner
 * (JSON, CycloneDX, the dashboard API) passes through `redact*` first.
 */

/** Well-known credential formats. Kept conservative to avoid noise. */
const TOKEN_PATTERNS: { name: string; re: RegExp }[] = [
  // `sk-` keys must start at a token boundary and contain a digit, otherwise
  // hyphenated prose such as "task-management-workflow" would match.
  { name: 'Anthropic API key', re: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key', re: /(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}/ },
  { name: 'GitHub token', re: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}/ },
  { name: 'Slack token', re: /xox[abposr]-[A-Za-z0-9-]{10,}/ },
  { name: 'AWS access key', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { name: 'Google API key', re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Stripe key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/ },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}/ },
  { name: 'GitLab token', re: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: 'Notion token', re: /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}/ },
  { name: 'Linear API key', re: /lin_api_[A-Za-z0-9]{30,}/ },
  { name: 'Private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

const SECRET_KEY_NAME = /(api[_-]?key|apikey|secret|token|passw(or)?d|pwd|credential|private[_-]?key|auth|bearer|access[_-]?key|client[_-]?secret|cookie|session)/i;

/** Names that match the pattern above but hold no secret. */
const NON_SECRET_KEY_NAME = /(_URL|_URI|_HOST|_PATH|_FILE|_DIR|_ENDPOINT|_REGION|_MODE|_ID|_TYPE|_NAME|_VERSION|_TIMEOUT|_ENABLED|_PORT)$/i;

/** Values that are references to the environment / secret stores, not literals. */
export function isReference(value: string): boolean {
  const v = value.trim();
  return (
    /^\$\{[^}]+\}$/.test(v) ||
    /^\$[A-Z_][A-Z0-9_]*$/i.test(v) ||
    /^\$\{(env|input|secret):[^}]+\}$/i.test(v) ||
    /^\{\{[^}]+\}\}$/.test(v) ||
    /^op:\/\//.test(v) || // 1Password
    /^(env|keychain):/i.test(v)
  );
}

const PLACEHOLDER = /^(|x+|\*+|<[^>]*>|your[-_ ].*|changeme|todo|placeholder|none|null|true|false|\d{1,6}|<redacted>)$/i;

export function findTokenPattern(value: string): string | undefined {
  for (const p of TOKEN_PATTERNS) if (p.re.test(value)) return p.name;
  return undefined;
}

/**
 * Decide whether a key/value pair (env var, header, settings entry) is a
 * literal secret. Returns a label describing why, or undefined.
 */
export function classifySecret(key: string, value: string): string | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim();
  if (isReference(v)) return undefined;
  const token = findTokenPattern(v);
  if (token) return token;
  if (PLACEHOLDER.test(v)) return undefined;
  if (SECRET_KEY_NAME.test(key) && !NON_SECRET_KEY_NAME.test(key) && v.length >= 8 && !/^https?:\/\//.test(v) && !v.includes(' ')) {
    return `literal value for ${key}`;
  }
  // Authorization: Bearer <literal>
  if (/^(bearer|basic|token)\s+\S{8,}$/i.test(v) && !/\$\{/.test(v)) return 'literal authorization header';
  return undefined;
}

export function maskValue(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return '<redacted>';
  return `${v.slice(0, 4)}…<redacted:${v.length} chars>`;
}

/** Redact a record of env vars / headers. References are kept verbatim. */
export function redactRecord(rec: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!rec) return rec;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) {
    out[k] = isReference(v) ? v : maskValue(v);
  }
  return out;
}

/** Replace any recognizable token inside free text. */
export function redactText(text: string): string {
  let out = text;
  for (const p of TOKEN_PATTERNS) {
    out = out.replace(new RegExp(p.re.source, 'g'), (m) => maskValue(m));
  }
  // --api-key=xxx / --token xxx style flags and key=value pairs
  out = out.replace(/((?:api[_-]?key|token|secret|password|passwd)\s*[=:]\s*)(["']?)([^\s"'&]{8,})\2/gi, (_m, pre, q, val) =>
    isReference(val) || /redacted/i.test(val) ? `${pre}${q}${val}${q}` : `${pre}${q}${maskValue(val)}${q}`,
  );
  out = out.replace(/\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{8,})/gi, (_m, scheme, sp, val) =>
    isReference(val) || /redacted/i.test(val) ? `${scheme}${sp}${val}` : `${scheme}${sp}${maskValue(val)}`,
  );
  return out;
}

/** Redact secrets carried in a URL (query string tokens, basic-auth credentials). */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = 'redacted';
    for (const [k, v] of u.searchParams) {
      if (classifySecret(k, v) || SECRET_KEY_NAME.test(k)) u.searchParams.set(k, 'redacted');
    }
    return redactText(u.toString());
  } catch {
    return redactText(url);
  }
}

/** Redact CLI args: the value after a secret-looking flag, and any token. */
export function redactArgs(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const prev = args[i - 1];
    if (prev && /^--?[\w-]*(key|token|secret|password)[\w-]*$/i.test(prev) && !isReference(a)) {
      out.push(maskValue(a));
    } else if (/^https?:\/\//.test(a)) {
      out.push(redactUrl(a));
    } else {
      out.push(redactText(a));
    }
  }
  return out;
}
