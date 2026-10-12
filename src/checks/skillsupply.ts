import { levenshtein } from '../trust/index.js';

/**
 * Supply-chain checks for what a skill or plugin brings with it: a name that imitates a well-known one,
 * dependencies it lists that imitate popular packages, and dependencies left floating.
 * Lists are deliberately short and conservative: a name must be one edit away from a long, well-known
 * name to count, so ordinary short words never match.
 */

/** Names of widely used skills and plugins (Anthropic's published skills and popular plugins). */
export const KNOWN_SKILLS = [
  'skill-creator', 'mcp-builder', 'webapp-testing', 'frontend-design', 'canvas-design', 'algorithmic-art', 'brand-guidelines',
  'theme-factory', 'doc-coauthoring', 'web-artifacts-builder', 'internal-comms', 'slack-gif-creator',
  'superpowers', 'code-review', 'feature-dev', 'commit-commands', 'pr-review-toolkit', 'security-guidance', 'plugin-dev', 'agent-sdk-dev', 'hookify',
];

export const KNOWN_PY = [
  'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'boto3', 'pyyaml', 'cryptography', 'beautifulsoup4', 'openai', 'anthropic',
  'langchain', 'pydantic', 'pytest', 'setuptools', 'pillow', 'scipy', 'matplotlib', 'fastapi', 'httpx', 'aiohttp', 'sqlalchemy', 'python-dotenv', 'tqdm', 'jinja2', 'paramiko',
];
export const KNOWN_NPM = [
  'express', 'lodash', 'react', 'axios', 'chalk', 'commander', 'typescript', 'webpack', 'openai', '@anthropic-ai/sdk', 'zod', 'dotenv', 'moment', 'inquirer',
  'node-fetch', 'puppeteer', 'playwright', 'eslint', 'prettier', 'jsonwebtoken', 'mongoose', 'socket.io',
];

/** Pairs that really are different packages despite being one edit apart. */
const DIFFERENT_PACKAGES = new Set(['request:requests', 'requests:request', 'react:preact', 'moment:moments', 'chalk:chalks', 'zod:zoo', 'jinja2:jinja']);

/** Edit distance where swapping two neighbouring letters (reqeusts) counts as one slip, as people actually mistype. */
function distance(a: string, b: string): number {
  const d = levenshtein(a, b, 2);
  if (d <= 1 || a.length !== b.length) return d;
  for (let i = 0; i < a.length - 1; i++) {
    if (a[i] !== b[i] && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(0, i) === b.slice(0, i) && a.slice(i + 2) === b.slice(i + 2)) return 1;
  }
  return d;
}

const norm = (n: string) => n.toLowerCase().replace(/_/g, '-');

/** Which well-known name does `name` imitate, if any? Exact matches are fine; so are names that are too short to judge. */
export function imitates(name: string, known: string[], opts: { minLength?: number } = {}): string | undefined {
  const min = opts.minLength ?? 6;
  const n = norm(name);
  const bare = (s: string) => s.replace(/^@[^/]+\//, '');
  if (known.some((k) => k === name)) return undefined;
  for (const k of known) {
    if (DIFFERENT_PACKAGES.has(`${name}:${k}`)) continue;
    // Same name, different spelling of case or separators (Skill_Creator vs skill-creator).
    if (norm(k) === n && k !== name) return k;
    if (bare(k).length < min || bare(n).length < min) continue;
    const d = distance(bare(n), bare(k));
    if (d === 1) return k;
    // Same name under a different scope: @anthropic-ai/sdk vs @anthropic/sdk.
    if (k.startsWith('@') && n.startsWith('@') && bare(k) === bare(n) && k !== n) return k;
  }
  return undefined;
}

export interface Dep {
  name: string;
  spec: string;
  /** True when the version is fixed (==, an exact npm version, or a commit hash). */
  pinned: boolean;
}

/** requirements.txt lines → dependencies. Options, includes, editable and URL lines are skipped. */
export function parseRequirements(text: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-') || /^(https?:|git\+|file:)/i.test(line)) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$/);
    if (!m) continue;
    const spec = m[3].split(';')[0].trim();
    out.push({ name: m[1], spec, pinned: /^===?\s*\S+$/.test(spec) || /--hash=/.test(raw) });
  }
  return out;
}

/** package.json dependencies. Ranges like ^1.2.3 are normal; "*", "latest" and bare URLs are floating. */
export function parsePackageJson(text: string): Dep[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  const out: Dep[] = [];
  for (const key of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = (json as Record<string, unknown>)?.[key];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, v] of Object.entries(deps)) {
      const spec = typeof v === 'string' ? v.trim() : '';
      const floating = spec === '' || spec === '*' || /^(latest|next|x)$/i.test(spec) || (/^(https?:|git\+|git:|github:)/i.test(spec) && !/#[0-9a-f]{7,40}$/i.test(spec));
      out.push({ name, spec, pinned: !floating });
    }
  }
  return out;
}

/** Is a Python requirement pinned strictly enough? Floating means no version or an open range. */
export const isFloatingPy = (d: Dep) => !d.pinned && !/^(~=|==)/.test(d.spec);
export const isFloatingNpm = (d: Dep) => !d.pinned;
