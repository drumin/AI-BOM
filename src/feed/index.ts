import path from 'node:path';
import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { promises as fs } from 'node:fs';
import type { Advisory } from '../vulns/advisories.js';
import { ADVISORIES } from '../vulns/advisories.js';
import { dataDir, writeAtomic } from '../util/store.js';

/**
 * Self-updating advisory feed.
 *
 * The maintainers publish `advisories.json` plus a detached Ed25519
 * signature (`advisories.json.sig`) on a rolling GitHub release named
 * "advisories". `ai-bom update` downloads both, verifies the signature
 * against the public key built into this package, refuses anything older
 * than what is cached (rollback protection) or dated in the future, and
 * keeps a verified copy in ~/.ai-bom/feed/. The cached copy is re-verified
 * every time it is loaded, so editing it on disk just disables it.
 *
 * Until the maintainers configure a signing key (PUBLIC_KEY below), updates
 * are off and only the advisories bundled in the package are used.
 */

/** Ed25519 public key (SPKI PEM) of the feed signer. Generate with `npm run feed:keygen`. */
export const PUBLIC_KEY: string | undefined = undefined;
export const FEED_URL = 'https://github.com/drumin/ai-scanner/releases/download/advisories/advisories.json';

export interface FeedFile {
  schema: 1;
  generatedAt: string;
  advisories: Advisory[];
}

export interface FeedStatus {
  status: 'updated' | 'unchanged' | 'not-configured' | 'error';
  message: string;
  generatedAt?: string;
  advisories?: number;
}

export type BytesFetch = (url: string) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

const feedDir = () => path.join(dataDir(), 'feed');
const cacheFile = () => path.join(feedDir(), 'advisories.json');

/** Self-hosters and forks can point at their own feed and key. */
export function feedConfig(): { url: string; key?: KeyObject } {
  const url = process.env.AI_BOM_FEED_URL || FEED_URL;
  const pem = process.env.AI_BOM_FEED_PUBKEY || PUBLIC_KEY;
  if (!pem) return { url };
  const text = pem.includes('BEGIN') ? pem : Buffer.from(pem, 'base64').toString('utf8');
  return { url, key: createPublicKey(text) };
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

function validAdvisory(a: unknown): a is Advisory {
  if (!a || typeof a !== 'object') return false;
  const x = a as Record<string, unknown>;
  const ver = (v: unknown) => v === undefined || (typeof v === 'string' && v.length < 40) || (Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length < 40));
  return (
    typeof x.id === 'string' && /^[A-Za-z0-9._:-]{3,60}$/.test(x.id) &&
    (x.ecosystem === 'npm' || x.ecosystem === 'pypi') &&
    typeof x.package === 'string' && x.package.length < 215 &&
    typeof x.severity === 'string' && SEVERITIES.has(x.severity) &&
    typeof x.summary === 'string' && x.summary.length <= 600 &&
    Array.isArray(x.references) && x.references.every((r) => typeof r === 'string' && /^https:\/\//.test(r)) &&
    ver(x.introduced) && ver(x.fixed)
  );
}

/** Verify signature and structure. Throws on any problem. */
export function verifyFeed(bytes: Buffer, signature: string, key: KeyObject): FeedFile {
  const sig = Buffer.from(signature.trim(), 'base64');
  if (!verify(null, bytes, key, sig)) throw new Error('Signature does not match: the feed was not signed by the AI-BOM maintainers (or was modified).');
  const data = JSON.parse(bytes.toString('utf8')) as Partial<FeedFile>;
  if (data.schema !== 1 || typeof data.generatedAt !== 'string' || Number.isNaN(Date.parse(data.generatedAt)) || !Array.isArray(data.advisories)) {
    throw new Error('Unsupported feed format.');
  }
  return { schema: 1, generatedAt: data.generatedAt, advisories: data.advisories.filter(validAdvisory).slice(0, 5000) };
}

export async function loadCachedFeed(): Promise<FeedFile | undefined> {
  const { key } = feedConfig();
  if (!key) return undefined;
  try {
    const [bytes, sig] = await Promise.all([fs.readFile(cacheFile()), fs.readFile(`${cacheFile()}.sig`, 'utf8')]);
    return verifyFeed(bytes, sig, key);
  } catch {
    return undefined;
  }
}

export async function feedAgeHours(): Promise<number | undefined> {
  try {
    return (Date.now() - (await fs.stat(cacheFile())).mtimeMs) / 3_600_000;
  } catch {
    return undefined;
  }
}

export async function updateFeed(fetchImpl: BytesFetch = fetch as unknown as BytesFetch): Promise<FeedStatus> {
  const { url, key } = feedConfig();
  if (!key) return { status: 'not-configured', message: 'The advisory feed is not enabled in this build (no signing key configured). Bundled advisories are used.' };
  try {
    const [res, sigRes] = await Promise.all([fetchImpl(url), fetchImpl(`${url}.sig`)]);
    if (!res.ok || !sigRes.ok) return { status: 'error', message: `Feed download failed (HTTP ${res.ok ? sigRes.status : res.status}).` };
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length > 5 * 1024 * 1024) return { status: 'error', message: 'Feed is unexpectedly large; ignored.' };
    const sig = Buffer.from(await sigRes.arrayBuffer()).toString('utf8');
    const feed = verifyFeed(bytes, sig, key);
    if (Date.parse(feed.generatedAt) > Date.now() + 86_400_000) return { status: 'error', message: 'Feed is dated in the future; ignored.' };
    const current = await loadCachedFeed();
    if (current && Date.parse(feed.generatedAt) < Date.parse(current.generatedAt)) {
      return { status: 'error', message: `Refusing an older feed (${feed.generatedAt}) than the one installed (${current.generatedAt}).` };
    }
    if (current && current.generatedAt === feed.generatedAt) {
      await fs.utimes(cacheFile(), new Date(), new Date()).catch(() => {});
      return { status: 'unchanged', message: 'Advisory feed is up to date.', generatedAt: feed.generatedAt, advisories: feed.advisories.length };
    }
    await writeAtomic(`${cacheFile()}.sig`, sig);
    await writeAtomic(cacheFile(), bytes.toString('utf8'));
    return { status: 'updated', message: `Advisory feed updated: ${feed.advisories.length} advisories from ${feed.generatedAt.slice(0, 10)}.`, generatedAt: feed.generatedAt, advisories: feed.advisories.length };
  } catch (e) {
    return { status: 'error', message: `Feed rejected: ${(e as Error).message}` };
  }
}

/** Bundled advisories plus the verified feed; the feed wins for the same id and package. */
export function mergeAdvisories(feed?: FeedFile): Advisory[] {
  if (!feed) return ADVISORIES;
  const map = new Map(ADVISORIES.map((a) => [`${a.id}|${a.package}`, a]));
  for (const a of feed.advisories) map.set(`${a.id}|${a.package}`, a);
  return [...map.values()];
}
