/**
 * Sign the advisory feed for publishing.
 *
 *   AI_BOM_FEED_KEY=<base64 PEM> npx tsx scripts/sign-feed.ts [--key file] [--out dir]
 *
 * Reads feed/advisories.json (a plain list of advisories), stamps it with the
 * current time and writes <out>/advisories.json + advisories.json.sig
 * (base64 Ed25519 signature over the exact bytes).
 */
import path from 'node:path';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { parseArgs } from 'node:util';

const { values } = parseArgs({ options: { key: { type: 'string' }, out: { type: 'string', default: 'feed-dist' }, src: { type: 'string', default: 'feed/advisories.json' } } });
const raw = values.key ? readFileSync(values.key, 'utf8') : process.env.AI_BOM_FEED_KEY;
if (!raw) {
  console.error('No signing key: set AI_BOM_FEED_KEY or pass --key.');
  process.exit(2);
}
const pem = raw.includes('BEGIN') ? raw : Buffer.from(raw, 'base64').toString('utf8');
const key = createPrivateKey(pem);
const source = JSON.parse(readFileSync(values.src!, 'utf8'));
const advisories = Array.isArray(source) ? source : source.advisories;
if (!Array.isArray(advisories)) throw new Error(`${values.src} must be a list of advisories`);
const body = Buffer.from(JSON.stringify({ schema: 1, generatedAt: new Date().toISOString(), advisories }, null, 2) + '\n');
const sig = sign(null, body, key);
if (!verify(null, body, createPublicKey(key), sig)) throw new Error('Self-check failed');
mkdirSync(values.out!, { recursive: true });
writeFileSync(path.join(values.out!, 'advisories.json'), body);
writeFileSync(path.join(values.out!, 'advisories.json.sig'), sig.toString('base64') + '\n');
console.log(`Signed ${advisories.length} advisories → ${values.out}/advisories.json(.sig)`);
