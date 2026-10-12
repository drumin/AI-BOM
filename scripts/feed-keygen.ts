/**
 * Create the Ed25519 key pair that signs the advisory feed.
 *
 *   npm run feed:keygen [-- <private-key-file>]
 *
 * The private key is written OUTSIDE the repository (default
 * ~/.ai-bom/feed-signing-key.pem, mode 600) and is never printed except as a
 * one-line value to paste into the GitHub Actions secret AI_BOM_FEED_KEY.
 * Paste the printed public key into src/feed/index.ts (PUBLIC_KEY).
 */
import os from 'node:os';
import path from 'node:path';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';

const out = process.argv[2] ?? path.join(os.homedir(), '.ai-bom', 'feed-signing-key.pem');
if (existsSync(out)) {
  console.error(`${out} already exists; refusing to overwrite a signing key.`);
  process.exit(1);
}
if (path.resolve(out).startsWith(path.resolve('.') + path.sep)) {
  console.error('Keep the private key outside the repository.');
  process.exit(1);
}
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const priv = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
writeFileSync(out, priv, { mode: 0o600 });
console.log(`Private key written to ${out} (keep it safe; back it up offline).\n`);
console.log('1) Public key, paste into src/feed/index.ts as PUBLIC_KEY:\n');
console.log(publicKey.export({ type: 'spki', format: 'pem' }).toString());
console.log('2) GitHub secret AI_BOM_FEED_KEY (repo Settings → Secrets → Actions), value:\n');
console.log(Buffer.from(priv).toString('base64'));
