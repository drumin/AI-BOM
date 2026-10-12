import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { promises as fs } from 'node:fs';

/**
 * Download a package WITHOUT installing it: the npm tarball or PyPI sdist /
 * wheel is fetched, its registry checksum verified, and its files unpacked
 * into a temp folder so they can be read. No install scripts run, nothing is
 * executed, and archive entries that try to escape the folder (../, absolute
 * paths, links) are refused.
 */

export type BytesFetch = (url: string, init?: { headers?: Record<string, string> }) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer>; json(): Promise<unknown> }>;

export interface FetchedPackage {
  ecosystem: 'npm' | 'pypi';
  name: string;
  version: string;
  dir: string;
  /** Registry metadata of this version (npm) / release (PyPI). */
  meta: Record<string, unknown>;
  latest?: string;
  cleanup: () => Promise<void>;
}

const MAX_TOTAL = 60 * 1024 * 1024;
const MAX_FILES = 6000;

function safeJoin(root: string, name: string): string | undefined {
  const clean = name.replace(/\\/g, '/').replace(/^\.\/+/, '');
  if (!clean || clean.startsWith('/') || /^[A-Za-z]:/.test(clean) || clean.split('/').includes('..')) return undefined;
  const out = path.join(root, clean);
  return out.startsWith(root + path.sep) ? out : undefined;
}

/** Minimal ustar/pax/GNU tar reader: regular files only. */
export async function extractTar(buf: Buffer, root: string, strip = 0): Promise<number> {
  let off = 0;
  let files = 0;
  let total = 0;
  let longName: string | undefined;
  let paxPath: string | undefined;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const str = (a: number, n: number) => h.subarray(a, a + n).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(str(124, 12).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    const body = buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
    if (type === 'L') {
      longName = body.toString('utf8').replace(/\0.*$/s, '');
      continue;
    }
    if (type === 'x') {
      const m = body.toString('utf8').match(/\d+ path=([^\n]+)\n/);
      paxPath = m?.[1];
      continue;
    }
    if (type === 'g') continue;
    const prefix = str(345, 155);
    let name = paxPath ?? longName ?? (prefix ? `${prefix}/${str(0, 100)}` : str(0, 100));
    longName = paxPath = undefined;
    if (type !== '0' && type !== '\0' && type !== '7') continue; // skip dirs, links, devices
    // Refuse absolute and parent-relative names before stripping the leading folder.
    if (/^([\\/]|[A-Za-z]:)/.test(name) || name.split(/[\\/]/).includes('..')) continue;
    name = name.split('/').slice(strip).join('/');
    const target = safeJoin(root, name);
    if (!target) continue;
    total += size;
    if (++files > MAX_FILES || total > MAX_TOTAL) throw new Error('Package is too large to inspect.');
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, body, { mode: 0o600 });
  }
  return files;
}

/** Minimal zip reader (wheels): stored and deflated entries via the central directory. */
export async function extractZip(buf: Buffer, root: string): Promise<number> {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('Not a zip file.');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  let total = 0;
  let written = 0;
  let files = 0;
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nlen).toString('utf8');
    p += 46 + nlen + elen + clen;
    if (name.endsWith('/')) continue;
    const target = safeJoin(root, name);
    if (!target) continue;
    total += usize;
    if (++files > MAX_FILES || total > MAX_TOTAL) throw new Error('Package is too large to inspect.');
    const lnlen = buf.readUInt16LE(local + 26);
    const lelen = buf.readUInt16LE(local + 28);
    const data = buf.subarray(local + 30 + lnlen + lelen, local + 30 + lnlen + lelen + csize);
    // The sizes in a zip header are only claims; count what actually comes out, and stop a bomb early.
    let out: Buffer | undefined;
    try {
      out = method === 0 ? data : method === 8 ? inflateRawSync(data, { maxOutputLength: Math.max(1, MAX_TOTAL - written) }) : undefined;
    } catch {
      throw new Error('Package is too large to inspect.');
    }
    if (!out) continue;
    written += out.length;
    if (written > MAX_TOTAL) throw new Error('Package is too large to inspect.');
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, out, { mode: 0o600 });
  }
  return files;
}

/** Inflate a tarball without letting a gzip bomb eat memory (the size checks in extractTar run after inflating). */
function gunzipCapped(buf: Buffer): Buffer {
  try {
    return gunzipSync(buf, { maxOutputLength: MAX_TOTAL });
  } catch {
    throw new Error('Package is too large to inspect.');
  }
}

async function download(url: string, fetchImpl: BytesFetch): Promise<Buffer> {
  if (!/^https:\/\//.test(url)) throw new Error('Refusing a non-HTTPS download.');
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status}).`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_TOTAL) throw new Error('Package is too large to inspect.');
  return buf;
}

export async function fetchNpm(name: string, version: string | undefined, fetchImpl: BytesFetch = fetch as unknown as BytesFetch): Promise<FetchedPackage> {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(res.status === 404 ? `No npm package named "${name}".` : `npm registry returned HTTP ${res.status}.`);
  const doc = (await res.json()) as { 'dist-tags'?: Record<string, string>; versions?: Record<string, Record<string, unknown>> };
  const latest = doc['dist-tags']?.latest;
  const v = version && version !== 'latest' ? version : latest;
  const meta = v ? doc.versions?.[v] : undefined;
  if (!v || !meta) throw new Error(`${name}@${version} does not exist.`);
  const dist = meta.dist as { tarball?: string; integrity?: string; shasum?: string } | undefined;
  if (!dist?.tarball) throw new Error('No tarball for this version.');
  const tgz = await download(dist.tarball, fetchImpl);
  if (dist.integrity?.startsWith('sha512-')) {
    if (createHash('sha512').update(tgz).digest('base64') !== dist.integrity.slice(7)) throw new Error('Checksum mismatch: the download does not match the registry.');
  } else if (dist.shasum && createHash('sha1').update(tgz).digest('hex') !== dist.shasum) throw new Error('Checksum mismatch.');
  const tar = gunzipCapped(tgz);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-bom-pkg-'));
  await extractTar(tar, dir, 1);
  return { ecosystem: 'npm', name, version: v, dir, meta, latest, cleanup: () => fs.rm(dir, { recursive: true, force: true }) };
}

export async function fetchPypi(name: string, version: string | undefined, fetchImpl: BytesFetch = fetch as unknown as BytesFetch): Promise<FetchedPackage> {
  const res = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(name)}/${version && version !== 'latest' ? `${encodeURIComponent(version)}/` : ''}json`);
  if (!res.ok) throw new Error(res.status === 404 ? `No PyPI package named "${name}"${version ? ` version ${version}` : ''}.` : `PyPI returned HTTP ${res.status}.`);
  const doc = (await res.json()) as { info?: Record<string, unknown>; urls?: { url: string; packagetype: string; filename: string; digests?: { sha256?: string } }[] };
  const v = String(doc.info?.version ?? version);
  const files = doc.urls ?? [];
  const pick = files.find((f) => f.packagetype === 'bdist_wheel' && /py3-none-any\.whl$/.test(f.filename)) ?? files.find((f) => f.packagetype === 'sdist' && /\.tar\.gz$/.test(f.filename)) ?? files.find((f) => f.packagetype === 'bdist_wheel');
  if (!pick) throw new Error('No downloadable file for this release.');
  const buf = await download(pick.url, fetchImpl);
  if (pick.digests?.sha256 && createHash('sha256').update(buf).digest('hex') !== pick.digests.sha256) throw new Error('Checksum mismatch: the download does not match PyPI.');
  const tar = pick.filename.endsWith('.whl') ? undefined : gunzipCapped(buf);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-bom-pkg-'));
  if (tar) await extractTar(tar, dir, 1);
  else await extractZip(buf, dir);
  let latest: string | undefined;
  if (version) {
    const l = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`).catch(() => undefined);
    latest = l?.ok ? String(((await l.json()) as { info?: { version?: string } }).info?.version ?? '') || undefined : undefined;
  } else latest = v;
  return { ecosystem: 'pypi', name, version: v, dir, meta: { ...doc.info, file: pick.filename }, latest, cleanup: () => fs.rm(dir, { recursive: true, force: true }) };
}
