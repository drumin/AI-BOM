import http from 'node:http';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Inventory } from '../types.js';
import { toCycloneDX } from '../bom/cyclonedx.js';
import { exists } from '../util/fs.js';

const isFile = (p: string) => fs.stat(p).then((s) => s.isFile(), () => false);

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
};

async function webRoot(): Promise<string | undefined> {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // dist/server/serve.js -> dist/web ; src/server/serve.ts (tsx) -> dist/web
  for (const c of [path.resolve(here, '..', 'web'), path.resolve(here, '..', '..', 'dist', 'web')]) {
    if (await exists(path.join(c, 'index.html'))) return c;
  }
  return undefined;
}

export interface ServeOptions {
  port: number;
  /** Fail at startup if the built dashboard is missing (default true; tests serve the API only). */
  requireAssets?: boolean;
  getInventory: () => Promise<Inventory>;
  /** online: true/false switches the vulnerability lookup; undefined keeps the current mode. */
  rescan: (opts: { online?: boolean; record?: boolean }) => Promise<Inventory>;
  connectors?: {
    add: (input: unknown) => Promise<void>;
    remove: (id: string) => Promise<boolean>;
    review: (id: string) => Promise<boolean>;
  };
  /**
   * Extra JSON actions (triage, fixes, snapshots, review). Keys are "METHOD /api/path";
   * a trailing ":id" segment is passed as `id`. Handlers return the response body.
   */
  actions?: Record<string, (body: Record<string, unknown>, id?: string) => Promise<unknown>>;
  /** Extra GET downloads: path -> [content type, producer]. */
  downloads?: Record<string, [string, () => Promise<string>]>;
}

/** An error whose message is safe to show, with an HTTP status. */
export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const MAX_BODY = 16 * 1024;

class BodyTooLarge extends Error {}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        // Stop buffering but drain the socket so we can still answer 413.
        req.removeAllListeners('data');
        req.resume();
        reject(new BodyTooLarge('Request body too large'));
      } else chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Serve the dashboard on 127.0.0.1 only. The Host header is checked so a
 * web page on another origin cannot read your inventory via DNS rebinding.
 */
export async function serve(opts: ServeOptions): Promise<{ url: string; close: () => void }> {
  const root = await webRoot();
  if (!root && opts.requireAssets !== false) throw new Error('Dashboard assets not found. Run "npm run build" first.');

  let port = opts.port;
  const server = http.createServer(async (req, res) => {
    const host = (req.headers.host ?? '').toLowerCase();
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    const send = (status: number, body: string | Buffer, type = 'application/json') => {
      res.writeHead(status, {
        'Content-Type': type,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
      });
      res.end(body);
    };
    try {
      const url = new URL(req.url ?? '/', `http://${host}`);
      if (url.pathname === '/api/inventory' && req.method === 'GET') {
        return send(200, JSON.stringify(await opts.getInventory()));
      }
      if (req.method !== 'GET' && url.pathname.startsWith('/api/')) {
        // Every mutation requires a custom header: cross-site forms and simple requests cannot set it.
        if (req.headers['x-ai-bom'] !== '1') return send(403, '{"error":"forbidden"}');
        if (url.pathname === '/api/rescan' && req.method === 'POST') {
          const q = url.searchParams.get('online');
          return send(200, JSON.stringify(await opts.rescan({ online: q === '1' ? true : q === '0' ? false : undefined, record: true })));
        }
        const c = opts.connectors;
        const m = url.pathname.match(/^\/api\/connectors(?:\/([\w-]{1,64}))?(\/review)?$/);
        if (c && m) {
          const [, id, review] = m;
          try {
            if (!id && req.method === 'POST') await c.add(await readJson(req));
            else if (id && review && req.method === 'POST') {
              if (!(await c.review(id))) return send(404, '{"error":"not found"}');
            } else if (id && !review && req.method === 'DELETE') {
              if (!(await c.remove(id))) return send(404, '{"error":"not found"}');
            } else return send(405, '{"error":"method not allowed"}');
          } catch (e) {
            return send(e instanceof BodyTooLarge ? 413 : 400, JSON.stringify({ error: (e as Error).message }));
          }
          return send(200, JSON.stringify(await opts.rescan({})));
        }
        const action = findAction(opts.actions, req.method ?? '', url.pathname);
        if (action) {
          try {
            const body = req.method === 'POST' ? ((await readJson(req)) as Record<string, unknown>) : {};
            return send(200, JSON.stringify((await action.fn(body && typeof body === 'object' ? body : {}, action.id)) ?? {}));
          } catch (e) {
            const status = e instanceof BodyTooLarge ? 413 : e instanceof HttpError ? e.status : 400;
            return send(status, JSON.stringify({ error: (e as Error).message }));
          }
        }
        return send(404, '{"error":"not found"}');
      }
      if (req.method === 'GET' && url.pathname.startsWith('/api/')) {
        const action = findAction(opts.actions, 'GET', url.pathname);
        if (action) {
          try {
            return send(200, JSON.stringify(await action.fn(Object.fromEntries(url.searchParams), action.id)));
          } catch (e) {
            return send(e instanceof HttpError ? e.status : 400, JSON.stringify({ error: (e as Error).message }));
          }
        }
        const dl = opts.downloads?.[url.pathname];
        if (dl) return send(200, await dl[1](), dl[0]);
      }
      if (url.pathname === '/api/cyclonedx' && req.method === 'GET') {
        return send(200, JSON.stringify(toCycloneDX(await opts.getInventory()), null, 2));
      }
      if (req.method !== 'GET') return send(405, 'Method not allowed', 'text/plain');
      if (!root) return send(404, 'Not found', 'text/plain');
      const rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
      const file = path.resolve(root, rel);
      if (!file.startsWith(root + path.sep) || !(await isFile(file))) {
        return send(200, await fs.readFile(path.join(root, 'index.html')), MIME['.html']);
      }
      return send(200, await fs.readFile(file), MIME[path.extname(file)] ?? 'application/octet-stream');
    } catch (e) {
      send(500, JSON.stringify({ error: (e as Error).message }));
    }
  });

  await new Promise<void>((resolve, reject) => {
    const tryListen = (p: number, attemptsLeft: number) => {
      const onError = (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE' && attemptsLeft > 0) tryListen(p + 1, attemptsLeft - 1);
        else reject(err);
      };
      server.once('error', onError);
      server.listen(p, '127.0.0.1', () => {
        server.off('error', onError);
        port = p;
        resolve();
      });
    };
    tryListen(port, 10);
  });

  return { url: `http://127.0.0.1:${port}/`, close: () => server.close() };
}

function findAction(actions: ServeOptions['actions'], method: string, pathname: string) {
  if (!actions) return undefined;
  const get = (k: string) => actions[k] as ((body: Record<string, unknown>, id?: string) => Promise<unknown>) | undefined;
  const exact = get(`${method} ${pathname}`);
  if (exact) return { fn: exact };
  const parts = pathname.split('/');
  // …/:id  or  …/:id/<verb>
  for (const at of [parts.length - 1, parts.length - 2]) {
    if (at < 3 || !/^[\w.-]{1,80}$/.test(parts[at] ?? '')) continue;
    const key = [...parts.slice(0, at), ':id', ...parts.slice(at + 1)].join('/');
    const fn = get(`${method} ${key}`);
    if (fn) return { fn, id: parts[at] };
  }
  return undefined;
}
