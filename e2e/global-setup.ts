import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

let server: ChildProcess | undefined;
let home: string | undefined;

/** Serve the demo dashboard on a free port, against a throwaway HOME so nothing real is touched. */
export async function setup() {
  home = mkdtempSync(path.join(os.tmpdir(), 'ai-bom-e2e-'));
  const port = 20000 + Math.floor(Math.random() * 20000);
  server = spawn(process.execPath, ['--import', 'tsx', 'scripts/demo.ts'], {
    env: { ...process.env, HOME: home, PORT: String(port), AI_BOM_HOME: path.join(home, 'state') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // An unread pipe fills up and blocks the server; keep the tail for the failure message instead.
  let log = '';
  server.stderr!.on('data', (d: Buffer) => (log = (log + d.toString()).slice(-4000)));
  const url = `http://127.0.0.1:${port}/`;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`demo server did not start\n${log}`)), 40_000);
    server!.stdout!.on('data', (d: Buffer) => {
      if (d.toString().includes('Demo dashboard:')) {
        clearTimeout(timer);
        resolve();
      }
    });
    server!.once('exit', (code) => reject(new Error(`demo server exited early (${code})\n${log}`)));
  });
  process.env.E2E_URL = url;
}

export async function teardown() {
  server?.removeAllListeners('exit');
  server?.kill();
  if (home) rmSync(home, { recursive: true, force: true });
}
