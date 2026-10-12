/**
 * Serve the dashboard against a synthetic macOS home directory (the test
 * fixture) so the UI can be developed and demoed without touching real config.
 *   npm run demo
 */
import { scan, type ScanOptions } from '../src/scan.js';
import { serve } from '../src/server/serve.js';
import { addConnector, markReviewed, removeConnector } from '../src/connectors.js';
import type { Inventory } from '../src/types.js';
import { buildFixture, plantConversation } from '../test/fixture.js';
import { dashboardActions, dashboardDownloads } from '../src/server/actions.js';
import os from 'node:os';
import path from 'node:path';
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';

// The demo keeps its fake home folder and its own state (muted findings, fixes, preferences, scan
// history) in ~/.ai-bom/demo, separate from your real data, so it survives restarts.
// `npm run demo -- --reset` starts over.
const demoRoot = path.join(os.homedir(), '.ai-bom', 'demo');
if (process.argv.includes('--reset')) rmSync(demoRoot, { recursive: true, force: true });
process.env.AI_BOM_HOME ??= path.join(demoRoot, 'state');
const fixtureRoot = path.join(demoRoot, 'fixture');
const marker = path.join(demoRoot, 'fixture.json');
let fx: ReturnType<typeof buildFixture>;
if (existsSync(marker)) fx = JSON.parse(readFileSync(marker, 'utf8'));
else {
  mkdirSync(fixtureRoot, { recursive: true });
  fx = buildFixture(fixtureRoot);
  writeFileSync(marker, JSON.stringify(fx));
}
// A recent conversation for the Activity tab (rewritten each start so its times stay current).
plantConversation(fx.home, fx.project);
const base: ScanOptions = {
  home: fx.home,
  platform: 'darwin',
  systemRoot: fx.systemRoot,
  projects: [fx.project, fx.scratch],
  connectorsFile: fx.connectorsFile,
  triageFile: path.join(process.env.AI_BOM_HOME, 'triage.json'),
  toolHashesFile: path.join(process.env.AI_BOM_HOME, 'tool-hashes.json'),
  recordAs: 'demo',
};
let online = false;
const decorate = (inv: Inventory): Inventory => {
  // Pretend a few assets appeared since the last scan so the "changes" view has content.
  for (const a of inv.assets.filter((x) => ['helper', 'internal-api', 'sync-helper'].includes(x.name))) a.isNew = true;
  inv.removed = [{ id: 'skill:demo', kind: 'skill', name: 'old-summarizer' }];
  return inv;
};
let inventory = decorate(await scan(base));
const rescan = async (o: { online?: boolean } = {}) => {
  if (o.online !== undefined) online = o.online;
  return (inventory = decorate(await scan({ ...base, online })));
};

const server = await serve({
  port: Number(process.env.PORT ?? 7655),
  getInventory: async () => inventory,
  rescan,
  connectors: {
    add: async (input) => void (await addConnector(fx.connectorsFile, input)),
    remove: (id) => removeConnector(fx.connectorsFile, id),
    review: (id) => markReviewed(fx.connectorsFile, id),
  },
  actions: dashboardActions({ opts: base, getInventory: async () => inventory, rescan }),
  downloads: dashboardDownloads(async () => inventory),
});
console.log(`Demo dashboard: ${server.url}\nDemo data is kept in ${demoRoot.replace(os.homedir(), '~')} (npm run demo -- --reset to start over).`);
