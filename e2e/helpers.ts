import { mkdirSync } from 'node:fs';
import { chromium, type Browser, type Page } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

export const url = () => {
  const u = process.env.E2E_URL;
  if (!u) throw new Error('E2E_URL is not set: run through `npm run test:e2e`');
  return u;
};

const live = new Set<Page>();
let browser: Browser | undefined;
export async function launch() {
  return (browser ??= await chromium.launch());
}
export async function closeBrowser() {
  await browser?.close();
  browser = undefined;
}

export async function open(opts: { width?: number; height?: number; scheme?: 'light' | 'dark'; hash?: string; welcome?: boolean } = {}): Promise<Page> {
  const b = await launch();
  // axe-core needs a page that belongs to an explicit context.
  const context = await b.newContext({ viewport: { width: opts.width ?? 1280, height: opts.height ?? 800 }, colorScheme: opts.scheme ?? 'light' });
  // The server keeps preferences between visits; start each test from the defaults.
  await context.request.post(url() + 'api/preferences', { headers: { 'x-ai-bom': '1' }, data: { theme: 'system', mapView: 'overview', findingsView: 'active', baselineView: 'nist-ai-rmf', baselineFilter: 'all', welcomed: opts.welcome ? 'no' : 'yes' } });
  const page = await context.newPage();
  // A hung step should fail in seconds and say what it was waiting for, not use up the whole test timeout.
  page.setDefaultTimeout(20_000);
  live.add(page);
  page.on('close', () => {
    live.delete(page);
    void context.close().catch(() => undefined);
  });
  await page.goto(url() + (opts.hash ?? ''));
  await page.waitForSelector('.tabs');
  return page;
}

/** Put keyboard focus back at the very start of the document, as on a fresh page. */
export async function focusStart(page: Page) {
  await page.evaluate(() => {
    const s = document.createElement('span');
    s.tabIndex = -1;
    document.body.prepend(s);
    s.focus();
    s.remove();
  });
}

export const activeDescription = (page: Page) =>
  page.evaluate(() => {
    const e = document.activeElement as HTMLElement | null;
    return e ? `${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}` : 'none';
  });

const withTimeout = <T>(p: Promise<T>, ms: number, what: string) =>
  Promise.race([p, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${what} did not finish within ${ms / 1000}s`)), ms))]);

/** axe-core with a deadline, so a stuck audit is reported instead of stalling the run. */
export function axe(page: Page) {
  const builder = new AxeBuilder({ page });
  const api = {
    withTags(tags: string[]) {
      builder.withTags(tags);
      return api;
    },
    analyze: () => withTimeout(builder.analyze(), 30_000, 'The axe audit'),
  };
  return api;
}

/** After each test: if it failed, save a screenshot of every page it left open; then close them. */
export async function afterTest(name: string, failed: boolean) {
  let i = 0;
  for (const page of [...live]) {
    if (failed) {
      mkdirSync('e2e/artifacts', { recursive: true });
      await page.screenshot({ path: `e2e/artifacts/${name.replace(/[^a-z0-9]+/gi, '-').slice(0, 80)}-${i++}.png`, timeout: 5000 }).catch(() => undefined);
    }
    await page.close().catch(() => undefined);
  }
}
