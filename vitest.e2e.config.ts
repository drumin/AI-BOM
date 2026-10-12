import { defineConfig } from 'vitest/config';

/**
 * Browser tests for the dashboard (Playwright + axe). Not part of `npm test`.
 *   npx playwright install chromium   # once
 *   npm run test:e2e
 */
export default defineConfig({
  test: {
    include: ['e2e/**/*.e2e.ts'],
    globalSetup: ['e2e/global-setup.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
