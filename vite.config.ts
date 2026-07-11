import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-hybrid-sign/',
  test: {
    // Only run Vitest unit tests. The Playwright e2e specs (e2e/) must not be
    // collected by Vitest, or they throw "test() was not expected here".
    include: ['src/**/*.test.ts'],
  },
});
