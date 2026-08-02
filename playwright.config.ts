import { defineConfig } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
// Overridable so a busy port on a dev box does not block the gate.
const PORT = process.env.PREVIEW_PORT ?? '4221';
const BASE = '/crypto-lab-hybrid-sign/';
const URL = `http://localhost:${PORT}${BASE}`;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: URL,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        baseURL: URL,
        colorScheme: 'dark',
        browserName: 'chromium',
      },
    },
  ],
});
