import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are gated on the composite-signature vitest
 * suite; this gates them on accessibility the same way. Scans the full page
 * with every collapsible expanded, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Expand every disclosure/collapsible and neutralize animation so axe sees
 * the fully-revealed DOM in a stable state. */
async function revealAll(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important;}`,
  });
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // reveal any class-hidden / [hidden] panels so their contents are scanned
    for (const el of Array.from(document.querySelectorAll('.hidden, [hidden]'))) {
      el.classList.remove('hidden');
      el.removeAttribute('hidden');
    }
    for (const el of Array.from(document.querySelectorAll('.hex-display'))) {
      el.classList.add('expanded');
    }
  });
  await page.waitForTimeout(50);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
