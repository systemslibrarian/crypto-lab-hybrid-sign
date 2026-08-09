import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the composite-signature
 * vitest suite and on `forgery.spec.ts`; this gates them on accessibility the
 * same way.
 *
 * The lab is driven along everything it teaches: the arrival state, where eight
 * of nine controls are locked and all seven output panels are absent; both skip
 * links focused; both disclosures opened through their summaries; the composite
 * keypair; the signature, expanded to its full 6,746 hex characters and
 * collapsed again, and copied; a clean verify with both locks lit green; each
 * tamper branch with its flip marks; all four break scenarios including the
 * double break, whose forgery is genuinely ACCEPTED; the over-length-context
 * error; a long unbroken message echoed into prose as the forgery target; and
 * the regenerate that puts the diagram back to idle. Every one of those states
 * is scanned, in both themes, at desktop and phone width.
 *
 * Clipboard permission is granted because `#copy-sig` calls
 * `navigator.clipboard.writeText`: without the grant the promise rejects, the
 * button reads "Copy failed", and the drive would be asserting against a state
 * the code never reached.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * force-revealed, why the lab's defaults are asserted rather than assumed, and
 * why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
