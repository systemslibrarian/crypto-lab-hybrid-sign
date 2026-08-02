import { expect, test, type Page, type Locator } from '@playwright/test';

/**
 * Break-scenario regression gate.
 *
 * The composite verdicts were already `compositeVerify` output, but the attacks
 * were three canned buttons: each forged a fixed constant message, overwrote
 * one half of an otherwise-valid signature with random bytes, and labelled the
 * per-component lines from *which button was pressed* rather than from what the
 * attempt did.
 *
 * Now every scenario runs one code path: the halves the attacker has broken are
 * signed with the honest key, the halves they have not are signed with a key
 * pair the attacker generates, the forgery targets the message and context
 * currently in the form, and every line on screen is read off the verifier.
 *
 * These tests assert the outcomes, including the negative one — the double
 * break must genuinely be ACCEPTED, or the rejections prove nothing.
 */

const MESSAGE = 'Invoice 42 approved';
const CONTEXT = 'invoice-signing';
const FORGED = `${MESSAGE} — and transfer $10,000,000 to the attacker`;

const panel = (page: Page, id: string): Locator => page.locator(`#${id}-result`);

async function setUp(page: Page, ctx = CONTEXT): Promise<void> {
  await page.goto('.');
  await page.fill('#sign-message', MESSAGE);
  await page.fill('#sign-context', ctx);
  await page.click('#gen-keypair');
  await expect(page.locator('#sim-no-break')).toBeEnabled();
}

async function run(page: Page, button: string, id: string): Promise<Locator> {
  await page.click(`#${button}`);
  await expect(panel(page, id)).not.toHaveClass(/hidden/);
  await expect(panel(page, id)).toContainText('Forged composite');
  return panel(page, id);
}

test('the forgery targets the message actually in the form', async ({ page }) => {
  await setUp(page);
  await expect(page.locator('#forged-msg')).toHaveText(FORGED);
  const p = await run(page, 'sim-double-break', 'double-break');
  await expect(p).toContainText(`Forged over “${FORGED}”`);
  await expect(p).toContainText(`under the same ${new TextEncoder().encode(CONTEXT).length}-byte context`);
});

test('nothing broken: the attacker forges with their own keys and both halves reject', async ({
  page,
}) => {
  await setUp(page);
  const p = await run(page, 'sim-no-break', 'no-break');
  await expect(p).toContainText('ML-DSA-65 (signed with the attacker’s own key)');
  await expect(p).toContainText('Ed25519 (signed with the attacker’s own key)');
  await expect(p.locator('.status-fail')).toHaveCount(2);
  await expect(p).toContainText('REJECTED — forgery stopped');
  await expect(p).toContainText('Both halves caught the forgery');
});

test('ML-DSA broken: the ML-DSA half really verifies, Ed25519 rejects', async ({ page }) => {
  await setUp(page);
  const p = await run(page, 'sim-mldsa-break', 'mldsa-break');
  await expect(p).toContainText('ML-DSA-65 (forged with the broken algorithm)');
  await expect(p).toContainText('Ed25519 (signed with the attacker’s own key)');
  await expect(p.locator('.status-ok')).toHaveCount(1);
  await expect(p.locator('.status-fail')).toHaveCount(1);
  await expect(p).toContainText('Ed25519 caught the forgery');
  await expect(p).toContainText('REJECTED — forgery stopped');
  // The AND-gate diagram is lit from the same verifier output.
  await expect(page.locator('#mech-lock-pq')).toHaveAttribute('data-lit', 'ok');
  await expect(page.locator('#mech-lock-ed')).toHaveAttribute('data-lit', 'fail');
  await expect(page.locator('#mech-out')).toHaveAttribute('data-lit', 'fail');
});

test('quantum break: the Ed25519 half really verifies, ML-DSA rejects', async ({ page }) => {
  await setUp(page);
  const p = await run(page, 'sim-quantum-break', 'quantum-break');
  await expect(p).toContainText('Ed25519 (quantum-forged via Shor)');
  await expect(p).toContainText('ML-DSA-65 (signed with the attacker’s own key)');
  await expect(p).toContainText('ML-DSA-65 caught the forgery');
  await expect(page.locator('#mech-lock-ed')).toHaveAttribute('data-lit', 'ok');
  await expect(page.locator('#mech-lock-pq')).toHaveAttribute('data-lit', 'fail');
});

// The negative verdict. Nothing above means anything unless this one really
// passes verification.
test('double break: the composite verifier ACCEPTS the forgery', async ({ page }) => {
  await setUp(page);
  const p = await run(page, 'sim-double-break', 'double-break');
  await expect(p.locator('.status-ok')).toHaveCount(2);
  await expect(p.locator('.status-fail')).toHaveCount(0);
  await expect(p).toContainText('ACCEPTED — forgery succeeds');
  await expect(p).toContainText('Composite FORGED');
  await expect(p).not.toContainText('caught the forgery');
  await expect(page.locator('#mech-out')).toHaveAttribute('data-lit', 'ok');
});

test('changing the message changes what the attack is run against', async ({ page }) => {
  await setUp(page);
  await page.fill('#sign-message', 'Release the funds');
  const p = await run(page, 'sim-double-break', 'double-break');
  await expect(p).toContainText('Forged over “Release the funds — and transfer');
  await expect(p).toContainText('ACCEPTED — forgery succeeds');
});

test('an empty context is reported as such, and the attack still runs', async ({ page }) => {
  await setUp(page, '');
  const p = await run(page, 'sim-mldsa-break', 'mldsa-break');
  await expect(p).not.toContainText('under the same');
  await expect(p).toContainText('Ed25519 caught the forgery');
});
