import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const TLS_DRAFT =
  'https://datatracker.ietf.org/doc/draft-ietf-tls-composite-mldsa/00/';
const IANA_REGISTRY =
  'https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme';

test('rendered standards note reports the pending TLS assignment', async ({ page }) => {
  await page.goto('.');

  const baseline = page.locator('.primer-caption');
  await expect(baseline).toContainText('RFC 10073');
  await expect(baseline).toContainText('November 2026, Proposed Standard');
  await expect(baseline).toContainText('older draft-16 construction');
  await expect(baseline).toContainText('has not been verified for RFC 10073 conformance');
  await expect(baseline.locator('a[href="https://www.rfc-editor.org/info/rfc10073/"]')).toHaveCount(1);
  /* RFC 10073 is X.509 ONLY. CMS is the separate RFC 10082, and the page must not
     let one stand for the other: the wording here previously paired "RFC 10073
     conformance" with "no X.509 or CMS encoding", which reads as the X.509 RFC
     covering CMS too. Both documents are named, each against its own encoding,
     and the non-conformance is stated for each. */
  await expect(baseline).toContainText('RFC 10082');
  await expect(baseline).toContainText('RFC 10073 does not cover CMS');
  await expect(baseline).toContainText('has not been verified for RFC 10082 conformance');
  await expect(baseline.locator('a[href="https://www.rfc-editor.org/info/rfc10082/"]')).toHaveCount(1);
  // No sentence may attach CMS to 10073 by juxtaposition again.
  await expect(baseline).not.toContainText('no X.509 or CMS encoding');

  const note = page.locator('#tls-standards-status');
  await expect(note).toBeVisible();
  await expect(note).toContainText('checked 24 October 2026');
  await expect(note).toContainText('mldsa65_ed25519_sha512');
  await expect(note).toContainText('placeholder TBD7');
  await expect(note).toContainText('has not assigned it a value');
  await expect(note).toContainText('not a final standard');
  await expect(note).toContainText('TLS draft references LAMPS draft-19');
  await expect(note).toContainText('does not claim draft-19 conformance');
  await expect(note.locator(`a[href="${TLS_DRAFT}"]`)).toHaveCount(1);
  await expect(note.locator(`a[href="${IANA_REGISTRY}"]`)).toHaveCount(1);

  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/0x090[AB]/i);

  const deployment = page.locator('#deployment-status');
  await expect(deployment).toContainText('construction baseline implemented in this lab');
  await expect(deployment).toContainText('separate work-in-progress proposal');
});

test('README distinguishes the LAMPS baseline from the pending TLS proposal', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

  expect(readme).toContain('LAMPS draft-16 construction');
  expect(readme).toContain('https://www.rfc-editor.org/info/rfc10073/');
  expect(readme).toContain('has not been verified for RFC 10073 conformance');
  // Same distinction the rendered page must keep: 10073 is X.509, 10082 is CMS.
  expect(readme).toContain('https://www.rfc-editor.org/info/rfc10082/');
  expect(readme).toContain('has not been verified for RFC 10082 conformance');
  expect(readme).toContain('one does not cover the other');
  expect(readme).not.toContain('no X.509 or CMS encoding');
  expect(readme).toContain('active working-group Internet-Draft, not a final standard');
  expect(readme).toContain('does not claim conformance to that newer construction revision');
  expect(readme).toContain('mldsa65_ed25519_sha512');
  expect(readme).toContain('placeholder `TBD7`');
  expect(readme).toContain(TLS_DRAFT);
  expect(readme).toContain(IANA_REGISTRY);
  expect(readme).not.toMatch(/0x090[AB]/i);
  expect(readme).not.toMatch(/codepoints? (?:have been|are) assigned/i);
});
