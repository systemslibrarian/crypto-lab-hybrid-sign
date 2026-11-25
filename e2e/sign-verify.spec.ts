import { expect, test } from '@playwright/test';

test('an empty message and the prefilled example verify as distinct messages', async ({ page }) => {
  await page.goto('./');
  const message = page.locator('#sign-message');
  const context = page.locator('#sign-context');
  const sign = page.locator('#sign-btn');
  const verify = page.locator('#verify-btn');
  const result = page.locator('#verify-result');
  const gate = page.locator('#mech-out');
  const example = await message.inputValue();
  await page.locator('#gen-keypair').click();
  await sign.click();
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'ok');

  await message.fill('');
  await expect(result).toBeHidden();
  await expect(gate).toHaveAttribute('data-lit', 'idle');
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'fail');

  await page.locator('#expand-sig').click();
  await sign.click();
  await expect(sign).toBeEnabled();
  await expect(result).toBeHidden();
  await expect(page.locator('#sig-hex')).toHaveText(/^[0-9a-f]+$/);
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'ok');

  await message.fill(example);
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'fail');
  await message.fill('');
  await context.fill('classroom');
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'fail');
  await context.fill('');
  await expect(result).toBeHidden();
  await verify.click();
  await expect(gate).toHaveAttribute('data-lit', 'ok');
});

test('editing before signing finishes preserves the previous signature', async ({ page }) => {
  await page.goto('./');
  await page.locator('#gen-keypair').click();
  await page.locator('#sign-btn').click();
  await expect(page.locator('#verify-btn')).toBeEnabled();
  const original = await page.locator('#sig-hex').innerText();
  await page.evaluate(() => {
    document.querySelector<HTMLButtonElement>('#sign-btn')!.click();
    const message = document.querySelector<HTMLInputElement>('#sign-message')!;
    message.value = 'edited while signing';
    message.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await expect(page.locator('#sign-btn')).toBeEnabled();
  await expect(page.locator('#sig-hex')).toHaveText(original);
  await page.locator('#verify-btn').click();
  await expect(page.locator('#mech-out')).toHaveAttribute('data-lit', 'fail');
});
