import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `revealAll()` pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the suite was structurally unable to see a defect in the one block a
 *     reader with the preference actually gets. `boot` asks for the preference
 *     and ASSERTS it took effect instead.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `revealAll()` opened every `<details>`,
 *     stripped `.hidden` off every element, and added `.expanded` to the hex
 *     readout. This lab hides five panels that way — `#keypair-result`,
 *     `#sign-steps`, `#verify-result` and the four break-result panels — and all
 *     of them are EMPTY until their button has been pressed. Un-hiding them
 *     produced a document no visitor can load: every panel open, every one
 *     showing an em-dash placeholder. This gate never touches `class`, `hidden`
 *     or `open`; every panel is revealed by the control that reveals it, and
 *     each `<details>` is opened by clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, WITHOUT PRESSING ANYTHING. The old
 *     suite never clicked a single control, so no keypair, no signature, no
 *     verification, no tamper and none of the four break scenarios had ever been
 *     scanned — which is the entire lab. This drive scans after every step, in
 *     {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: every lit lock
 *     tints its surface with `color-mix()`, which axe files under `incomplete`;
 *     and SC 1.4.11 has no axe rule at all, which is where this lab's real
 *     defects were.
 *
 *  5. IT HAD NO REFLOW OR KEYBOARD-SCROLLER ORACLE, and this page needs both.
 *     The TLS SignatureScheme `<pre>` and the 480px-min comparison table both
 *     scroll horizontally at 380px, and the message input is echoed into prose
 *     as the forgery target — so an unbroken token typed there is a reflow
 *     failure that only exists in a state the drive has to go and build.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `style.css` declares exactly one
 * `@keyframes` (`spin`, on the in-button `.spinner`), which animates `transform`
 * and not `opacity`, and its reduced-motion block clamps durations and sets
 * `.spinner { animation: none }` — a ring that no longer turns, but is still
 * drawn. The check runs in every state regardless, because those are properties
 * of the current stylesheet rather than of the page.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 *
 * `console.info` is deliberately not collected: `main.ts` prints a self-test
 * banner there on every load.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This lab renders its hero as a `<header class="cl-hero">` inside
 * `<div id="app" role="main">`, and a `<header>` only implies `banner` when it
 * is not scoped inside sectioning content. `role="main"` on a DIV does not scope
 * it — `index.html`'s `dedupeBanner()` tests `el.closest('main, article, aside,
 * nav, section')`, which is a TAG selector and does not match a role. So the
 * hero is demoted by the explicit `dedupeBanner()` pass rather than by its
 * nesting, and that pass runs after `main.ts` has rendered only because module
 * scripts execute before `DOMContentLoaded`. Asserting the OUTCOME rather than
 * either mechanism means a change to any link in that chain is caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** The five panels that ship hidden, with the control that reveals each. */
export const HIDDEN_PANELS = [
  { sel: '#keypair-result', by: '#gen-keypair' },
  { sel: '#sign-steps', by: '#sign-btn' },
  { sel: '#verify-result', by: '#verify-btn' },
  { sel: '#no-break-result', by: '#sim-no-break' },
  { sel: '#mldsa-break-result', by: '#sim-mldsa-break' },
  { sel: '#quantum-break-result', by: '#sim-quantum-break' },
  { sel: '#double-break-result', by: '#sim-double-break' },
] as const;

/** The eight controls that ship DISABLED until a prerequisite has been run. */
export const LOCKED_CONTROLS = [
  '#sign-btn',
  '#verify-btn',
  '#tamper-mldsa-btn',
  '#tamper-ed-btn',
  '#sim-no-break',
  '#sim-mldsa-break',
  '#sim-quantum-break',
  '#sim-double-break',
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because this lab ships almost entirely
 * LOCKED. One of nine controls is enabled, seven panels are behind `.hidden`,
 * and the AND-gate diagram sits at `data-lit="idle"` with both locks reading
 * "awaiting verify". That arrival state is the first thing every reader sees and
 * the gate this replaces never scanned it — it stripped `.hidden` from all seven
 * panels first, producing a page of em-dash placeholders.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // `main.ts` renders the whole document body into #app, so a navigation that
  // resolves proves nothing on its own.
  await expect(page.locator('#gen-keypair')).toBeEnabled();
  await expect(page.locator('.exhibit')).toHaveCount(5);

  // ── Everything this lab generates ships absent ───────────────────────────
  for (const { sel } of HIDDEN_PANELS) await expect(page.locator(sel)).toBeHidden();
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#sign-message')).toHaveValue('Paul Clark certified 2026');
  await expect(page.locator('#sign-context')).toHaveValue('');
  await expect(page.locator('#ctx-error')).toBeHidden();
  await expect(page.locator('#expand-sig')).toHaveAttribute('aria-expanded', 'false');

  // ── The AND-gate diagram ships idle, with both locks unlit ───────────────
  // This is the one exhibit whose state is carried by an attribute rather than
  // by whether a panel exists, so a wrong default here would be invisible.
  await expect(page.locator('#mech-flow')).toHaveAttribute('data-state', 'idle');
  for (const id of ['#mech-lock-ed', '#mech-lock-pq', '#mech-out']) {
    await expect(page.locator(id)).toHaveAttribute('data-lit', 'idle');
  }
  await expect(page.locator('#mech-state-ed')).toHaveText('awaiting verify');
  await expect(page.locator('#mech-state-pq')).toHaveText('awaiting verify');
  await expect(page.locator('#mech-out-label')).toHaveText('ACCEPT / REJECT');

  // Both disclosures ship shut.
  await expect(page.locator('details')).toHaveCount(2);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is a
 * plausible offender: a `min-width: 480px` comparison table, a `<pre>` of TLS
 * registry lines, 6,746 hex characters when the signature is expanded, and a
 * free-text message input whose contents are echoed back into prose as the
 * message a forgery targets.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than a
    // scrollbar, and invisible to the standard check. This lab does NOT have
    // that rule today; the test is kept because adding one is the usual way a
    // reflow failure gets "fixed", and this oracle has to survive that.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // comparison table has a huge bounding rect but is clipped by `.table-wrap`
    // and contributes nothing to the document's scroll width — naming it sends
    // you off fixing the wrong element, which has cost a run elsewhere in this
    // fleet.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is. With the viewport clipping,
    // falling back to the widest CLIPPED element would report a decoy forever.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0]!;
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * Three containers on this page scroll: `.table-wrap` and `.hex-display`, which
 * both carry `role="region"`, `tabindex="0"` and an `aria-label`, and the TLS
 * SignatureScheme `<pre>`, which did not — it is `overflow-x: auto` around lines
 * ~55 characters wide and overflows at every viewport below ~520px, so its
 * content was unreachable without a mouse. That is a defect this drive found and
 * the source now fixes; the assertion stays because the convention is not
 * enforced anywhere else.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) and generated content live in `nontext.ts`.
 *
 * There was no such check here before, and the palette shows why one was
 * needed. `style.css` defines `--border-strong` with a comment deriving three
 * ratios for it — and applies it to exactly ONE rule, `.field input, .field
 * textarea`, against 34 uses of `--border`, the SURFACE divider. Every button on
 * this page therefore drew its boundary from its own fill alone, and the fills
 * are declared "constant across themes": gold `#ffd700` measured 1.40:1 against
 * the white light-theme exhibit it sits on, and `.btn-neutral` — the Verify
 * button — measured 1.22:1 in dark. Do not narrow that query back to the inputs;
 * that is precisely the set the token was already correctly applied to.
 *
 * One deliberate exclusion is applied here rather than in `nontext.ts`: the
 * shared top bar. It is not this lab's to change — every repo in the fleet
 * carries a copy — and its `.cl-btn` boundary
 * (`color-mix(in srgb, var(--accent) 38%, transparent)` over `#0b1512`) measures
 * 1.68:1 in dark and 1.23:1 in light here, as it does everywhere. That is
 * reported upward as a fleet-wide observation rather than patched in one repo,
 * and it is written down so the exclusion is a decision and not an oversight.
 */
const SHARED_HEADER_PREFIXES = ['a.cl-skip-link', 'button#cl-theme-toggle', 'a.cl-btn'];

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since every lit
 *    lock and every verdict surface is a `color-mix()` axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not finish
 *    — including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides, a defect that never reaches the violations array
 *    at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls, and the ink of every
 *    `::before`/`::after` — SC 1.4.11 and 1.4.3 for generated content, neither
 *    of which axe has any rule for and neither of which the element walk in
 *    `contrast.ts` can reach; see `nontext.ts`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const nonText = (await auditNonText(page)).filter(
    (f) => !SHARED_HEADER_PREFIXES.some((p) => f.selector.startsWith(p))
  );
  softExpect(
    Array.from(new Set(formatNonTextFailures(nonText))),
    `non-text contrast (SC 1.4.11) and generated content in state: ${label}`,
    []
  );

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
  await expectNoNewNonTextFailures(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Open one `<details>` by clicking its summary, and assert it opened. */
async function openDisclosure(page: Page, selector: string): Promise<void> {
  const d = page.locator(selector);
  await expect(d).not.toHaveAttribute('open', '');
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/** Focus a skip link so its "visually hidden until focused" state is measured. */
async function focusSkipLink(page: Page, selector: string): Promise<void> {
  await page.locator(selector).focus();
  await expect(page.locator(selector)).toBeFocused();
}

/**
 * Wait for a break/verify simulation to finish.
 *
 * Every one of these handlers disables its button, swaps in a `.spinner`, and
 * only restores the label on the far side of the work. Waiting for the label to
 * come back is the real completion signal — a fixed timeout would either race
 * the ML-DSA keygen (which is the slow part) or waste seconds on every step.
 */
async function waitForButton(page: Page, id: string, label: string): Promise<void> {
  await expect(page.locator(id)).toHaveText(label);
  await expect(page.locator(id)).toBeEnabled();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * The shape of this drive is set by the lab's prerequisite chain: nothing works
 * until a keypair exists, the tamper and verify controls need a signature on top
 * of that, and the AND-gate diagram is reset to idle by both. So the order is
 * locked state → keypair → signature → each verify/tamper branch → each of the
 * four break scenarios → error state → regenerate (which is this lab's Reset,
 * and puts the diagram and three of the panels back).
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const s = (label: string): Promise<void> => scan(page, `${theme} / ${label}`);

  // ── The arrival state: one enabled control, seven empty panels ───────────
  await s('first paint (all locked)');

  // Both "visually hidden until focused" skip links, in their focused state.
  await focusSkipLink(page, '.cl-skip-link');
  await s('shared skip link focused');
  await focusSkipLink(page, '.skip-link');
  await s('lab skip link focused');

  // The two disclosures, opened through their own summaries.
  await openDisclosure(page, 'details.method-note');
  await s('method note open');
  await openDisclosure(page, 'details.why-shor-more');
  await s('why-shor detail open');

  // ── Exhibit 1: the composite keypair ────────────────────────────────────
  await page.locator('#gen-keypair').click();
  await expect(page.locator('#keypair-result')).toBeVisible();
  await waitForButton(page, '#gen-keypair', 'Regenerate Keypair');
  // The keypair unlocks five controls; assert that rather than assuming it.
  for (const id of ['#sign-btn', '#sim-no-break', '#sim-mldsa-break', '#sim-quantum-break', '#sim-double-break']) {
    await expect(page.locator(id)).toBeEnabled();
  }
  await expect(page.locator('#verify-btn')).toBeDisabled();
  await s('keypair generated');

  // ── Exhibit 2: sign ─────────────────────────────────────────────────────
  await page.locator('#sign-btn').click();
  await expect(page.locator('#sign-steps')).toBeVisible();
  await waitForButton(page, '#sign-btn', 'Sign with Composite');
  await expect(page.locator('#sig-len')).toHaveText('3373');
  await s('signed');

  // The expanded hex readout: 6,746 characters in one `overflow-y: auto` box.
  await page.locator('#expand-sig').click();
  await expect(page.locator('#expand-sig')).toHaveAttribute('aria-expanded', 'true');
  await s('full signature expanded');
  await page.locator('#expand-sig').click();
  await expect(page.locator('#expand-sig')).toHaveAttribute('aria-expanded', 'false');
  await s('full signature collapsed');

  // The copy confirmation is a 1500ms label swap — a real, reachable state.
  await page.locator('#copy-sig').click();
  await expect(page.locator('#copy-sig')).toHaveText('Copied ✓');
  await s('copy confirmed');
  await expect(page.locator('#copy-sig')).toHaveText('Copy hex', { timeout: 5_000 });

  // ── Both verify branches, and both tamper branches ──────────────────────
  await page.locator('#verify-btn').click();
  await expect(page.locator('#verify-result')).toBeVisible();
  await expect(page.locator('#mech-out')).toHaveAttribute('data-lit', 'ok');
  await s('verified clean (both locks lit green)');

  await page.locator('#tamper-mldsa-btn').click();
  await expect(page.locator('#mech-lock-pq')).toHaveAttribute('data-lit', 'fail');
  await expect(page.locator('#mech-lock-ed')).toHaveAttribute('data-lit', 'ok');
  await expect(page.locator('#sig-hex-pq .sig-flip').first()).toBeVisible();
  await s('ML-DSA half tampered (flip marks lit)');

  await page.locator('#tamper-ed-btn').click();
  await expect(page.locator('#mech-lock-ed')).toHaveAttribute('data-lit', 'fail');
  await expect(page.locator('#mech-lock-pq')).toHaveAttribute('data-lit', 'ok');
  await s('Ed25519 half tampered (flip marks lit)');

  // ── Exhibit 3: every branch of the break fork ───────────────────────────
  const scenarios = [
    { btn: '#sim-no-break', label: 'Simulate Forgery Attempt', panel: '#no-break-result', lit: 'idle' },
    { btn: '#sim-mldsa-break', label: 'Simulate ML-DSA Break', panel: '#mldsa-break-result', lit: 'idle' },
    { btn: '#sim-quantum-break', label: 'Simulate Quantum Break', panel: '#quantum-break-result', lit: 'idle' },
    { btn: '#sim-double-break', label: 'Simulate Double Break', panel: '#double-break-result', lit: 'ok' },
  ] as const;
  for (const sc of scenarios) {
    await page.locator(sc.btn).click();
    await expect(page.locator(sc.panel)).toBeVisible();
    await waitForButton(page, sc.btn, sc.label);
    await expect(page.locator(`${sc.panel} .verify-panel`)).toBeVisible();
    // The double break is the only scenario whose forgery is ACCEPTED — the
    // residual risk the exhibit exists to show. Asserting it here means a drive
    // that silently stopped reaching the negative case fails rather than passes.
    await expect(page.locator('#mech-out')).toHaveAttribute(
      'data-lit',
      sc.btn === '#sim-double-break' ? 'ok' : 'fail'
    );
    await s(`break scenario ${sc.btn.replace('#sim-', '')}`);
  }

  // ── The error state, and a long free-text message in prose ──────────────
  // 256 multibyte characters: over the combiner's single-byte len(ctx) cap, so
  // `readContext` aborts and reveals the `role="alert"` panel.
  await page.locator('#sign-context').fill('é'.repeat(200));
  await page.locator('#sign-btn').click();
  await expect(page.locator('#ctx-error')).toBeVisible();
  await expect(page.locator('#ctx-error')).toContainText('the maximum is 255');
  await s('context too long (inline error)');
  await page.locator('#sign-context').fill('');

  // A long unbroken token in the message input is echoed straight into prose as
  // the forgery target, and into the forged-detail line under every verdict.
  await page.locator('#sign-message').fill('a'.repeat(90));
  await page.locator('#sim-quantum-break').click();
  await waitForButton(page, '#sim-quantum-break', 'Simulate Quantum Break');
  await expect(page.locator('#forged-msg')).toContainText('aaaa');
  await s('long unbroken message echoed into prose');
  await page.locator('#sign-message').fill('Paul Clark certified 2026');

  // ── Regenerate: this lab's Reset ────────────────────────────────────────
  await page.locator('#gen-keypair').click();
  await waitForButton(page, '#gen-keypair', 'Regenerate Keypair');
  await expect(page.locator('#sign-steps')).toBeHidden();
  await expect(page.locator('#verify-result')).toBeHidden();
  await expect(page.locator('#mech-out')).toHaveAttribute('data-lit', 'idle');
  await expect(page.locator('#verify-btn')).toBeDisabled();
  await s('keypair regenerated (diagram back to idle)');
}
