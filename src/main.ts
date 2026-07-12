import './style.css';
import {
  generateCompositeKeyPair,
  compositeSign,
  compositeVerify,
  compositePublicKeyFrom,
  tamperMldsaPortion,
  tamperEd25519Portion,
  COMPOSITE_LABEL,
  COMPOSITE_PREFIX,
  COMPOSITE_SIG_BYTES,
  ML_DSA_65,
  ED25519,
  type CompositeKeyPair,
  type CompositePublicKey,
} from './composite';
import {
  simulateMldsaBreak,
  simulateQuantumBreak,
  simulateDoubleBreak,
  DOUBLE_BREAK_NARRATIVE,
  FORGED_MESSAGE_TEXT,
  type BreakResult,
} from './breaks';

// ── Helpers ────────────────────────────────────────────────────────────────
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`Element #${id} not found`);
  return e as T;
}

function setText(id: string, text: string): void {
  el(id).textContent = text;
}

function setHtml(id: string, html: string): void {
  el(id).innerHTML = html;
}

function show(id: string): void { el(id).classList.remove('hidden'); }
function hide(id: string): void { el(id).classList.add('hidden'); }

/**
 * Read the context input as bytes. The composite combiner encodes len(ctx) in a
 * single byte, so a context over 255 bytes is invalid (multibyte UTF-8 can blow
 * past the input's 255-char cap). Returns null and shows an inline error in that
 * case so callers abort cleanly instead of throwing into a dead spinner.
 */
function readContext(): Uint8Array | null {
  const ctxStr = el<HTMLInputElement>('sign-context').value;
  const ctx = ctxStr ? new TextEncoder().encode(ctxStr) : new Uint8Array(0);
  if (ctx.length > 255) {
    setText('ctx-error', `Context is ${ctx.length} bytes; the maximum is 255.`);
    show('ctx-error');
    return null;
  }
  hide('ctx-error');
  return ctx;
}

function readMessage(): Uint8Array {
  return new TextEncoder().encode(
    el<HTMLInputElement>('sign-message').value || 'Paul Clark certified 2026'
  );
}

function hexDisplay(bytes: Uint8Array, maxBytes = 32): string {
  const full = toHex(bytes);
  const preview = toHex(bytes.slice(0, maxBytes));
  const ellipsis = bytes.length > maxBytes ? `…(${bytes.length} bytes)` : '';
  return `<span class="hex-preview">${preview}${ellipsis}</span>`;
}

function verifyIcon(ok: boolean): string {
  return ok
    ? '<span class="lock-icon status-ok" aria-hidden="true">🔒</span>'
    : '<span class="lock-icon status-fail" aria-hidden="true">🔓</span>';
}

// ── State ──────────────────────────────────────────────────────────────────
let currentKeyPair: CompositeKeyPair | null = null;
let currentPublicKey: CompositePublicKey | null = null;
let currentSignature: Uint8Array | null = null;

// ── Render shell ───────────────────────────────────────────────────────────
function renderApp(): void {
  const app = document.getElementById('app')!;
  app.innerHTML = `
<a href="#main-content" class="skip-link">Skip to main content</a>

<header id="main-content" class="cl-hero" tabindex="-1">
  <div class="cl-hero-main">
    <h1 class="cl-hero-title"><span class="ed">Ed25519</span><span class="plus"> + </span><span class="pq">ML-DSA-65</span></h1>
    <p class="cl-hero-sub">PQ/T Composite · IETF LAMPS draft-16 · TLS 0x090B</p>
    <p class="cl-hero-desc">Generate a hybrid keypair, sign a message with both algorithms at once, then tamper with or break either half to watch the composite verifier accept only when Ed25519 <em>and</em> ML-DSA-65 both check out.</p>
  </div>
  <aside class="cl-hero-why" aria-label="Why it matters">
    <span class="cl-hero-why-label">WHY IT MATTERS</span>
    <p class="cl-hero-why-text">Signatures made today may need to verify for decades, well past the arrival of quantum computers. Binding a classical and a post-quantum algorithm together keeps a document authentic even if one entire family is later broken.</p>
  </aside>
</header>

<!-- ── Exhibit 1: Keypair ── -->
<section class="exhibit" id="exhibit1">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 1</span>
    <h2>The Composite Keypair</h2>
  </div>

  <div class="btn-row">
    <button class="btn btn-primary" id="gen-keypair">Generate Composite Keypair</button>
  </div>

  <div id="keypair-result" class="hidden" style="margin-top:1rem">
    <div class="keypair-grid">
      <div class="key-card ed-card">
        <h3>Ed25519 <span class="badge badge-classical">Classical</span></h3>
        <div class="key-row"><span class="key-label">Private</span>
          <span><span class="censor" id="ed-priv" aria-hidden="true">████████████████</span><span class="sr-only">withheld &mdash; never leaves the browser</span></span></div>
        <div class="key-row"><span class="key-label">Public</span>
          <span class="key-value" id="ed-pub">—</span></div>
        <div class="key-row"><span class="key-label">Size</span>
          <span>${ED25519.privateKeyBytes}B / ${ED25519.publicKeyBytes}B</span></div>
        <div class="key-row"><span class="key-label">Security</span>
          <span>128-bit classical</span></div>
        <div class="key-row"><span class="key-label">Broken by</span>
          <span style="color:var(--warn)">Quantum (Shor)</span></div>
      </div>
      <div class="key-card pq-card">
        <h3>ML-DSA-65 <span class="badge badge-pq">Post-Quantum</span></h3>
        <div class="key-row"><span class="key-label">Private</span>
          <span><span class="censor" id="pq-priv" aria-hidden="true">████████████████</span><span class="sr-only">withheld &mdash; never leaves the browser</span></span></div>
        <div class="key-row"><span class="key-label">Public</span>
          <span class="key-value" id="pq-pub">—</span></div>
        <div class="key-row"><span class="key-label">Size</span>
          <span>${ML_DSA_65.privateKeyBytes}B / ${ML_DSA_65.publicKeyBytes}B</span></div>
        <div class="key-row"><span class="key-label">Security</span>
          <span>~192-bit classical + PQ</span></div>
        <div class="key-row"><span class="key-label">Broken by</span>
          <span style="color:var(--success)">Nothing currently known</span></div>
      </div>
    </div>

    <div class="size-summary">
      <div class="size-row"><span>Combined private key</span><span class="size-val">${ED25519.privateKeyBytes + ML_DSA_65.privateKeyBytes} bytes</span></div>
      <div class="size-row"><span>Combined public key</span><span class="size-val">${ED25519.publicKeyBytes + ML_DSA_65.publicKeyBytes} bytes</span></div>
      <div class="size-row"><span>Composite signature</span><span class="size-val">${COMPOSITE_SIG_BYTES} bytes (ML-DSA ${ML_DSA_65.signatureBytes}B + Ed25519 ${ED25519.signatureBytes}B)</span></div>
      <div class="size-row"><span>Algorithm identifier</span><span class="size-val">${COMPOSITE_LABEL}</span></div>
      <div class="size-row"><span>TLS 1.3 codepoint</span><span class="size-val">0x090B (mldsa65_ed25519)</span></div>
    </div>
  </div>
</section>

<!-- ── Exhibit 2: Sign & Verify ── -->
<section class="exhibit" id="exhibit2">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 2</span>
    <h2>Sign and Verify</h2>
  </div>

  <div class="field">
    <label for="sign-message">Message</label>
    <input type="text" id="sign-message" value="Paul Clark certified 2026" />
  </div>
  <div class="field">
    <label for="sign-context">Context (optional)</label>
    <input type="text" id="sign-context" maxlength="255" placeholder="(leave blank for empty context)" aria-describedby="ctx-error" />
    <div id="ctx-error" class="field-error hidden" role="alert"></div>
  </div>

  <div class="btn-row">
    <button class="btn btn-primary" id="sign-btn" disabled aria-disabled="true">Sign with Composite</button>
    <button class="btn btn-neutral" id="verify-btn" disabled aria-disabled="true">Verify</button>
    <button class="btn btn-warn" id="tamper-mldsa-btn" disabled aria-disabled="true">Tamper ML-DSA portion</button>
    <button class="btn btn-danger" id="tamper-ed-btn" disabled aria-disabled="true">Tamper Ed25519 portion</button>
  </div>

  <div id="sign-steps" class="hidden" style="margin-top:1rem">
    <h4 style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.5rem">Signing steps:</h4>
    <ul class="steps">
      <li>M' = Prefix &Vert; Label &Vert; len(ctx) &Vert; ctx &Vert; <strong>SHA-512(M)</strong></li>
      <li>ML-DSA-65.Sign(sk, M', ctx=Label) → <span style="color:var(--pq-color)">${ML_DSA_65.signatureBytes} bytes</span></li>
      <li>Ed25519.Sign(sk, M') → <span style="color:var(--ed-color)">${ED25519.signatureBytes} bytes</span></li>
      <li>Concatenate: ML-DSA &Vert; Ed25519 → <strong style="color:var(--composite-ok)">${COMPOSITE_SIG_BYTES} bytes</strong></li>
    </ul>
    <div class="field">
      <label>Signature (<span id="sig-len">—</span> bytes)</label>
      <div class="hex-display" id="sig-hex">—</div>
      <div class="btn-row" style="margin-top:0.4rem">
        <button class="expand-btn" id="expand-sig" aria-expanded="false">Show full signature</button>
        <button class="expand-btn" id="copy-sig">Copy hex</button>
      </div>
    </div>
  </div>

  <div id="verify-result" class="hidden" aria-live="polite">
    <div class="verify-panel" id="verify-panel">—</div>
  </div>
</section>

<!-- ── Exhibit 3: Break Scenarios ── -->
<section class="exhibit" id="exhibit3">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 3</span>
    <h2>The Break Scenarios</h2>
  </div>

  <p class="narrative" style="margin-bottom:0.8rem">
    What happens when an attacker breaks <strong>one</strong> of the two algorithms?
    Each simulation forges a signature on the message
    &ldquo;<em id="forged-msg">—</em>&rdquo; and feeds it to the real verifier.
  </p>

  <details class="method-note">
    <summary>How these simulations stay honest</summary>
    <p>
      We can&rsquo;t actually break Ed25519 or ML-DSA-65 in a browser. We model an
      attacker&rsquo;s forging power instead: the <strong>broken</strong> component is
      signed with the real private key, so it genuinely verifies — exactly as a true
      forgery would. The <strong>intact</strong> component gets random bytes, which fail
      verification exactly as a forgery attempt would. Every ✓/✗ below is the literal
      output of <code>compositeVerify</code> on the forged signature. Nothing is faked.
    </p>
  </details>

  <div class="scenario">
    <h3 style="color:var(--pq-color)">Scenario 1 — ML-DSA Catastrophically Broken</h3>
    <p class="timeline">Timeline: 2028. Lattice cryptanalysis breakthrough. ML-DSA signatures can be forged without the private key.</p>
    <div class="btn-row">
      <button class="btn btn-pq" id="sim-mldsa-break" disabled aria-disabled="true">Simulate ML-DSA Break</button>
    </div>
    <div id="mldsa-break-result" class="hidden" aria-live="polite" style="margin-top:0.8rem"></div>
  </div>

  <div class="scenario">
    <h3 style="color:var(--ed-color)">Scenario 2 — Quantum Computer Arrives</h3>
    <p class="timeline">Timeline: 2035. CRQC operational. Shor's algorithm breaks Ed25519.</p>
    <div class="btn-row">
      <button class="btn btn-ed" id="sim-quantum-break" disabled aria-disabled="true">Simulate Quantum Break</button>
    </div>
    <div id="quantum-break-result" class="hidden" aria-live="polite" style="margin-top:0.8rem"></div>
  </div>

  <div class="scenario">
    <h3 style="color:var(--danger)">Scenario 3 — Both Algorithms Broken (the residual risk)</h3>
    <p class="timeline">Timeline: Unknown. Catastrophic simultaneous break of both algorithm families.</p>
    <div class="btn-row">
      <button class="btn btn-danger" id="sim-double-break" disabled aria-disabled="true">Simulate Double Break</button>
    </div>
    <div id="double-break-result" class="hidden" aria-live="polite" style="margin-top:0.8rem"></div>
    <div id="double-break-text" class="narrative" style="margin-top:0.6rem"></div>
  </div>
</section>

<!-- ── Exhibit 4: Comparison ── -->
<section class="exhibit" id="exhibit4">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 4</span>
    <h2>Composite vs Single Algorithm</h2>
  </div>

  <div class="table-wrap" role="region" aria-label="Signature comparison table (scrollable)" tabindex="0">
  <table class="compare-table" aria-label="Comparison of Ed25519, ML-DSA-65, and Composite signature properties">
    <thead>
      <tr>
        <th scope="col">Property</th>
        <th scope="col" class="ed-col">Ed25519</th>
        <th scope="col" class="pq-col">ML-DSA-65</th>
        <th scope="col" class="comp-col">Composite</th>
      </tr>
    </thead>
    <tbody>
      <tr><th scope="row">Private key</th><td class="ed-col">32 B</td><td class="pq-col">4,032 B</td><td class="comp-col">4,064 B</td></tr>
      <tr><th scope="row">Public key</th><td class="ed-col">32 B</td><td class="pq-col">1,952 B</td><td class="comp-col">1,984 B</td></tr>
      <tr><th scope="row">Signature</th><td class="ed-col">64 B</td><td class="pq-col">3,309 B</td><td class="comp-col">${COMPOSITE_SIG_BYTES} B</td></tr>
      <tr><th scope="row">Classical security</th><td class="ed-col">128 bits</td><td class="pq-col">~192 bits</td><td class="comp-col">~192 bits (min)</td></tr>
      <tr><th scope="row">PQ security</th><td class="ed-col" style="color:var(--danger)">0 (broken by Shor)</td><td class="pq-col">~192 bits</td><td class="comp-col">~192 bits</td></tr>
      <tr><th scope="row">Survives single break</th><td class="ed-col" style="color:var(--danger)">No</td><td class="pq-col" style="color:var(--danger)">No</td><td class="comp-col" style="color:var(--success)"><strong>Yes</strong></td></tr>
      <tr><th scope="row">Standardization</th><td class="ed-col">RFC 8032</td><td class="pq-col">FIPS 204</td><td class="comp-col">IETF LAMPS draft-16</td></tr>
    </tbody>
  </table>
  </div>

  <div style="margin-top:1rem">
    <h3 style="font-size:0.88rem;margin-bottom:0.6rem;color:var(--text-muted)">TLS 1.3 SignatureScheme registry</h3>
    <pre>0x090A: mldsa44_ecdsa_secp256r1_sha256   (Level 2 + P-256)
0x090B: mldsa65_ed25519                   (Level 3 + Ed25519) ← this demo
SSH:    ssh-ed25519-ml-dsa-65             (draft-josefsson-ssh-ed25519mldsa65)
X.509:  id-MLDSA65-Ed25519-SHA512         (draft-ietf-lamps-pq-composite-sigs-16)</pre>
  </div>
</section>

<!-- ── Exhibit 5: Why This Matters ── -->
<section class="exhibit" id="exhibit5">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 5</span>
    <h2>Why This Matters for Long-Lived Signatures</h2>
  </div>

  <p class="narrative" style="margin-bottom:1rem">
    <strong>The 25-year threat model:</strong> Data signed today may need to verify authenticity
    in 2035, 2040, or 2050. A quantum computer could exist by then. Composite signatures ensure
    that even if <em>one</em> algorithm falls — classically or via quantum — your signatures
    remain valid under the other.
  </p>

  <h3 style="font-size:0.88rem;margin-bottom:0.6rem">The crypto-lab story arc</h3>
  <div class="arc-grid">
    <div class="arc-card">
      <div class="arc-label">KEM side — key exchange</div>
      <div>X25519 → <a href="https://systemslibrarian.github.io/crypto-lab-x3dh-wire/">crypto-lab-x3dh-wire</a></div>
      <div>ML-KEM-768 → <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/">crypto-lab-kyber-vault</a></div>
      <div>X25519 + ML-KEM-768 → <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-wire/">crypto-lab-hybrid-wire</a></div>
    </div>
    <div class="arc-card arc-this">
      <div class="arc-label">Signature side — authentication ← you are here</div>
      <div>Ed25519 → <a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/">crypto-lab-ed25519-forge</a></div>
      <div>ML-DSA-65 → <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/">crypto-lab-dilithium-seal</a></div>
      <div style="color:var(--composite-ok);font-weight:600">Ed25519 + ML-DSA-65 → <strong>THIS DEMO</strong></div>
    </div>
  </div>

  <h3 style="font-size:0.88rem;margin:1rem 0 0.6rem">Real-world deployment</h3>
  <p class="narrative">
    IETF LAMPS <strong>draft-ietf-lamps-pq-composite-sigs-16</strong> (April 2026) standardizes
    composite signatures for X.509 and CMS. TLS 1.3 has codepoints <code>0x090A</code> and
    <code>0x090B</code>. SSH has <strong>draft-josefsson-ssh-ed25519mldsa65-01</strong>. PKI
    vendors Entrust and DigiCert have prototyped composite CA issuance. Microsoft announced
    composite signature support in Windows code-signing for 2026. The scheme is designed for
    the migration period (~2025–2035) while PQ crypto earns decades of cryptanalytic confidence.
  </p>
</section>

<footer>
  <p>No backends. All cryptography runs in your browser.</p>
  <p style="margin-top:0.4rem">
    <span class="chip">@noble/curves Ed25519</span>
    <span class="chip">@noble/post-quantum ML-DSA-65</span>
    <span class="chip">IETF LAMPS draft-16</span>
    <span class="chip">TLS 0x090B</span>
  </p>
  <p style="margin-top:0.4rem">
    Related demos:
    <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer">crypto-lab-dilithium-seal</a>
    <a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/" target="_blank" rel="noreferrer">crypto-lab-ed25519-forge</a>
    <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-guide/" target="_blank" rel="noreferrer">crypto-lab-hybrid-guide</a>
    <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-wire/" target="_blank" rel="noreferrer">crypto-lab-hybrid-wire</a>
    <a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/" target="_blank" rel="noreferrer">crypto-lab-pki-chain</a>
  </p>
</footer>
`;
}

// ── Wire up events ─────────────────────────────────────────────────────────
function wireEvents(): void {
  // Theme is owned by the shared crypto-lab header (in index.html).

  // Exhibit 1 — generate keypair
  el('gen-keypair').addEventListener('click', () => {
    const btn = el<HTMLButtonElement>('gen-keypair');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Generating…';

    // Yield to DOM before heavy computation
    setTimeout(() => {
      currentKeyPair = generateCompositeKeyPair();
      currentPublicKey = compositePublicKeyFrom(currentKeyPair);
      currentSignature = null;
      hide('sign-steps');
      hide('verify-result');
      el<HTMLButtonElement>('verify-btn').disabled = true;
      el<HTMLButtonElement>('tamper-mldsa-btn').disabled = true;
      el<HTMLButtonElement>('tamper-ed-btn').disabled = true;

      setHtml('ed-pub', `<span class="key-value">${toHex(currentKeyPair.ed25519.publicKey).slice(0, 16)}…</span>`);
      setHtml('pq-pub', `<span class="key-value">${toHex(currentKeyPair.mldsa.publicKey).slice(0, 16)}…</span>`);

      show('keypair-result');
      btn.disabled = false;
      btn.textContent = 'Regenerate Keypair';

      // Enable sign button
      const signBtn2 = el<HTMLButtonElement>('sign-btn');
      signBtn2.disabled = false;
      signBtn2.removeAttribute('aria-disabled');

      // Enable break simulation buttons
      const mldsaBreakBtn = el<HTMLButtonElement>('sim-mldsa-break');
      mldsaBreakBtn.disabled = false;
      mldsaBreakBtn.removeAttribute('aria-disabled');
      const qBreakBtn = el<HTMLButtonElement>('sim-quantum-break');
      qBreakBtn.disabled = false;
      qBreakBtn.removeAttribute('aria-disabled');
      const dBreakBtn = el<HTMLButtonElement>('sim-double-break');
      dBreakBtn.disabled = false;
      dBreakBtn.removeAttribute('aria-disabled');

      // Populate double-break scenario text + forged-message label
      setText('forged-msg', FORGED_MESSAGE_TEXT);
      el('double-break-text').textContent = DOUBLE_BREAK_NARRATIVE;
    }, 10);
  });

  // Exhibit 2 — sign
  el('sign-btn').addEventListener('click', () => {
    if (!currentKeyPair) return;
    const btn = el<HTMLButtonElement>('sign-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing…';

    setTimeout(() => {
      const ctx = readContext();
      if (ctx === null) {
        btn.disabled = false;
        btn.textContent = 'Sign with Composite';
        return;
      }
      const msg = readMessage();

      currentSignature = compositeSign(currentKeyPair!, msg, ctx);

      setText('sig-len', String(currentSignature.length));
      el('sig-hex').textContent = toHex(currentSignature.slice(0, 48)) + '…';
      show('sign-steps');

      // Enable remaining buttons
      const verifyBtnEl = el<HTMLButtonElement>('verify-btn');
      verifyBtnEl.disabled = false;
      verifyBtnEl.removeAttribute('aria-disabled');
      const tamperMldsaBtnEl = el<HTMLButtonElement>('tamper-mldsa-btn');
      tamperMldsaBtnEl.disabled = false;
      tamperMldsaBtnEl.removeAttribute('aria-disabled');
      const tamperEdBtnEl = el<HTMLButtonElement>('tamper-ed-btn');
      tamperEdBtnEl.disabled = false;
      tamperEdBtnEl.removeAttribute('aria-disabled');

      btn.disabled = false;
      btn.textContent = 'Sign with Composite';
    }, 10);
  });

  // Expand signature hex
  el('expand-sig').addEventListener('click', () => {
    if (!currentSignature) return;
    const hexEl = el('sig-hex');
    const expandBtn = el<HTMLButtonElement>('expand-sig');
    if (hexEl.classList.contains('expanded')) {
      hexEl.textContent = toHex(currentSignature.slice(0, 48)) + '…';
      hexEl.classList.remove('expanded');
      expandBtn.textContent = 'Show full signature';
      expandBtn.setAttribute('aria-expanded', 'false');
    } else {
      hexEl.textContent = toHex(currentSignature);
      hexEl.classList.add('expanded');
      expandBtn.textContent = 'Collapse';
      expandBtn.setAttribute('aria-expanded', 'true');
    }
  });

  // Copy full signature hex to clipboard
  el('copy-sig').addEventListener('click', async () => {
    if (!currentSignature) return;
    const btn = el<HTMLButtonElement>('copy-sig');
    try {
      await navigator.clipboard.writeText(toHex(currentSignature));
      btn.textContent = 'Copied ✓';
    } catch {
      btn.textContent = 'Copy failed';
    }
    setTimeout(() => { btn.textContent = 'Copy hex'; }, 1500);
  });

  // Exhibit 2 — verify
  el('verify-btn').addEventListener('click', () => {
    if (!currentSignature || !currentPublicKey) return;
    verifyAndDisplay(currentSignature, 'Clean signature');
  });

  el('tamper-mldsa-btn').addEventListener('click', () => {
    if (!currentSignature) return;
    verifyAndDisplay(tamperMldsaPortion(currentSignature), 'Tampered ML-DSA portion');
  });

  el('tamper-ed-btn').addEventListener('click', () => {
    if (!currentSignature) return;
    verifyAndDisplay(tamperEd25519Portion(currentSignature), 'Tampered Ed25519 portion');
  });

  // Exhibit 3 — break simulations (all three share one honest renderer)
  wireBreakButton('sim-mldsa-break', 'Simulate ML-DSA Break', 'mldsa-break-result', 'mldsa');
  wireBreakButton('sim-quantum-break', 'Simulate Quantum Break', 'quantum-break-result', 'quantum');
  wireBreakButton('sim-double-break', 'Simulate Double Break', 'double-break-result', 'double');
}

type BreakKind = 'mldsa' | 'quantum' | 'double';

function statusCell(valid: boolean): string {
  return valid
    ? '<span class="status-ok">✓ VALID</span>'
    : '<span class="status-fail">✗ INVALID</span>';
}

function renderBreakResult(kind: BreakKind, r: BreakResult): string {
  // Outcome line.
  let verdict: string;
  if (kind === 'double') {
    verdict = r.forgedValid
      ? '<strong style="color:var(--danger)">Composite FORGED.</strong> Both families fell at once, so both components verify and the composite accepts the forgery. This is the residual risk — defense in depth, not invincibility.'
      : '<strong style="color:var(--danger)">Unexpected: composite rejected a double-forged signature.</strong>';
  } else {
    const guardName = r.caughtBy === 'ed25519' ? 'Ed25519' : 'ML-DSA-65';
    const guardKind = r.caughtBy === 'ed25519' ? 'classical' : 'post-quantum';
    verdict = !r.forgedValid && r.caughtBy !== 'none'
      ? `<strong style="color:var(--success)">${guardName} caught the forgery.</strong> One algorithm was broken, but the intact ${guardKind} component held — so the composite rejects.`
      : '<strong style="color:var(--danger)">Unexpected: composite accepted the forged signature.</strong>';
  }

  // Per-component description of what the attacker did.
  const mldsaForged = kind !== 'quantum'; // forged (valid) in mldsa-break and double-break
  const edForged = kind !== 'mldsa';      // forged (valid) in quantum-break and double-break
  const mldsaNote = mldsaForged ? 'forged by attacker' : 'attacker cannot forge';
  const edNote = edForged
    ? (kind === 'quantum' ? 'quantum-forged via Shor' : 'forged by attacker')
    : 'attacker cannot forge';

  const compositeCell = r.forgedValid
    ? '<span class="status-comp-fail">✓ ACCEPTED — forgery succeeds</span>'
    : '<span class="status-comp-ok">✗ REJECTED — forgery stopped</span>';

  return `
    <div class="verify-panel">
      <div class="verify-row">
        <span style="color:var(--pq-color)">ML-DSA-65 (${mldsaNote}):</span>
        <span>${statusCell(r.forgedMldsaValid)}</span>
      </div>
      <div class="verify-row">
        <span style="color:var(--ed-color)">Ed25519 (${edNote}):</span>
        <span>${statusCell(r.forgedEd25519Valid)}</span>
      </div>
      <div class="verify-row">
        <span>Forged composite:</span>
        <span>${compositeCell}</span>
      </div>
      <p class="narrative" style="margin-top:0.6rem">${verdict}</p>
    </div>`;
}

function wireBreakButton(
  btnId: string,
  label: string,
  resultId: string,
  kind: BreakKind
): void {
  el(btnId).addEventListener('click', () => {
    if (!currentKeyPair) return;
    const btn = el<HTMLButtonElement>(btnId);
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Simulating…';

    setTimeout(() => {
      const r =
        kind === 'mldsa' ? simulateMldsaBreak(currentKeyPair!) :
        kind === 'quantum' ? simulateQuantumBreak(currentKeyPair!) :
        simulateDoubleBreak(currentKeyPair!);
      setHtml(resultId, renderBreakResult(kind, r));
      show(resultId);
      btn.disabled = false;
      btn.textContent = label;
    }, 10);
  });
}

function verifyAndDisplay(sig: Uint8Array, label: string): void {
  if (!currentPublicKey) return;
  const ctx = readContext();
  if (ctx === null) return;
  const msg = readMessage();

  const r = compositeVerify(currentPublicKey, msg, sig, ctx);

  const html = `
    <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem">${label}</div>
    <div class="verify-row">
      ${verifyIcon(r.ed25519Valid)}
      <span style="color:var(--ed-color)">Ed25519 verification:</span>
      <span class="${r.ed25519Valid ? 'status-ok' : 'status-fail'}">${r.ed25519Valid ? '✓ VALID' : '✗ INVALID'}</span>
    </div>
    <div class="verify-row">
      ${verifyIcon(r.mldsaValid)}
      <span style="color:var(--pq-color)">ML-DSA-65 verification:</span>
      <span class="${r.mldsaValid ? 'status-ok' : 'status-fail'}">${r.mldsaValid ? '✓ VALID' : '✗ INVALID'}</span>
    </div>
    <div class="verify-row">
      ${verifyIcon(r.valid)}
      <span>COMPOSITE:</span>
      <span class="${r.valid ? 'status-comp-ok' : 'status-comp-fail'}">
        ${r.valid ? '✓ VALID' : `✗ INVALID ${!r.mldsaValid && r.ed25519Valid ? '(caught by ML-DSA-65)' : ''}${r.mldsaValid && !r.ed25519Valid ? '(caught by Ed25519)' : ''}${!r.mldsaValid && !r.ed25519Valid ? '(both failed)' : ''}`}
      </span>
    </div>
  `;
  setHtml('verify-panel', html);
  show('verify-result');
}

// ── Boot ───────────────────────────────────────────────────────────────────
renderApp();
wireEvents();

// Boot-time self-test: prove spec-prefix bytes and a full sign/verify/tamper
// round-trip in the console, so a curious visitor can confirm it's real.
// Deferred off the boot path — the ML-DSA keygen + signs are heavy enough to
// stall first paint on a phone, and nothing in the UI depends on it.
function runSelfTest(): void {
  const EXPECTED_PREFIX =
    '436f6d706f73697465416c676f726974686d5369676e61747572657332303235';
  const prefixHex = toHex(COMPOSITE_PREFIX);
  const prefixOk = prefixHex.toLowerCase() === EXPECTED_PREFIX;

  const kp = generateCompositeKeyPair();
  const pub = compositePublicKeyFrom(kp);
  const msg = new TextEncoder().encode('self-test');
  const sig = compositeSign(kp, msg);
  const clean = compositeVerify(pub, msg, sig).valid;
  const edTamper = !compositeVerify(pub, msg, tamperEd25519Portion(sig)).valid;
  const mldsaTamper = !compositeVerify(pub, msg, tamperMldsaPortion(sig)).valid;
  const ok = prefixOk && clean && edTamper && mldsaTamper;

  console.info(
    `%c[composite-sign] self-test ${ok ? 'PASSED ✓' : 'FAILED ✗'}`,
    `color:${ok ? '#00e676' : '#ff3366'};font-weight:700`,
    { prefixOk, cleanVerifies: clean, edTamperRejected: edTamper, mldsaTamperRejected: mldsaTamper }
  );
}

const ric = (window as unknown as {
  requestIdleCallback?: (cb: () => void) => void;
}).requestIdleCallback;
if (ric) ric(runSelfTest);
else setTimeout(runSelfTest, 200);
