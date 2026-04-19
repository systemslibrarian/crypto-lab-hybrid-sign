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
import { simulateMldsaBreak, simulateQuantumBreak, simulateDoubleBreak } from './breaks';

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

function hexDisplay(bytes: Uint8Array, maxBytes = 32): string {
  const full = toHex(bytes);
  const preview = toHex(bytes.slice(0, maxBytes));
  const ellipsis = bytes.length > maxBytes ? `…(${bytes.length} bytes)` : '';
  return `<span class="hex-preview">${preview}${ellipsis}</span>`;
}

function verifyIcon(ok: boolean): string {
  return ok
    ? '<span class="lock-icon status-ok">🔒</span>'
    : '<span class="lock-icon status-fail">🔓</span>';
}

// ── State ──────────────────────────────────────────────────────────────────
let currentKeyPair: CompositeKeyPair | null = null;
let currentPublicKey: CompositePublicKey | null = null;
let currentSignature: Uint8Array | null = null;

// ── Render shell ───────────────────────────────────────────────────────────
function renderApp(): void {
  const app = document.getElementById('app')!;
  app.innerHTML = `
<button class="theme-btn" id="theme-toggle">☀ / ☾</button>

<header>
  <h1>
    <span class="ed">Ed25519</span>
    <span class="plus"> + </span>
    <span class="pq">ML-DSA-65</span>
  </h1>
  <p>PQ/T Composite Signatures &bull; IETF LAMPS draft-ietf-lamps-pq-composite-sigs-16 &bull; TLS codepoint 0x090B</p>
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
          <span class="censor" id="ed-priv">████████████████</span></div>
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
          <span class="censor" id="pq-priv">████████████████</span></div>
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
    <label>Message</label>
    <input type="text" id="sign-message" value="Paul Clark certified 2026" />
  </div>
  <div class="field">
    <label>Context (optional)</label>
    <input type="text" id="sign-context" placeholder="(leave blank for empty context)" />
  </div>

  <div class="btn-row">
    <button class="btn btn-primary" id="sign-btn" disabled>Sign with Composite</button>
    <button class="btn btn-neutral" id="verify-btn" disabled>Verify</button>
    <button class="btn btn-warn" id="tamper-mldsa-btn" disabled>Tamper ML-DSA portion</button>
    <button class="btn btn-danger" id="tamper-ed-btn" disabled>Tamper Ed25519 portion</button>
  </div>

  <div id="sign-steps" class="hidden" style="margin-top:1rem">
    <h4 style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.5rem">Signing steps:</h4>
    <ul class="steps">
      <li>Build M' = Prefix || Domain || len(ctx) || ctx || M</li>
      <li>Ed25519.Sign(sk, M') → <span style="color:var(--ed-color)">${ED25519.signatureBytes} bytes</span></li>
      <li>ML-DSA-65.Sign(sk, M', ctx=label) → <span style="color:var(--pq-color)">${ML_DSA_65.signatureBytes} bytes</span></li>
      <li>Concatenate: ML-DSA || Ed25519 → <strong style="color:var(--composite-ok)">${COMPOSITE_SIG_BYTES} bytes</strong></li>
    </ul>
    <div class="field">
      <label>Signature (<span id="sig-len">—</span> bytes)</label>
      <div class="hex-display" id="sig-hex">—</div>
      <button class="expand-btn" id="expand-sig">Show full signature</button>
    </div>
  </div>

  <div id="verify-result" class="hidden">
    <div class="verify-panel" id="verify-panel">—</div>
  </div>
</section>

<!-- ── Exhibit 3: Break Scenarios ── -->
<section class="exhibit" id="exhibit3">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 3</span>
    <h2>The Break Scenarios</h2>
  </div>

  <p class="narrative" style="margin-bottom:1rem">
    What happens when an attacker breaks <strong>one</strong> of the two algorithms?
    Run the simulations to see the composite catch each failure mode.
  </p>

  <div class="scenario">
    <h3 style="color:var(--pq-color)">Scenario 1 — ML-DSA Catastrophically Broken</h3>
    <p class="timeline">Timeline: 2028. Lattice cryptanalysis breakthrough. ML-DSA signatures can be forged without the private key.</p>
    <div class="btn-row">
      <button class="btn btn-pq" id="sim-mldsa-break" disabled>Simulate ML-DSA Break</button>
    </div>
    <div id="mldsa-break-result" class="hidden" style="margin-top:0.8rem"></div>
  </div>

  <div class="scenario">
    <h3 style="color:var(--ed-color)">Scenario 2 — Quantum Computer Arrives</h3>
    <p class="timeline">Timeline: 2035. CRQC operational. Shor's algorithm breaks Ed25519.</p>
    <div class="btn-row">
      <button class="btn btn-ed" id="sim-quantum-break" disabled>Simulate Quantum Break</button>
    </div>
    <div id="quantum-break-result" class="hidden" style="margin-top:0.8rem"></div>
  </div>

  <div class="scenario">
    <h3 style="color:var(--danger)">Scenario 3 — Both Algorithms Broken (Theoretical)</h3>
    <p class="timeline">Timeline: Unknown. Catastrophic simultaneous break of both algorithm families.</p>
    <div id="double-break-text" class="narrative" style="margin-top:0.6rem"></div>
  </div>
</section>

<!-- ── Exhibit 4: Comparison ── -->
<section class="exhibit" id="exhibit4">
  <div class="exhibit-header">
    <span class="exhibit-num">Exhibit 4</span>
    <h2>Composite vs Single Algorithm</h2>
  </div>

  <table class="compare-table">
    <thead>
      <tr>
        <th>Property</th>
        <th class="ed-col">Ed25519</th>
        <th class="pq-col">ML-DSA-65</th>
        <th class="comp-col">Composite</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>Private key</td><td class="ed-col">32 B</td><td class="pq-col">4,032 B</td><td class="comp-col">4,064 B</td></tr>
      <tr><td>Public key</td><td class="ed-col">32 B</td><td class="pq-col">1,952 B</td><td class="comp-col">1,984 B</td></tr>
      <tr><td>Signature</td><td class="ed-col">64 B</td><td class="pq-col">3,309 B</td><td class="comp-col">${COMPOSITE_SIG_BYTES} B</td></tr>
      <tr><td>Classical security</td><td class="ed-col">128 bits</td><td class="pq-col">~192 bits</td><td class="comp-col">~192 bits (min)</td></tr>
      <tr><td>PQ security</td><td class="ed-col" style="color:var(--danger)">0 (broken by Shor)</td><td class="pq-col">~192 bits</td><td class="comp-col">~192 bits</td></tr>
      <tr><td>Survives single break</td><td class="ed-col" style="color:var(--danger)">No</td><td class="pq-col" style="color:var(--danger)">No</td><td class="comp-col" style="color:var(--success)"><strong>Yes</strong></td></tr>
      <tr><td>Standardization</td><td class="ed-col">RFC 8032</td><td class="pq-col">FIPS 204</td><td class="comp-col">IETF LAMPS draft-16</td></tr>
    </tbody>
  </table>

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
</footer>
`;
}

// ── Wire up events ─────────────────────────────────────────────────────────
function wireEvents(): void {
  // Theme toggle
  el('theme-toggle').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  });

  // Exhibit 1 — generate keypair
  el('gen-keypair').addEventListener('click', () => {
    const btn = el<HTMLButtonElement>('gen-keypair');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Generating…';

    // Yield to DOM before heavy computation
    setTimeout(() => {
      currentKeyPair = generateCompositeKeyPair();
      currentPublicKey = compositePublicKeyFrom(currentKeyPair);

      setHtml('ed-pub', `<span class="key-value">${toHex(currentKeyPair.ed25519.publicKey).slice(0, 16)}…</span>`);
      setHtml('pq-pub', `<span class="key-value">${toHex(currentKeyPair.mldsa.publicKey).slice(0, 16)}…</span>`);

      show('keypair-result');
      btn.disabled = false;
      btn.textContent = 'Regenerate Keypair';

      // Enable sign button
      el<HTMLButtonElement>('sign-btn').disabled = false;

      // Enable break simulation buttons
      el<HTMLButtonElement>('sim-mldsa-break').disabled = false;
      el<HTMLButtonElement>('sim-quantum-break').disabled = false;

      // Populate double-break scenario text
      const db = simulateDoubleBreak(currentKeyPair, new Uint8Array(1));
      el('double-break-text').textContent = db.composite;
    }, 10);
  });

  // Exhibit 2 — sign
  el('sign-btn').addEventListener('click', () => {
    if (!currentKeyPair) return;
    const btn = el<HTMLButtonElement>('sign-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Signing…';

    setTimeout(() => {
      const msg = new TextEncoder().encode(
        (el<HTMLInputElement>('sign-message')).value || 'Paul Clark certified 2026'
      );
      const ctxStr = (el<HTMLInputElement>('sign-context')).value;
      const ctx = ctxStr ? new TextEncoder().encode(ctxStr) : new Uint8Array(0);

      currentSignature = compositeSign(currentKeyPair!, msg, ctx);

      setText('sig-len', String(currentSignature.length));
      el('sig-hex').textContent = toHex(currentSignature.slice(0, 48)) + '…';
      show('sign-steps');

      // Enable remaining buttons
      el<HTMLButtonElement>('verify-btn').disabled = false;
      el<HTMLButtonElement>('tamper-mldsa-btn').disabled = false;
      el<HTMLButtonElement>('tamper-ed-btn').disabled = false;

      btn.disabled = false;
      btn.textContent = 'Sign with Composite';
    }, 10);
  });

  // Expand signature hex
  el('expand-sig').addEventListener('click', () => {
    if (!currentSignature) return;
    const hexEl = el('sig-hex');
    if (hexEl.classList.contains('expanded')) {
      hexEl.textContent = toHex(currentSignature.slice(0, 48)) + '…';
      hexEl.classList.remove('expanded');
      el('expand-sig').textContent = 'Show full signature';
    } else {
      hexEl.textContent = toHex(currentSignature);
      hexEl.classList.add('expanded');
      el('expand-sig').textContent = 'Collapse';
    }
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

  // Exhibit 3 — break simulations
  el('sim-mldsa-break').addEventListener('click', () => {
    if (!currentKeyPair) return;
    const btn = el<HTMLButtonElement>('sim-mldsa-break');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Simulating…';

    setTimeout(() => {
      const msg = new TextEncoder().encode('Forged authorization for attacker');
      const r = simulateMldsaBreak(currentKeyPair!, msg);

      const html = `
        <div class="verify-panel">
          <div class="verify-row">
            <span>Legitimate signature:</span>
            <span>${r.legitValid ? '<span class="status-ok">✓ VALID</span>' : '<span class="status-fail">✗ INVALID</span>'}</span>
          </div>
          <div class="verify-row">
            <span style="color:var(--pq-color)">ML-DSA-65 forged by attacker:</span>
            <span style="color:var(--warn)">✓ (forged successfully)</span>
          </div>
          <div class="verify-row">
            <span style="color:var(--ed-color)">Ed25519 — attacker cannot forge:</span>
            <span>${r.ed25519Caught ? '<span class="status-fail">✗ FAIL — Ed25519 catches it</span>' : '<span class="status-ok">✓</span>'}</span>
          </div>
          <div class="verify-row">
            <span>Forged composite:</span>
            <span>${r.forgedValid ? '<span class="status-comp-ok">✓ PASSED (broken!)</span>' : '<span class="status-comp-fail">✗ REJECTED</span>'}</span>
          </div>
          <p class="narrative" style="margin-top:0.6rem">
            ${r.ed25519Caught
              ? '<strong style="color:var(--success)">Ed25519 caught the forgery.</strong> Even though ML-DSA was broken, the classical component protected the composite.'
              : '<strong style="color:var(--danger)">Unexpected: composite accepted forged signature.</strong>'}
          </p>
        </div>`;
      setHtml('mldsa-break-result', html);
      show('mldsa-break-result');
      btn.disabled = false;
      btn.textContent = 'Simulate ML-DSA Break';
    }, 10);
  });

  el('sim-quantum-break').addEventListener('click', () => {
    if (!currentKeyPair) return;
    const btn = el<HTMLButtonElement>('sim-quantum-break');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Simulating…';

    setTimeout(() => {
      const msg = new TextEncoder().encode('Forged authorization for attacker');
      const r = simulateQuantumBreak(currentKeyPair!, msg);

      const html = `
        <div class="verify-panel">
          <div class="verify-row">
            <span>Legitimate signature:</span>
            <span>${r.legitValid ? '<span class="status-ok">✓ VALID</span>' : '<span class="status-fail">✗ INVALID</span>'}</span>
          </div>
          <div class="verify-row">
            <span style="color:var(--ed-color)">Ed25519 quantum-forged via Shor:</span>
            <span style="color:var(--warn)">✓ (quantum-forged successfully)</span>
          </div>
          <div class="verify-row">
            <span style="color:var(--pq-color)">ML-DSA-65 — post-quantum secure:</span>
            <span>${r.mldsaCaught ? '<span class="status-fail">✗ FAIL — ML-DSA catches it</span>' : '<span class="status-ok">✓</span>'}</span>
          </div>
          <div class="verify-row">
            <span>Forged composite:</span>
            <span>${r.forgedValid ? '<span class="status-comp-ok">✓ PASSED (broken!)</span>' : '<span class="status-comp-fail">✗ REJECTED</span>'}</span>
          </div>
          <p class="narrative" style="margin-top:0.6rem">
            ${r.mldsaCaught
              ? '<strong style="color:var(--success)">ML-DSA-65 caught the forgery.</strong> The post-quantum component protected the composite even against a quantum adversary.'
              : '<strong style="color:var(--danger)">Unexpected: composite accepted forged signature.</strong>'}
          </p>
        </div>`;
      setHtml('quantum-break-result', html);
      show('quantum-break-result');
      btn.disabled = false;
      btn.textContent = 'Simulate Quantum Break';
    }, 10);
  });
}

function verifyAndDisplay(sig: Uint8Array, label: string): void {
  if (!currentPublicKey) return;
  const msg = new TextEncoder().encode(
    (el<HTMLInputElement>('sign-message')).value || 'Paul Clark certified 2026'
  );
  const ctxStr = (el<HTMLInputElement>('sign-context')).value;
  const ctx = ctxStr ? new TextEncoder().encode(ctxStr) : new Uint8Array(0);

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
        ${r.valid ? '✓ VALID' : `✗ INVALID ${!r.mldsaValid && r.ed25519Valid ? '(caught by Ed25519)' : ''}${r.mldsaValid && !r.ed25519Valid ? '(caught by ML-DSA-65)' : ''}${!r.mldsaValid && !r.ed25519Valid ? '(both failed)' : ''}`}
      </span>
    </div>
  `;
  setHtml('verify-panel', html);
  show('verify-result');
}

// ── Boot ───────────────────────────────────────────────────────────────────
renderApp();
wireEvents();

// Verify prefix hex in console for spec compliance
const prefixHex = toHex(COMPOSITE_PREFIX);
console.info(
  '[composite-sign] COMPOSITE_PREFIX hex:',
  prefixHex,
  '\nExpected: 436f6d706f73697465416c676f726974686d5369676e61747572657332303235',
  '\nMatch:', prefixHex.toLowerCase() === '436f6d706f73697465416c676f726974686d5369676e61747572657332303235'
);
