import {
  compositeSign,
  compositeVerify,
  compositePublicKeyFrom,
  buildCompositeMessage,
  COMPOSITE_LABEL_BYTES,
  ML_DSA_65,
  type CompositeKeyPair,
} from './composite';
import {
  generateEd25519KeyPair,
  generateMLDSAKeyPair,
  ed25519Sign,
  mldsaSign,
  ED25519,
} from './primitives';

/**
 * Break-scenario simulations.
 *
 * We obviously cannot actually break Ed25519 or ML-DSA-65 in a browser. So we
 * MODEL an attacker's forging power honestly, and then let them use it:
 *
 *   * A component the attacker has BROKEN is signed with the real private key.
 *     That is exactly the power a break confers — the ability to mint a
 *     component signature that genuinely verifies.
 *   * A component they have NOT broken is signed with a key pair they generated
 *     themselves. That is the strongest thing an attacker without the key can
 *     actually do: submit a well-formed signature under the wrong key.
 *
 * Everything after that is the lab's real code. The forgery is assembled by the
 * same concatenation the signer uses, over the same message representative M′
 * (so the context binding is exercised), and handed to `compositeVerify`. Each
 * per-component VALID / INVALID line, the composite accept/reject, and which
 * half caught the forgery are all read off that verifier's output — including
 * which halves the attacker controlled, which comes from the attempt itself
 * rather than from which button was pressed.
 */

export type CaughtBy = 'ed25519' | 'mldsa' | 'both' | 'none';

/** What the attacker was able to do to one half of the composite. */
export interface ForgedHalf {
  /** True when this family had fallen, so the honest signing key was used. */
  usedHonestKey: boolean;
  /** Measured: this component's verifier accepted the bytes submitted. */
  valid: boolean;
}

export interface BreakResult {
  /** Did a legitimate signature over the same message verify? (sanity check) */
  legitValid: boolean;
  /** Forged ML-DSA-65 component verifies? */
  forgedMldsaValid: boolean;
  /** Forged Ed25519 component verifies? */
  forgedEd25519Valid: boolean;
  /** Does the forged COMPOSITE verify? (true only if both components do) */
  forgedValid: boolean;
  /** Which intact component(s) rejected the forgery — 'none' when it landed. */
  caughtBy: CaughtBy;
  /** Per-half record of what the attacker actually had and what it achieved. */
  mldsa: ForgedHalf;
  ed25519: ForgedHalf;
  /** The exact bytes the attacker submitted. */
  forgedSignature: Uint8Array;
  /** The message the forgery is over — never one the honest key signed. */
  forgedMessage: Uint8Array;
  forgedMessageText: string;
  /** The context the forgery was made and verified under. */
  ctx: Uint8Array;
}

/** Appended to whatever the user signed, so the forgery is over a new message. */
const FORGERY_SUFFIX = ' — and transfer $10,000,000 to the attacker';

/** The message an attacker would try to get accepted, given what was signed. */
export function forgedMessageFor(honestMessage: Uint8Array): Uint8Array {
  const honest = new TextDecoder().decode(honestMessage);
  return new TextEncoder().encode(honest + FORGERY_SUFFIX);
}

export interface BreakOptions {
  /** The attacker can mint valid Ed25519 signatures (e.g. a CRQC runs Shor). */
  breakEd25519: boolean;
  /** The attacker can mint valid ML-DSA-65 signatures (lattice cryptanalysis). */
  breakMldsa: boolean;
  /** What the honest party actually signed — the forgery targets a variation of it. */
  honestMessage: Uint8Array;
  /** The context the honest signature was made under; the forgery uses the same. */
  ctx?: Uint8Array;
}

/**
 * Run a forgery attempt and report what the verifier did with it.
 *
 * There is no scenario table here: the two booleans decide only *which signing
 * key each half is forged with*. Everything the page displays afterwards —
 * whether each component verified, whether the composite accepted, which half
 * caught it — comes from `compositeVerify` on the bytes this function built.
 */
export function runForgery(keyPair: CompositeKeyPair, opts: BreakOptions): BreakResult {
  const ctx = opts.ctx ?? new Uint8Array(0);
  const forgedMessage = forgedMessageFor(opts.honestMessage);
  // The same representative the real signer would build — so the label, the
  // context length byte and the pre-hash all bind the forgery too.
  const mPrime = buildCompositeMessage(forgedMessage, ctx);

  // ML-DSA half: honest key if lattices fell, otherwise the attacker's own key.
  const mldsaSigner = opts.breakMldsa ? keyPair.mldsa : generateMLDSAKeyPair();
  const mldsaSig = mldsaSign(mPrime, mldsaSigner.privateKey, COMPOSITE_LABEL_BYTES);

  // Ed25519 half: honest key if a CRQC exists, otherwise the attacker's own key.
  const edSigner = opts.breakEd25519 ? keyPair.ed25519 : generateEd25519KeyPair();
  const edSig = ed25519Sign(mPrime, edSigner.privateKey);

  const forged = new Uint8Array(ML_DSA_65.signatureBytes + ED25519.signatureBytes);
  forged.set(mldsaSig, 0);
  forged.set(edSig, ML_DSA_65.signatureBytes);

  const pub = compositePublicKeyFrom(keyPair);
  // Sanity: an honest signature over the same forged message under the same ctx
  // must verify, so a rejection below is the forgery failing, not the harness.
  const legit = compositeVerify(pub, forgedMessage, compositeSign(keyPair, forgedMessage, ctx), ctx);
  const r = compositeVerify(pub, forgedMessage, forged, ctx);

  let caughtBy: CaughtBy = 'none';
  if (!r.valid) {
    if (!r.ed25519Valid && !r.mldsaValid) caughtBy = 'both';
    else if (!r.ed25519Valid) caughtBy = 'ed25519';
    else caughtBy = 'mldsa';
  }

  return {
    legitValid: legit.valid,
    forgedMldsaValid: r.mldsaValid,
    forgedEd25519Valid: r.ed25519Valid,
    forgedValid: r.valid,
    caughtBy,
    mldsa: { usedHonestKey: opts.breakMldsa, valid: r.mldsaValid },
    ed25519: { usedHonestKey: opts.breakEd25519, valid: r.ed25519Valid },
    forgedSignature: forged,
    forgedMessage,
    forgedMessageText: new TextDecoder().decode(forgedMessage),
    ctx,
  };
}

// ── The named scenarios, all one code path ────────────────────────────────

/**
 * Scenario 0 — nothing broken. The attacker forges with keys they generated
 * themselves; both components must reject.
 */
export function simulateNoBreak(
  keyPair: CompositeKeyPair,
  honestMessage: Uint8Array,
  ctx?: Uint8Array
): BreakResult {
  return runForgery(keyPair, { breakEd25519: false, breakMldsa: false, honestMessage, ctx });
}

/**
 * Scenario 1 — ML-DSA-65 catastrophically broken (lattice cryptanalysis).
 * The attacker can mint a VALID ML-DSA-65 signature on the forged message but
 * cannot forge Ed25519. Ed25519 must reject → composite rejected.
 */
export function simulateMldsaBreak(
  keyPair: CompositeKeyPair,
  honestMessage: Uint8Array,
  ctx?: Uint8Array
): BreakResult {
  return runForgery(keyPair, { breakEd25519: false, breakMldsa: true, honestMessage, ctx });
}

/**
 * Scenario 2 — quantum computer (Shor) breaks Ed25519.
 * The attacker can mint a VALID Ed25519 signature on the forged message but
 * cannot forge ML-DSA-65. ML-DSA-65 must reject → composite rejected.
 */
export function simulateQuantumBreak(
  keyPair: CompositeKeyPair,
  honestMessage: Uint8Array,
  ctx?: Uint8Array
): BreakResult {
  return runForgery(keyPair, { breakEd25519: true, breakMldsa: false, honestMessage, ctx });
}

/**
 * Scenario 3 — BOTH families broken simultaneously (the residual risk).
 * The attacker can forge both components, so the composite accepts the forgery.
 * Defense in depth, not invincibility.
 */
export function simulateDoubleBreak(
  keyPair: CompositeKeyPair,
  honestMessage: Uint8Array,
  ctx?: Uint8Array
): BreakResult {
  return runForgery(keyPair, { breakEd25519: true, breakMldsa: true, honestMessage, ctx });
}

export const DOUBLE_BREAK_NARRATIVE =
  'If both Ed25519 (elliptic-curve discrete log) and ML-DSA-65 (module lattices) ' +
  'are broken at the same moment, an attacker forges both component signatures and ' +
  'the composite verification succeeds. The composite buys DEFENSE IN DEPTH, not ' +
  'invincibility. Its security assumption is that two independent mathematical ' +
  'families do not fall simultaneously — historically very unlikely, but not ' +
  'impossible. Composites protect you through the migration period; once PQ ' +
  'cryptography earns decades of cryptanalytic confidence, the classical half can ' +
  'be retired.';
