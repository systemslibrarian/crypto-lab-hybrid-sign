import {
  compositeSign,
  compositeVerify,
  compositePublicKeyFrom,
  ML_DSA_65,
  type CompositeKeyPair,
} from './composite';
import { ED25519 } from './primitives';

/**
 * Break-scenario simulations.
 *
 * We obviously cannot actually break Ed25519 or ML-DSA-65 in a browser. So we
 * MODEL an attacker's forging power honestly: an algorithm the attacker has
 * "broken" is one for which they can mint a signature that genuinely verifies.
 * We stand in for that power by signing the forged message with the real
 * private key — the resulting component signature passes verification exactly
 * as a real forgery would. The algorithm the attacker has NOT broken gets
 * random bytes, which fail verification exactly as a forgery attempt would.
 *
 * The payoff: every per-component VALID / INVALID line the UI shows is the
 * literal output of `compositeVerify` on the forged signature — nothing is
 * narrated or faked. The composite's accept/reject decision is real.
 */

export type CaughtBy = 'ed25519' | 'mldsa' | 'none';

export interface BreakResult {
  /** Did a legitimate signature over the same message verify? (sanity check) */
  legitValid: boolean;
  /** Forged ML-DSA-65 component verifies? */
  forgedMldsaValid: boolean;
  /** Forged Ed25519 component verifies? */
  forgedEd25519Valid: boolean;
  /** Does the forged COMPOSITE verify? (true only if both components do) */
  forgedValid: boolean;
  /** Which intact component rejected the forgery (if any). */
  caughtBy: CaughtBy;
}

const FORGED_MESSAGE = 'Transfer $10,000,000 to attacker — authorized';

/** Replace the ML-DSA portion [0, 3309) of a composite signature with random bytes. */
function randomizeMldsaPortion(sig: Uint8Array): void {
  crypto.getRandomValues(sig.subarray(0, ML_DSA_65.signatureBytes));
}

/** Replace the Ed25519 portion [3309, 3373) of a composite signature with random bytes. */
function randomizeEd25519Portion(sig: Uint8Array): void {
  crypto.getRandomValues(sig.subarray(ML_DSA_65.signatureBytes));
}

function evaluate(
  keyPair: CompositeKeyPair,
  message: Uint8Array,
  forgedSig: Uint8Array
): BreakResult {
  const pub = compositePublicKeyFrom(keyPair);
  const legit = compositeVerify(pub, message, compositeSign(keyPair, message));
  const r = compositeVerify(pub, message, forgedSig);

  let caughtBy: CaughtBy = 'none';
  if (!r.valid) {
    if (!r.ed25519Valid && r.mldsaValid) caughtBy = 'ed25519';
    else if (r.ed25519Valid && !r.mldsaValid) caughtBy = 'mldsa';
  }

  return {
    legitValid: legit.valid,
    forgedMldsaValid: r.mldsaValid,
    forgedEd25519Valid: r.ed25519Valid,
    forgedValid: r.valid,
    caughtBy,
  };
}

/**
 * Scenario 1 — ML-DSA-65 catastrophically broken (lattice cryptanalysis).
 * The attacker can mint a VALID ML-DSA-65 signature on the forged message but
 * cannot forge Ed25519. Ed25519 must reject → composite rejected.
 */
export function simulateMldsaBreak(keyPair: CompositeKeyPair): BreakResult {
  const forgedMessage = new TextEncoder().encode(FORGED_MESSAGE);
  // Start from a fully valid forgery, then knock out the component the
  // attacker did NOT break (Ed25519).
  const forged = compositeSign(keyPair, forgedMessage);
  randomizeEd25519Portion(forged);
  return evaluate(keyPair, forgedMessage, forged);
}

/**
 * Scenario 2 — quantum computer (Shor) breaks Ed25519.
 * The attacker can mint a VALID Ed25519 signature on the forged message but
 * cannot forge ML-DSA-65. ML-DSA-65 must reject → composite rejected.
 */
export function simulateQuantumBreak(keyPair: CompositeKeyPair): BreakResult {
  const forgedMessage = new TextEncoder().encode(FORGED_MESSAGE);
  const forged = compositeSign(keyPair, forgedMessage);
  randomizeMldsaPortion(forged);
  return evaluate(keyPair, forgedMessage, forged);
}

/**
 * Scenario 3 — BOTH families broken simultaneously (the residual risk).
 * The attacker can forge both components, so the composite accepts the forgery.
 * Defense in depth, not invincibility.
 */
export function simulateDoubleBreak(keyPair: CompositeKeyPair): BreakResult {
  const forgedMessage = new TextEncoder().encode(FORGED_MESSAGE);
  // Both components forged with full forging power → both verify.
  const forged = compositeSign(keyPair, forgedMessage);
  return evaluate(keyPair, forgedMessage, forged);
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

export const FORGED_MESSAGE_TEXT = FORGED_MESSAGE;
