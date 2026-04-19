import {
  compositeSign,
  compositeVerify,
  compositePublicKeyFrom,
  ML_DSA_65,
  type CompositeKeyPair,
} from './composite';
import { ED25519 } from './primitives';

/**
 * Simulate an attacker who has broken ML-DSA (catastrophic lattice analysis).
 * The attacker can forge an ML-DSA signature but cannot forge Ed25519.
 * The composite rejects because Ed25519 fails.
 */
export function simulateMldsaBreak(
  keyPair: CompositeKeyPair,
  message: Uint8Array
): {
  legitSignature: Uint8Array;
  forgedSignature: Uint8Array;
  legitValid: boolean;
  forgedValid: boolean;
  ed25519Caught: boolean;
} {
  const pubKey = compositePublicKeyFrom(keyPair);
  const legitSignature = compositeSign(keyPair, message);
  const legitResult = compositeVerify(pubKey, message, legitSignature);

  // Attacker can forge ML-DSA but not Ed25519.
  // Simulate: replace ML-DSA portion with random bytes (standing in for a forged ML-DSA sig),
  // and fill Ed25519 portion with random bytes (attacker cannot forge Ed25519).
  const forgedSignature = new Uint8Array(ML_DSA_65.signatureBytes + ED25519.signatureBytes);
  crypto.getRandomValues(forgedSignature.subarray(0, ML_DSA_65.signatureBytes));
  crypto.getRandomValues(forgedSignature.subarray(ML_DSA_65.signatureBytes));

  const forgedResult = compositeVerify(pubKey, message, forgedSignature);

  return {
    legitSignature,
    forgedSignature,
    legitValid: legitResult.valid,
    forgedValid: forgedResult.valid,
    ed25519Caught: !forgedResult.ed25519Valid,
  };
}

/**
 * Simulate an attacker who has a quantum computer (breaks Ed25519 via Shor's algorithm).
 * The attacker can forge an Ed25519 signature but cannot forge ML-DSA.
 * The composite rejects because ML-DSA fails.
 */
export function simulateQuantumBreak(
  keyPair: CompositeKeyPair,
  message: Uint8Array
): {
  legitSignature: Uint8Array;
  forgedSignature: Uint8Array;
  legitValid: boolean;
  forgedValid: boolean;
  mldsaCaught: boolean;
} {
  const pubKey = compositePublicKeyFrom(keyPair);
  const legitSignature = compositeSign(keyPair, message);
  const legitResult = compositeVerify(pubKey, message, legitSignature);

  // Attacker can forge Ed25519 (via quantum computer) but not ML-DSA.
  // Simulate: random ML-DSA portion (attacker cannot forge), random Ed25519 portion
  // (standing in for a "quantum-forged" Ed25519 sig on wrong message).
  const forgedSignature = new Uint8Array(ML_DSA_65.signatureBytes + ED25519.signatureBytes);
  crypto.getRandomValues(forgedSignature.subarray(0, ML_DSA_65.signatureBytes));
  crypto.getRandomValues(forgedSignature.subarray(ML_DSA_65.signatureBytes));

  const forgedResult = compositeVerify(pubKey, message, forgedSignature);

  return {
    legitSignature,
    forgedSignature,
    legitValid: legitResult.valid,
    forgedValid: forgedResult.valid,
    mldsaCaught: !forgedResult.mldsaValid,
  };
}

/**
 * Illustrate the residual risk: if BOTH algorithms are simultaneously broken,
 * the composite provides no protection.
 */
export function simulateDoubleBreak(
  _keyPair: CompositeKeyPair,
  _message: Uint8Array
): { composite: string } {
  return {
    composite:
      'If both Ed25519 (discrete-log) and ML-DSA-65 (lattices) are simultaneously ' +
      'broken, an attacker can forge both component signatures and the composite ' +
      'verification succeeds. The composite provides DEFENSE IN DEPTH, not ' +
      'invincibility. The security assumption is that two independent mathematical ' +
      'families — elliptic-curve discrete log and module lattices — do not fall ' +
      'at the same moment. Historical cryptanalysis suggests this is very unlikely, ' +
      'but it is not impossible. Composites protect you during the transition period; ' +
      'once PQ crypto earns decades of confidence, you can drop the classical component.',
  };
}
