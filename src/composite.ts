import {
  generateEd25519KeyPair,
  generateMLDSAKeyPair,
  ed25519Sign,
  ed25519Verify,
  mldsaSign,
  mldsaVerify,
  ED25519,
  ML_DSA_65,
  type Ed25519KeyPair,
  type MLDSAKeyPair,
} from './primitives';

export { ED25519, ML_DSA_65 };

// ── Composite algorithm constants ──────────────────────────────────────────
// Per draft-ietf-lamps-pq-composite-sigs-16

/**
 * Prefix per draft-ietf-lamps-pq-composite-sigs-16 Section 7.3.
 * ASCII "CompositeAlgorithmSignatures2025"
 * Hex: 436F6D706F73697465416C676F726974686D5369676E61747572657332303235
 */
export const COMPOSITE_PREFIX = new TextEncoder().encode(
  'CompositeAlgorithmSignatures2025'
);

/**
 * Domain separator / ML-DSA context label.
 * Per draft-16 for the id-MLDSA65-Ed25519-SHA512 OID / TLS codepoint 0x090B.
 */
export const COMPOSITE_LABEL = 'COMPSIG-MLDSA65-ED25519-SHA512';
export const COMPOSITE_LABEL_BYTES = new TextEncoder().encode(COMPOSITE_LABEL);

// ── Total signature size: ML-DSA-65 (3309) || Ed25519 (64) = 3373 bytes ───
export const COMPOSITE_SIG_BYTES =
  ML_DSA_65.signatureBytes + ED25519.signatureBytes; // 3373

// ── Keypair types ──────────────────────────────────────────────────────────
export interface CompositeKeyPair {
  ed25519: Ed25519KeyPair;
  mldsa: MLDSAKeyPair;
}

export interface CompositePublicKey {
  ed25519: Uint8Array; // 32
  mldsa: Uint8Array;   // 1952
}

// ── Key generation ─────────────────────────────────────────────────────────
export function generateCompositeKeyPair(): CompositeKeyPair {
  return {
    ed25519: generateEd25519KeyPair(),
    mldsa: generateMLDSAKeyPair(),
  };
}

export function compositePublicKeyFrom(kp: CompositeKeyPair): CompositePublicKey {
  return {
    ed25519: kp.ed25519.publicKey,
    mldsa: kp.mldsa.publicKey,
  };
}

// ── Message construction ───────────────────────────────────────────────────
/**
 * Build M' = Prefix || Domain || len(ctx) || ctx || M
 * per draft-ietf-lamps-pq-composite-sigs-16 composite combiner.
 */
export function buildCompositeMessage(
  message: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0)
): Uint8Array {
  // Domain = COMPOSITE_LABEL_BYTES
  const domain = COMPOSITE_LABEL_BYTES;
  const ctxLen = new Uint8Array([ctx.length & 0xff]);

  const total =
    COMPOSITE_PREFIX.length +
    domain.length +
    1 + // len(ctx)
    ctx.length +
    message.length;

  const buf = new Uint8Array(total);
  let offset = 0;
  buf.set(COMPOSITE_PREFIX, offset); offset += COMPOSITE_PREFIX.length;
  buf.set(domain, offset);           offset += domain.length;
  buf.set(ctxLen, offset);           offset += 1;
  buf.set(ctx, offset);              offset += ctx.length;
  buf.set(message, offset);

  return buf;
}

// ── Signing ────────────────────────────────────────────────────────────────
/**
 * Sign with composite algorithm per draft-16.
 * Returns ML-DSA-65 signature (3309 bytes) || Ed25519 signature (64 bytes) = 3373 bytes.
 */
export function compositeSign(
  keyPair: CompositeKeyPair,
  message: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const mPrime = buildCompositeMessage(message, ctx);

  // Both sign the SAME derived message M'
  // ML-DSA context = the composite label (domain separation)
  const mldsaSig = mldsaSign(mPrime, keyPair.mldsa.privateKey, COMPOSITE_LABEL_BYTES);
  const edSig = ed25519Sign(mPrime, keyPair.ed25519.privateKey);

  // Concatenate: ML-DSA-65 || Ed25519
  const composite = new Uint8Array(ML_DSA_65.signatureBytes + ED25519.signatureBytes);
  composite.set(mldsaSig, 0);
  composite.set(edSig, ML_DSA_65.signatureBytes);
  return composite;
}

// ── Verification ───────────────────────────────────────────────────────────
export interface VerifyResult {
  valid: boolean;
  ed25519Valid: boolean;
  mldsaValid: boolean;
}

/**
 * Verify composite signature. Returns true IFF BOTH Ed25519 AND ML-DSA-65 verify.
 * Composite sig layout: [0..3309) = ML-DSA-65, [3309..3373) = Ed25519.
 */
export function compositeVerify(
  publicKey: CompositePublicKey,
  message: Uint8Array,
  signature: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0)
): VerifyResult {
  if (signature.length !== COMPOSITE_SIG_BYTES) {
    return { valid: false, ed25519Valid: false, mldsaValid: false };
  }

  const mldsaSig = signature.slice(0, ML_DSA_65.signatureBytes);
  const edSig = signature.slice(ML_DSA_65.signatureBytes);

  const mPrime = buildCompositeMessage(message, ctx);

  const mldsaValid = mldsaVerify(mldsaSig, mPrime, publicKey.mldsa, COMPOSITE_LABEL_BYTES);
  const ed25519Valid = ed25519Verify(edSig, mPrime, publicKey.ed25519);

  return {
    valid: mldsaValid && ed25519Valid,
    ed25519Valid,
    mldsaValid,
  };
}

// ── Tamper helpers ─────────────────────────────────────────────────────────
export function tamperMldsaPortion(sig: Uint8Array): Uint8Array {
  const tampered = sig.slice();
  // Flip bits in the middle of the ML-DSA portion
  tampered[1000] ^= 0xff;
  tampered[1001] ^= 0xff;
  return tampered;
}

export function tamperEd25519Portion(sig: Uint8Array): Uint8Array {
  const tampered = sig.slice();
  // Flip bits in the Ed25519 portion
  const offset = ML_DSA_65.signatureBytes;
  tampered[offset] ^= 0xff;
  tampered[offset + 1] ^= 0xff;
  return tampered;
}
