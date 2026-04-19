import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

// ── Size constants (verified from library at install time) ─────────────────
export const ED25519 = {
  publicKeyBytes: 32,
  privateKeyBytes: 32,
  signatureBytes: 64,
} as const;

export const ML_DSA_65 = {
  publicKeyBytes: 1952,
  privateKeyBytes: 4032,
  signatureBytes: 3309,
} as const;

// ── Key pair types ─────────────────────────────────────────────────────────
export interface Ed25519KeyPair {
  privateKey: Uint8Array; // 32 bytes (seed)
  publicKey: Uint8Array;  // 32 bytes
}

export interface MLDSAKeyPair {
  privateKey: Uint8Array; // 4032 bytes
  publicKey: Uint8Array;  // 1952 bytes
}

// ── Key generation ─────────────────────────────────────────────────────────
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const kp = ed25519.keygen();
  return { privateKey: kp.secretKey, publicKey: kp.publicKey };
}

export function generateMLDSAKeyPair(): MLDSAKeyPair {
  const kp = ml_dsa65.keygen();
  return { privateKey: kp.secretKey, publicKey: kp.publicKey };
}

// ── Signing ────────────────────────────────────────────────────────────────
// Note: @noble/curves ed25519.sign(msg, secretKey)
//       @noble/post-quantum ml_dsa65.sign(msg, secretKey, opts?)

export function ed25519Sign(msg: Uint8Array, sk: Uint8Array): Uint8Array {
  return ed25519.sign(msg, sk);
}

export function ed25519Verify(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pk);
  } catch {
    return false;
  }
}

export function mldsaSign(msg: Uint8Array, sk: Uint8Array, ctx?: Uint8Array): Uint8Array {
  return ml_dsa65.sign(msg, sk, ctx ? { context: ctx } : undefined);
}

export function mldsaVerify(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array, ctx?: Uint8Array): boolean {
  try {
    return ml_dsa65.verify(sig, msg, pk, ctx ? { context: ctx } : undefined);
  } catch {
    return false;
  }
}
