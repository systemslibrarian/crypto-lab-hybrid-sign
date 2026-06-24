import { describe, it, expect } from 'vitest';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  generateCompositeKeyPair,
  compositePublicKeyFrom,
  compositeSign,
  compositeVerify,
  buildCompositeMessage,
  tamperMldsaPortion,
  tamperEd25519Portion,
  COMPOSITE_PREFIX,
  COMPOSITE_LABEL,
  COMPOSITE_LABEL_BYTES,
  COMPOSITE_SIG_BYTES,
  MAX_CTX_BYTES,
  ED25519,
  ML_DSA_65,
} from './composite';
import {
  simulateMldsaBreak,
  simulateQuantumBreak,
  simulateDoubleBreak,
} from './breaks';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('spec constants', () => {
  it('prefix is ASCII "CompositeAlgorithmSignatures2025"', () => {
    expect(hex(COMPOSITE_PREFIX)).toBe(
      '436f6d706f73697465416c676f726974686d5369676e61747572657332303235'
    );
    expect(new TextDecoder().decode(COMPOSITE_PREFIX)).toBe(
      'CompositeAlgorithmSignatures2025'
    );
  });

  it('label and sizes match draft-16 / FIPS 204', () => {
    expect(COMPOSITE_LABEL).toBe('COMPSIG-MLDSA65-ED25519-SHA512');
    expect(ML_DSA_65.signatureBytes).toBe(3309);
    expect(ED25519.signatureBytes).toBe(64);
    expect(COMPOSITE_SIG_BYTES).toBe(3373);
  });
});

describe('message representative M′', () => {
  it('is Prefix || Label || len(ctx) || ctx || SHA-512(M)', () => {
    const msg = enc('hello world');
    const ctx = enc('ctx');
    const mPrime = buildCompositeMessage(msg, ctx);

    const phm = sha512(msg);
    const expectedLen =
      COMPOSITE_PREFIX.length + COMPOSITE_LABEL_BYTES.length + 1 + ctx.length + phm.length;
    expect(mPrime.length).toBe(expectedLen);

    let o = 0;
    expect(mPrime.slice(o, (o += COMPOSITE_PREFIX.length))).toEqual(COMPOSITE_PREFIX);
    expect(mPrime.slice(o, (o += COMPOSITE_LABEL_BYTES.length))).toEqual(COMPOSITE_LABEL_BYTES);
    expect(mPrime[o++]).toBe(ctx.length);
    expect(mPrime.slice(o, (o += ctx.length))).toEqual(ctx);
    expect(mPrime.slice(o)).toEqual(phm); // tail is the SHA-512 hash, not raw M
  });

  it('prehashes the message (tail is 64-byte SHA-512, independent of M length)', () => {
    const a = buildCompositeMessage(enc('x'));
    const b = buildCompositeMessage(enc('x'.repeat(10_000)));
    expect(a.length).toBe(b.length); // both end in a 64-byte digest
  });

  it('rejects context longer than 255 bytes', () => {
    expect(() => buildCompositeMessage(enc('m'), new Uint8Array(256))).toThrow(RangeError);
    expect(() => buildCompositeMessage(enc('m'), new Uint8Array(255))).not.toThrow();
    expect(MAX_CTX_BYTES).toBe(255);
  });
});

describe('round-trip', () => {
  it('a clean composite signature verifies (both components)', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    const msg = enc('Paul Clark certified 2026');
    const sig = compositeSign(kp, msg);

    expect(sig.length).toBe(COMPOSITE_SIG_BYTES);
    const r = compositeVerify(pub, msg, sig);
    expect(r).toEqual({ valid: true, ed25519Valid: true, mldsaValid: true });
  });

  it('honors context: signing ctx must equal verifying ctx', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    const msg = enc('m');
    const sig = compositeSign(kp, msg, enc('ctx-A'));

    expect(compositeVerify(pub, msg, sig, enc('ctx-A')).valid).toBe(true);
    expect(compositeVerify(pub, msg, sig, enc('ctx-B')).valid).toBe(false);
    expect(compositeVerify(pub, msg, sig).valid).toBe(false); // empty ctx
  });

  it('a different message does not verify', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    const sig = compositeSign(kp, enc('message one'));
    expect(compositeVerify(pub, enc('message two'), sig).valid).toBe(false);
  });

  it('a wrong-length signature is rejected without throwing', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    expect(compositeVerify(pub, enc('m'), new Uint8Array(10))).toEqual({
      valid: false,
      ed25519Valid: false,
      mldsaValid: false,
    });
  });
});

describe('tamper detection (both must verify)', () => {
  it('tampering the ML-DSA portion fails ML-DSA but Ed25519 still holds', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    const msg = enc('certify');
    const sig = compositeSign(kp, msg);

    const r = compositeVerify(pub, msg, tamperMldsaPortion(sig));
    expect(r.mldsaValid).toBe(false);
    expect(r.ed25519Valid).toBe(true);
    expect(r.valid).toBe(false);
  });

  it('tampering the Ed25519 portion fails Ed25519 but ML-DSA still holds', () => {
    const kp = generateCompositeKeyPair();
    const pub = compositePublicKeyFrom(kp);
    const msg = enc('certify');
    const sig = compositeSign(kp, msg);

    const r = compositeVerify(pub, msg, tamperEd25519Portion(sig));
    expect(r.ed25519Valid).toBe(false);
    expect(r.mldsaValid).toBe(true);
    expect(r.valid).toBe(false);
  });
});

describe('break scenarios', () => {
  it('ML-DSA broken: ML-DSA forges, Ed25519 catches it, composite rejects', () => {
    const r = simulateMldsaBreak(generateCompositeKeyPair());
    expect(r.legitValid).toBe(true);
    expect(r.forgedMldsaValid).toBe(true);   // attacker forged a valid ML-DSA sig
    expect(r.forgedEd25519Valid).toBe(false); // attacker cannot forge Ed25519
    expect(r.forgedValid).toBe(false);
    expect(r.caughtBy).toBe('ed25519');
  });

  it('quantum break: Ed25519 forged, ML-DSA catches it, composite rejects', () => {
    const r = simulateQuantumBreak(generateCompositeKeyPair());
    expect(r.legitValid).toBe(true);
    expect(r.forgedEd25519Valid).toBe(true);  // Shor-forged Ed25519
    expect(r.forgedMldsaValid).toBe(false);   // attacker cannot forge ML-DSA
    expect(r.forgedValid).toBe(false);
    expect(r.caughtBy).toBe('mldsa');
  });

  it('double break: both forged, composite accepts the forgery (residual risk)', () => {
    const r = simulateDoubleBreak(generateCompositeKeyPair());
    expect(r.forgedMldsaValid).toBe(true);
    expect(r.forgedEd25519Valid).toBe(true);
    expect(r.forgedValid).toBe(true);
    expect(r.caughtBy).toBe('none');
  });
});
