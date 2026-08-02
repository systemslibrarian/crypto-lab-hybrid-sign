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
  simulateNoBreak,
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
    expect(COMPOSITE_LABEL).toBe('COMPSIG-MLDSA65-Ed25519-SHA512');
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

// The scenarios used to differ only in which portion of an otherwise-valid
// signature was overwritten with random bytes, and the UI labelled each half
// from the button that was pressed. They now build a genuine forgery: halves
// the attacker has broken are signed with the honest key, halves they have not
// are signed with a key pair they generate for themselves, and every field
// below is compositeVerify's answer on the bytes produced.
describe('break scenarios', () => {
  const MSG = new TextEncoder().encode('Paul Clark certified 2026');

  it('forges over a different message than the one that was signed', () => {
    const kp = generateCompositeKeyPair();
    const r = simulateDoubleBreak(kp, MSG);
    expect(r.forgedMessageText).not.toBe(new TextDecoder().decode(MSG));
    expect(r.forgedMessageText.startsWith('Paul Clark certified 2026')).toBe(true);
    // The honest signature over the original message must NOT cover the forged one.
    const pub = compositePublicKeyFrom(kp);
    const honest = compositeSign(kp, MSG);
    expect(compositeVerify(pub, r.forgedMessage, honest).valid).toBe(false);
  });

  it('no break: the attacker signs with their own keys and both halves reject', () => {
    const r = simulateNoBreak(generateCompositeKeyPair(), MSG);
    expect(r.legitValid).toBe(true);
    expect(r.ed25519.usedHonestKey).toBe(false);
    expect(r.mldsa.usedHonestKey).toBe(false);
    expect(r.forgedMldsaValid).toBe(false);
    expect(r.forgedEd25519Valid).toBe(false);
    expect(r.forgedValid).toBe(false);
    expect(r.caughtBy).toBe('both');
    // A well-formed signature was still produced — it is simply the wrong one.
    expect(r.forgedSignature.length).toBe(COMPOSITE_SIG_BYTES);
  });

  it('ML-DSA broken: ML-DSA forges, Ed25519 catches it, composite rejects', () => {
    const r = simulateMldsaBreak(generateCompositeKeyPair(), MSG);
    expect(r.legitValid).toBe(true);
    expect(r.mldsa.usedHonestKey).toBe(true);
    expect(r.ed25519.usedHonestKey).toBe(false);
    expect(r.forgedMldsaValid).toBe(true);   // attacker forged a valid ML-DSA sig
    expect(r.forgedEd25519Valid).toBe(false); // attacker cannot forge Ed25519
    expect(r.forgedValid).toBe(false);
    expect(r.caughtBy).toBe('ed25519');
  });

  it('quantum break: Ed25519 forged, ML-DSA catches it, composite rejects', () => {
    const r = simulateQuantumBreak(generateCompositeKeyPair(), MSG);
    expect(r.legitValid).toBe(true);
    expect(r.ed25519.usedHonestKey).toBe(true);
    expect(r.forgedEd25519Valid).toBe(true);  // Shor-forged Ed25519
    expect(r.forgedMldsaValid).toBe(false);   // attacker cannot forge ML-DSA
    expect(r.forgedValid).toBe(false);
    expect(r.caughtBy).toBe('mldsa');
  });

  // The negative verdict: with both families down the forgery must actually be
  // accepted by the real verifier, or none of the rejections above mean anything.
  it('double break: both forged, composite accepts the forgery (residual risk)', () => {
    const kp = generateCompositeKeyPair();
    const r = simulateDoubleBreak(kp, MSG);
    expect(r.forgedMldsaValid).toBe(true);
    expect(r.forgedEd25519Valid).toBe(true);
    expect(r.forgedValid).toBe(true);
    expect(r.caughtBy).toBe('none');
    // Re-run the verifier independently on the exact bytes the attacker built.
    expect(
      compositeVerify(compositePublicKeyFrom(kp), r.forgedMessage, r.forgedSignature).valid
    ).toBe(true);
  });

  it('the forgery is bound to the context it was made under', () => {
    const kp = generateCompositeKeyPair();
    const ctx = new TextEncoder().encode('invoice-signing');
    const r = simulateDoubleBreak(kp, MSG, ctx);
    const pub = compositePublicKeyFrom(kp);
    // Accepted under its own context...
    expect(compositeVerify(pub, r.forgedMessage, r.forgedSignature, ctx).valid).toBe(true);
    // ...and rejected under any other, because ctx is bound into M'.
    expect(compositeVerify(pub, r.forgedMessage, r.forgedSignature).valid).toBe(false);
  });

  it('a forgery for one keypair does not verify against another', () => {
    const victim = generateCompositeKeyPair();
    const r = simulateDoubleBreak(victim, MSG);
    const stranger = compositePublicKeyFrom(generateCompositeKeyPair());
    expect(compositeVerify(stranger, r.forgedMessage, r.forgedSignature).valid).toBe(false);
  });
});
