# crypto-lab-hybrid-sign

## What It Is

Browser-based PQ/T Composite Signature demo implementing the Ed25519 + ML-DSA-65 hybrid per IETF LAMPS `draft-ietf-lamps-pq-composite-sigs-16` (April 2026). Combines a classical Ed25519 signature with a post-quantum ML-DSA-65 signature such that **both must verify** for the composite to be valid. Uses `@noble/curves` for Ed25519 and `@noble/post-quantum` for ML-DSA-65. Demonstrates the two break scenarios the scheme defends against: catastrophic ML-DSA cryptanalysis (classical) and quantum computer compromise of Ed25519. Shows the residual risk of simultaneous double breaks honestly — composites provide defense in depth, not invincibility.

A composite signature combines an Ed25519 signature (classical, 128-bit security) with an ML-DSA-65 signature (post-quantum, ~192-bit security). Both must verify for the composite to be accepted. Forging requires breaking **both** independent algorithm families — elliptic-curve discrete log and module lattice cryptography — simultaneously.

The demo opens with a plain-language hook (a composite signature is two signatures stapled together — one today's-crypto, one quantum-proof — trusted only if **both** check out) and a live **two-lock AND-gate diagram**: message M feeds a classical Ed25519 lock and a post-quantum ML-DSA-65 lock, both feeding an AND gate whose ACCEPT/REJECT output lights green/red in real time as you Verify, tamper, or run a break scenario. The `M′` construction is glossed term-by-term (Prefix, Label, ctx, pre-hash), the 3,373-byte blob is drawn as two labelled halves whose bytes flip in place when a half is tampered, and a "why Shor breaks one but not the other" aside explains the quantum asymmetry (discrete log vs module lattices) that is the whole reason for the pairing.

Key sizes: private 4,064 bytes · public 1,984 bytes · signature 3,373 bytes  
Algorithm identifier: `COMPSIG-MLDSA65-Ed25519-SHA512`  
TLS 1.3 codepoint: `0x090B (mldsa65_ed25519)`

## When to Use It

- Understanding why long-lived signatures (certificates, identity, legal records) are moving toward PQ/T hybrids during the migration period
- Teaching the "defense in depth" principle — security from multiple independent algorithm families
- Evaluating composite signatures for X.509 code-signing, CA hierarchies, SSH identity keys that must last 10+ years
- Comparing composite signatures to hybrid KEMs (different primitives, same philosophy)
- **Not for:** short-lived session tokens, JWT tokens (use ML-DSA alone once your stack supports it), situations where signature size is constrained (composites are 3,373 bytes vs 64 bytes classical-only)
- Do NOT deploy this code in production — it is a teaching demo of the composite construction; use a vetted library tracking the LAMPS composite-signatures draft.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/)**

Generate a composite keypair with its Ed25519 and ML-DSA-65 component keys side by side, sign and verify a message (building the `M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M)` representative and signing with both algorithms), then run the three break scenarios live. Each scenario feeds a real forged signature to the real verifier — the broken component is signed with the live key so it genuinely verifies, the intact component gets random bytes that genuinely fail, and every ✓/✗ is the literal output of `compositeVerify`. A side-by-side panel compares composite vs single-algorithm size and security, with TLS/SSH/X.509 deployment context.

## What Can Go Wrong

- Composite signatures protect against **single** algorithm breaks. A simultaneous break of both algorithms defeats the composite. The assumption is that independent algorithm families (discrete log vs lattice) don't fall at the same moment.
- 3,373-byte signatures are ~53× larger than Ed25519 alone. Protocols with tight size budgets (constrained IoT, blockchain transactions) may not tolerate this.
- Both components must be implemented correctly. A bug in either half weakens the composite to just the other algorithm's security.
- The composite label (`COMPSIG-MLDSA65-Ed25519-SHA512`) and prefix (`CompositeAlgorithmSignatures2025`) are domain separators — omitting them or using wrong values breaks interoperability even though local verification may still succeed.
- Ed25519 and ML-DSA-65 have different failure modes against side-channel attacks. Implementers must harden both components — composites don't auto-protect against timing attacks.

## Real-World Usage

Composite PQ/T signatures are being standardized by the IETF LAMPS working group in `draft-ietf-lamps-pq-composite-sigs-16` (April 2026) for X.509 certificates and CMS signed data. TLS 1.3 SignatureScheme codepoints have been assigned: `mldsa44_ed25519 (0x090A)` and `mldsa65_ed25519 (0x090B)`. SSH has a separate draft `draft-josefsson-ssh-ed25519mldsa65-01` (October 2025). Major PKI vendors (Entrust, DigiCert) have prototyped composite CA issuance. Microsoft announced composite signature support for Windows code signing in 2026. The scheme is designed for the migration period (~2025–2035) while PQ crypto earns decades of cryptanalytic confidence.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-sign
cd crypto-lab-hybrid-sign
npm install
npm run dev
```

## Related Demos

- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the post-quantum half of the composite.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — Ed25519, the classical half of the composite.
- [crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/) — the same defense-in-depth idea applied to KEMs.
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — a hybrid X25519 + ML-KEM-768 key exchange, the KEM counterpart.
- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — X.509 certificate chains, where composite signatures are headed.

## The Five Exhibits

A plain-language **primer** sits above the exhibits: a one-sentence hook, a small caption demoting the standards nomenclature (LAMPS draft-16, TLS `0x090B`), and a live **two-lock AND-gate diagram** (message M → classical Ed25519 lock + post-quantum ML-DSA-65 lock → AND gate → ACCEPT/REJECT) that lights green/red from the real verifier's output as you use Exhibits 2 and 3.

1. **Composite Keypair** — Live generation showing Ed25519 and ML-DSA-65 component keys side by side with sizes and security properties
2. **Sign and Verify** — Step-by-step composite signing with each term of the M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M) representative glossed inline (domain-separator prefix, algorithm label, caller context, pre-hash), the 3,373-byte signature drawn as two labelled halves (ML-DSA 3,309 B ‖ Ed25519 64 B) whose bytes flip in place when tampered, plus per-component verification with tamper and copy-hex buttons
3. **Break Scenarios** — A "why Shor breaks one but not the other" aside (elliptic-curve discrete log vs module lattices) precedes three simulations: ML-DSA lattice break (Ed25519 catches it), quantum break of Ed25519 (ML-DSA catches it), and the residual double break (composite forged). Each simulation feeds a real forged signature to the real verifier — the broken component is signed with the live key so it genuinely verifies, the intact component gets random bytes that genuinely fail, and every ✓/✗ is the literal output of `compositeVerify`. Nothing is narrated or faked.
4. **Composite vs Single Algorithm** — Side-by-side size and security comparison; TLS/SSH/X.509 deployment context
5. **Why This Matters** — The 25-year threat model, the crypto-lab story arc (KEMs + signatures), real-world deployment status

## Stack

Vite + TypeScript strict + vanilla CSS. GitHub Pages. No backends. No `Math.random()` — all randomness via `crypto.getRandomValues` (inside `@noble` primitives). SHA-512 prehash via `@noble/hashes`.

## Accessibility & mobile

Targets WCAG 2.1 AA. Every text/background pair clears 4.5:1 in **both** light and dark themes (accent colours are darkened per-theme; solid button fills keep a fixed black/white label at ≥4.5:1) and focus indicators clear 3:1. Also: a single banner landmark (the shared crypto-lab header), skip link with a programmatic focus target, `aria-live` result regions, labelled form fields, `scope` row/column headers with a keyboard-scrollable table region, a screen-reader label on the redacted private key, 44px touch targets, 16px inputs (no iOS zoom), fluid type, and `prefers-reduced-motion` / `forced-colors` support. Layout reflows cleanly down to 320px.

## Tests

```
npm test
```

14 Vitest unit tests covering: spec prefix/label/size constants, the `Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M)` message representative (including the 255-byte context guard), clean round-trip, context binding, message binding, wrong-length rejection, per-component tamper detection, and all three break scenarios (both single breaks reject, double break is forged). A boot-time self-test also logs a sign/verify/tamper round-trip to the browser console.

## The crypto-lab Suite

| Layer | Classical | Post-Quantum | Hybrid |
|---|---|---|---|
| Key exchange (KEM) | [crypto-lab-x3dh-wire](https://github.com/systemslibrarian/crypto-lab-x3dh-wire) | [crypto-lab-kyber-vault](https://github.com/systemslibrarian/crypto-lab-kyber-vault) | [crypto-lab-hybrid-wire](https://github.com/systemslibrarian/crypto-lab-hybrid-wire) |
| Signatures | [crypto-lab-ed25519-forge](https://github.com/systemslibrarian/crypto-lab-ed25519-forge) | [crypto-lab-dilithium-seal](https://github.com/systemslibrarian/crypto-lab-dilithium-seal) | **this repo** |

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
