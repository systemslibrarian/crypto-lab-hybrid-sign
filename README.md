# crypto-lab-hybrid-sign

Browser-based PQ/T Composite Signature demo implementing the Ed25519 + ML-DSA-65 hybrid per IETF LAMPS `draft-ietf-lamps-pq-composite-sigs-16` (April 2026). Combines a classical Ed25519 signature with a post-quantum ML-DSA-65 signature such that **both must verify** for the composite to be valid. Uses `@noble/curves` for Ed25519 and `@noble/post-quantum` for ML-DSA-65. Demonstrates the two break scenarios the scheme defends against: catastrophic ML-DSA cryptanalysis (classical) and quantum computer compromise of Ed25519. Shows the residual risk of simultaneous double breaks honestly — composites provide defense in depth, not invincibility.

## What It Is

A composite signature combines an Ed25519 signature (classical, 128-bit security) with an ML-DSA-65 signature (post-quantum, ~192-bit security). Both must verify for the composite to be accepted. Forging requires breaking **both** independent algorithm families — elliptic-curve discrete log and module lattice cryptography — simultaneously.

Key sizes: private 4,064 bytes · public 1,984 bytes · signature 3,373 bytes  
Algorithm identifier: `COMPSIG-MLDSA65-ED25519-SHA512`  
TLS 1.3 codepoint: `0x090B (mldsa65_ed25519)`

## When to Use It

- Understanding why long-lived signatures (certificates, identity, legal records) are moving toward PQ/T hybrids during the migration period
- Teaching the "defense in depth" principle — security from multiple independent algorithm families
- Evaluating composite signatures for X.509 code-signing, CA hierarchies, SSH identity keys that must last 10+ years
- Comparing composite signatures to hybrid KEMs (different primitives, same philosophy)
- **Not for:** short-lived session tokens, JWT tokens (use ML-DSA alone once your stack supports it), situations where signature size is constrained (composites are 3,373 bytes vs 64 bytes classical-only)

## Live Demo

https://systemslibrarian.github.io/crypto-lab-hybrid-sign/

## The Five Exhibits

1. **Composite Keypair** — Live generation showing Ed25519 and ML-DSA-65 component keys side by side with sizes and security properties
2. **Sign and Verify** — Step-by-step composite signing (builds M′ = Prefix ‖ Domain ‖ ctx ‖ M, signs with both algorithms) and per-component verification with tamper buttons
3. **Break Scenarios** — Simulate ML-DSA lattice break (Ed25519 catches it) and quantum computer break of Ed25519 (ML-DSA catches it), plus the residual double-break risk
4. **Composite vs Single Algorithm** — Side-by-side size and security comparison; TLS/SSH/X.509 deployment context
5. **Why This Matters** — The 25-year threat model, the crypto-lab story arc (KEMs + signatures), real-world deployment status

## What Can Go Wrong

- Composite signatures protect against **single** algorithm breaks. A simultaneous break of both algorithms defeats the composite. The assumption is that independent algorithm families (discrete log vs lattice) don't fall at the same moment.
- 3,373-byte signatures are ~53× larger than Ed25519 alone. Protocols with tight size budgets (constrained IoT, blockchain transactions) may not tolerate this.
- Both components must be implemented correctly. A bug in either half weakens the composite to just the other algorithm's security.
- The composite label (`COMPSIG-MLDSA65-ED25519-SHA512`) and prefix (`CompositeAlgorithmSignatures2025`) are domain separators — omitting them or using wrong values breaks interoperability even though local verification may still succeed.
- Ed25519 and ML-DSA-65 have different failure modes against side-channel attacks. Implementers must harden both components — composites don't auto-protect against timing attacks.

## Real-World Usage

Composite PQ/T signatures are being standardized by the IETF LAMPS working group in `draft-ietf-lamps-pq-composite-sigs-16` (April 2026) for X.509 certificates and CMS signed data. TLS 1.3 SignatureScheme codepoints have been assigned: `mldsa44_ed25519 (0x090A)` and `mldsa65_ed25519 (0x090B)`. SSH has a separate draft `draft-josefsson-ssh-ed25519mldsa65-01` (October 2025). Major PKI vendors (Entrust, DigiCert) have prototyped composite CA issuance. Microsoft announced composite signature support for Windows code signing in 2026. The scheme is designed for the migration period (~2025–2035) while PQ crypto earns decades of cryptanalytic confidence.

## Stack

Vite + TypeScript strict + vanilla CSS. GitHub Pages. No backends. No `Math.random()` — all randomness via `crypto.getRandomValues` (inside `@noble` primitives).

## The crypto-lab Suite

| Layer | Classical | Post-Quantum | Hybrid |
|---|---|---|---|
| Key exchange (KEM) | [crypto-lab-x3dh-wire](https://github.com/systemslibrarian/crypto-lab-x3dh-wire) | [crypto-lab-kyber-vault](https://github.com/systemslibrarian/crypto-lab-kyber-vault) | [crypto-lab-hybrid-wire](https://github.com/systemslibrarian/crypto-lab-hybrid-wire) |
| Signatures | [crypto-lab-ed25519-forge](https://github.com/systemslibrarian/crypto-lab-ed25519-forge) | [crypto-lab-dilithium-seal](https://github.com/systemslibrarian/crypto-lab-dilithium-seal) | **this repo** |

---

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God." — 1 Corinthians 10:31
