# System Architecture

## Overview

The system implements a two-tier cryptographic identity framework designed to evaluate the feasibility of balancing:
- Child safety (policy-based access control)
- Fraud prevention (strong issuer signatures + revocation)
- User anonymity (minimal disclosure + unlinkability)

The architecture consists of three primary actors:
1. **Issuer (Python / Flask)**
2. **Wallet (Python client)**
3. **Verifier (Node.js / Express)**

Tier 1 and Tier 2 share infrastructure but differ cryptographically.

---

## Tier 1: Attached Credential Model

### Cryptographic Primitive
- Ed25519 digital signatures
- SHA-256 hashing
- Domain-bound presentation digest
- Pairwise pseudonyms via hashing

### Flow

1. Issuer signs credential using Ed25519.
2. Wallet stores credential bundle.
3. Wallet builds presentation:
   - Includes credential
   - Includes issuer signature
   - Includes domain-bound digest
   - Signs digest with wallet key
4. Verifier:
   - Checks nonce freshness
   - Verifies issuer signature
   - Verifies wallet signature
   - Checks revocation status
   - Applies policy

### Properties

- Strong authenticity
- Replay resistance
- Revocation support
- Limited privacy (full credential attached)

---

## Tier 2: BBS+ Selective Disclosure Model

### Cryptographic Primitive
- BBS+ signatures over BLS12-381
- Zero-knowledge proof of knowledge
- Selective disclosure proofs

Library:
- `@mattrglobal/bbs-signatures`

### Flow

1. Issuer signs ordered message vector using BBS+.
2. Wallet stores credential + BBS signature.
3. Wallet generates proof:
   - Selectively reveals specific message indices
   - Hides remaining messages
   - Binds proof to nonce
4. Verifier:
   - Validates proof via `blsVerifyProof`
   - Applies policy using revealed claims
   - Checks revocation status

### Properties

- Hidden attributes never transmitted
- Signature not directly exposed
- Reduced correlation surface
- Higher computational overhead

---

## Shared Components

### Revocation
- Revocation handle embedded in credential
- Issuer maintains status list
- Verifier queries status list
- Revocation enforced at verification

### Nonce System
- Verifier issues challenge nonce
- Nonce is single-use and time-limited
- Prevents replay attacks

### Policy Engine
- Policies mapped to claim semantics
- Enforced post-verification
- Example policies:
  - `age_over_18`
  - `gb_only`

---

## Deployment Model

All components run locally for experimental evaluation:

- Issuer: `localhost:5001`
- Verifier: `localhost:5002`
- Wallet: CLI-driven client

Architecture supports horizontal scalability in theory, but this implementation is experimental.

---

## Architectural Trade-Offs

| Dimension | Tier 1 | Tier 2 |
|------------|--------|--------|
| Privacy | Moderate | High |
| Performance | High | Moderate |
| Complexity | Low | High |
| Disclosure | Full credential | Selective |
| Implementation cost | Low | Significant |

Tier 2 introduces cryptographic complexity but improves disclosure minimization.
