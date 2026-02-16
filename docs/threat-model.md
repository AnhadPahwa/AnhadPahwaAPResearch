# Threat Model

## Adversaries Considered

1. Malicious verifier
2. Replay attacker
3. Credential thief
4. Colluding verifiers
5. Revocation bypass attempt

---

# Tier 1 Threat Analysis

## Replay Attack
Mitigated by:
- Single-use nonce
- Expiration window

## Credential Forgery
Mitigated by:
- Ed25519 issuer signatures

## Credential Theft
Risk:
- If wallet private key compromised, attacker can present

## Correlation Risk
- Full credential attached
- Claims visible
- Limited unlinkability

---

# Tier 2 Threat Analysis

## Selective Disclosure
Hidden claims not revealed.
Verifier learns only selected indices.

## Replay
Mitigated via nonce binding to proof.

## Cross-Site Correlation
Reduced via:
- Domain-specific pairwise pseudonyms

Remaining Risks:
- IP correlation
- Timing correlation
- Revocation handle reuse

---

# Revocation Risks

Revocation handle reuse may introduce linkability.
Future designs may require:
- Anonymous revocation mechanisms
- Cryptographic accumulators

---

# Out of Scope

- Global passive adversary
- State-level surveillance
- Side-channel timing attacks
- Compromised cryptographic primitives

---

# Security Assumptions

- Hardness of discrete logarithm in BLS12-381
- Security of Ed25519
- Secure hash function (SHA-256)
- Honest-but-curious verifier model
