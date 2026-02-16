# Tier 1 Freeze (Baseline)

Date: 2026-02-08

Tier 1 is frozen as the baseline implementation for comparison with Tier 2

## Tier 1 features
- Issuer-signed JSON credential (Ed25519)
- Wallet-held credential storage
- Presentation with attached credential (full disclosure in Tier 1)
- Nonce-based replay prevention
- Revocation via issuer status list + verifier cache
- Policy checks (e.g., age_over_18, gb_only)
- Pairwise pseudonym generation (domain-specific)

## 'Do not change' list
- Presentation v1 JSON format and field names
- Credential canonicalization and signing procedure
- Verifier check ordering and failure reasons
- Revocation cache refresh interval and status list format
- Tier 1 test harness + CSV schema

## Baseline results artefact
- experiments/results/tier1_tests.csv 
