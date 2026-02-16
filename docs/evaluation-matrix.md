# Evaluation Matrix

The system is evaluated across multiple dimensions.

---

## Metrics

| Metric | Tier 1 | Tier 2 |
|--------|--------|--------|
| Verification time (ms) | Measured | Measured |
| Proof generation time (ms) | N/A | Measured |
| Presentation size (bytes) | Measured | Measured |
| Replay resistance | Yes | Yes |
| Revocation support | Yes | Yes |
| Selective disclosure | No | Yes |
| Cross-site unlinkability | Partial | Stronger |

---

## Quantitative Metrics

- verify_ms
- prove_ms
- total_ms
- presentation_bytes
- acceptance rate
- replay rejection
- revocation enforcement

---

## Qualitative Metrics

| Criterion | Tier 1 | Tier 2 |
|------------|--------|--------|
| Privacy preservation | Moderate | High |
| Implementation complexity | Low | High |
| Scalability | High | Moderate |
| Fraud resistance | High | High |
| Regulatory compatibility | Moderate | High |

---

## Experimental Scenarios

1. Valid credential (20 runs)
2. Replay attempt
3. Cross-site presentation
4. Revoked credential
5. Policy failure

---

## Interpretation Framework

Feasibility is defined as:

- Sub-100ms total verification latency
- Successful replay rejection
- Successful revocation enforcement
- Selective disclosure functioning correctly

Tier 2 is evaluated for added privacy relative to computational cost.
