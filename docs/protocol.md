# Protocol Specification

## Actors

- Issuer (I)
- Wallet (W)
- Verifier (V)

---

# Tier 1 Protocol

## 1. Credential Issuance

I -> W:
- Credential (claims)
- Ed25519 signature
- Revocation handle

Credential Bundle:
{
  credential,
  issuer_sig,
  revocation_handle
}

---

## 2. Presentation Request

V -> W:
{
  domain,
  policy_id,
  nonce,
  expires_in_seconds
}

Nonce:
- Random
- Single-use
- Time-limited

---

## 3. Presentation Construction

W:
1. Build digest object:
   {
     version,
     domain,
     policy_id,
     nonce,
     disclosed,
     hidden_commitments
   }
2. Compute SHA-256 digest
3. Sign digest with wallet private key
4. Attach credential + issuer signature

W -> V:
{
  domain,
  policy_id,
  nonce,
  disclosed,
  hidden_commitments,
  bindings,
  attached,
  wallet_sig
}

---

## 4. Verification

V:
1. Check nonce validity
2. Verify issuer signature
3. Recompute digest
4. Verify wallet signature
5. Check revocation
6. Enforce policy

---

# Tier 2 Protocol (BBS+)

## 1. Credential Issuance

Issuer signs ordered message vector:

m[0], m[1], ..., m[n-1]

Using BBS+ over BLS12-381.

Bundle contains:
{
  credential,
  bbs_signature,
  issuer_bbs_pubkey,
  revocation_handle
}

---

## 2. Proof Generation

Wallet:
1. Select indices to reveal
2. Compute proof:
   blsCreateProof({
     publicKey,
     signature,
     messages,
     revealed,
     nonce
   })

3. Construct presentation:
{
  version,
  domain,
  policy_id,
  nonce,
  pairwise_nym,
  issuer_bbs_pubkey,
  revealed_indices,
  revealed_messages_by_index,
  bbs_proof,
  revocation_handle
}

---

## 3. Verification

Verifier:
1. Validate nonce
2. Reconstruct revealed message array
3. Run:
   blsVerifyProof({
     publicKey,
     proof,
     revealed,
     messages,
     nonce
   })
4. Check revocation
5. Apply policy

---

## Message Ordering

Message indices are fixed and deterministic.
Index semantics are defined in implementation.
All parties must use identical ordering.

---

## Nonce Binding

Nonce is derived deterministically and bound to proof.
Prevents replay across sessions.
