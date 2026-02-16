from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from crypto.canonical import canonicalize
from crypto.hashing import sha256
from crypto.encoding import b64url_encode
from wallet.storage import load_credential_bundle
from wallet.pseudonym import pairwise_nym
from wallet.commitments import commit, new_salt
from wallet.wallet_sign import wallet_sign

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def build_presentation(domain: str, policy_id: str, nonce: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Returns:
      - presentation dict
      - salts dict
    """
    bundle = load_credential_bundle()
    credential = bundle["credential"]
    issuer_sig = bundle["issuer_sig"]

    # salts for commitments (kept private by wallet)
    salt_age = new_salt()
    salt_rev = new_salt()

    age_group = credential["claims"]["age_group"]
    rev_handle = credential["revocation_handle"]

    # minimal disclosed fields for the presentation itself
    disclosed = {
        "issuer_id": credential["issuer_id"],
        "assurance_level": credential["claims"]["assurance_level"],
        "expiry": credential["expiry"],
    }

    hidden_commitments = {
        "age_group_commit": commit(age_group, salt_age),
        "revocation_handle_commit": commit(rev_handle, salt_rev),
    }

    # digest binds: disclosed + commitments + domain + policy + nonce
    digest_obj = {
        "version": "v1",
        "domain": domain,
        "policy_id": policy_id,
        "nonce": nonce,
        "disclosed": disclosed,
        "hidden_commitments": hidden_commitments,
    }
    digest = sha256(canonicalize(digest_obj))
    presentation_digest = b64url_encode(digest)

    pres = {
        "version": "v1",
        "domain": domain,
        "policy_id": policy_id,
        "nonce": nonce,
        "timestamp": utc_now_iso(),
        "pairwise_nym": pairwise_nym(domain),

        "disclosed": disclosed,
        "hidden_commitments": hidden_commitments,

        "bindings": {
            "presentation_digest": presentation_digest
        },

        "attached": {
            "credential": credential,
            "issuer_sig": issuer_sig
        },

        # wallet signature prevents tampering with digest-bound fields
        "wallet_sig": wallet_sign(digest),
    }

    salts = {
        "salt_age_group": b64url_encode(salt_age),
        "salt_revocation_handle": b64url_encode(salt_rev),
    }

    return pres, salts
