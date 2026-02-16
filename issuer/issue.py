from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from uuid import uuid4
import os

from crypto.canonical import canonicalize
from crypto.encoding import b64url_encode
from crypto.signing import ed25519_sign
from Crypto.PublicKey import ECC

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def iso_in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def random_handle(n_bytes: int = 16) -> str:
    return b64url_encode(os.urandom(n_bytes))

@dataclass
class IssuedCredential:
    credential : Dict[str, Any]
    issuer_sig : str    #b64 url

def make_credential(
    subject_pubkey_b64: str,
    claims: Dict[str, Any],
    issuer_id: str="issuer:local:v1",
    expiry_days: int=365,
) -> Dict[str, Any]:
    return {
        "version": "v1",
        "cred_id": str(uuid4()),
        "issuer_id": issuer_id,
        "subject_pubkey": subject_pubkey_b64,
        "claims": claims,
        "expiry": iso_in_days(expiry_days),
        "revocation_handle": random_handle(16)
    }

def sign_credential(
    credential: Dict[str, Any],
    issuer_sk: ECC.EccKey,
) -> IssuedCredential:
    msg = canonicalize(credential)
    signature = ed25519_sign(msg, issuer_sk)
    issuer_sig_b64 = b64url_encode(signature)
    return IssuedCredential(credential=credential, issuer_sig=issuer_sig_b64)