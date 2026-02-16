from pathlib import Path
import json
from crypto.canonical import canonicalize
from crypto.signing import ed25519_sign
from crypto.encoding import b64url_encode
from crypto.keys import load_issuer_sk

REVOKED_PATH = Path("issuer_data/revoked.json")

def load_revoked():
    if not REVOKED_PATH.exists():
        return []
    return json.loads(REVOKED_PATH.read_text())

def save_revoked(lst):
    REVOKED_PATH.parent.mkdir(parents=True, exist_ok=True)
    REVOKED_PATH.write_text(json.dumps(lst, indent=2, sort_keys=True))

def build_statuslist():
    revoked = load_revoked()
    status = {
        "version": "v1",
        "issuer_id": "issuer:local:v1",
        "revoked_handles": revoked
    }
    sig = ed25519_sign(canonicalize(status), load_issuer_sk())
    return {
        **status,
        "sig": b64url_encode(sig)
    }
