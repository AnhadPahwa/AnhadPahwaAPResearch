from pathlib import Path
from crypto.hashing import hmac_sha256
from crypto.encoding import b64url_encode

SECRET_PATH = Path("wallet_data") / "wallet_secret.bin"

def load_wallet_secret() -> bytes:
    if not SECRET_PATH.exists():
        raise FileNotFoundError("wallet_secret.bin missing. Run python3 -m wallet.keygen")
    return SECRET_PATH.read_bytes()

def pairwise_nym(domain: str) -> str:
    secret = load_wallet_secret()
    mac = hmac_sha256(secret, domain.encode("utf-8"))
    return b64url_encode(mac)