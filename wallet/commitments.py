import os
from crypto.hashing import sha256
from crypto.encoding import b64url_encode

def commit(value: str, salt: bytes) -> str:
    """
    Commitment = SHA256(value || salt), base64url.
    This is not ZK, but hides the value unless salt is revealed.
    """
    data = value.encode("utf-8") + salt
    return b64url_encode(sha256(data))

def new_salt(n: int = 16) -> bytes:
    return os.urandom(n)