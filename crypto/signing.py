from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC

def ed25519_sign(message: bytes, sk: ECC.EccKey) -> bytes:
    """
    Standard Ed25519 over the raw message bytes (RFC8032).
    DO NOT pre-hash here; Node crypto.verify(null, ...) expects this.
    """
    signer = eddsa.new(sk, mode="rfc8032")
    return signer.sign(message)

def ed25519_verify(message: bytes, sig: bytes, pk: ECC.EccKey) -> bool:
    """
    Verify standard Ed25519 signature over raw message bytes.
    """
    try:
        verifier = eddsa.new(pk, mode="rfc8032")
        verifier.verify(message, sig)
        return True
    except ValueError:
        return False
