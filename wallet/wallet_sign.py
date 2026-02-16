from Crypto.PublicKey import ECC
from crypto.signing import ed25519_sign
from crypto.encoding import b64url_encode
from wallet.keygen import load_wallet_sk

def wallet_sign(message: bytes) -> str:
    sk: ECC.EccKey = load_wallet_sk()
    sig = ed25519_sign(message, sk)
    return b64url_encode(sig)