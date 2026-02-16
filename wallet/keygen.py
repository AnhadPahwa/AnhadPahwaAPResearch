from pathlib import Path
from Crypto.PublicKey import ECC
from crypto.encoding import b64url_encode

WALLET_DIR = Path("wallet_data")
SK_PATH = WALLET_DIR / "wallet_sk.pem"
PK_PATH = WALLET_DIR / "wallet_pk.pem"
SECRET_PATH = WALLET_DIR / "wallet_secret.bin"

def generate_wallet() -> None:
    WALLET_DIR.mkdir(parents=True, exist_ok=True)

    sk = ECC.generate(curve="Ed25519")
    pk = sk.public_key()

    SK_PATH.write_text(sk.export_key(format="PEM"), encoding="utf-8")
    PK_PATH.write_text(pk.export_key(format="PEM"), encoding="utf-8")

    # secret used for pairwise pseudonyms (HMAC)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(__import__("os").urandom(32))

def load_wallet_sk() -> ECC.EccKey:
    return ECC.import_key(SK_PATH.read_text(encoding="utf-8"))

def load_wallet_pk() -> ECC.EccKey:
    return ECC.import_key(PK_PATH.read_text(encoding="utf-8"))

def wallet_pubkey_b64() -> str:
    """
    We need a stable public key encoding. Use the PEM bytes -> base64url.
    This is not a standard DID encoding, but it's deterministic for the prototype.
    """
    pem = PK_PATH.read_text(encoding="utf-8").encode("utf-8")
    return b64url_encode(pem)

if __name__ == "__main__":
    generate_wallet()
    print("Wallet generated.")
    print("subject_pubkey:", wallet_pubkey_b64())
