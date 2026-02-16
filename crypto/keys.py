from pathlib import Path
from Crypto.PublicKey import ECC

DEFAULT_KEY_DIR = Path("issuer_data")
DEFAULT_SK_PATH = DEFAULT_KEY_DIR / "issuer_sk.pem"
DEFAULT_PK_PATH = DEFAULT_KEY_DIR / "issuer_pk.pem"

def generate_issuer_keypair(sk_path=DEFAULT_SK_PATH, pk_path=DEFAULT_PK_PATH) -> None:
    sk_path.parent.mkdir(parents=True, exist_ok=True)

    sk = ECC.generate(curve='Ed25519')
    pk = sk.public_key()

    sk_path.write_text(sk.export_key(format='PEM'), encoding='utf-8')
    pk_path.write_text(pk.export_key(format='PEM'), encoding='utf-8')

def load_issuer_sk(sk_path=DEFAULT_SK_PATH) -> ECC.EccKey:
    sk_pem = sk_path.read_text(encoding='utf-8')
    return ECC.import_key(sk_pem)

def load_issuer_pk(pk_path=DEFAULT_PK_PATH) -> ECC.EccKey:
    pk_pem = pk_path.read_text(encoding='utf-8')
    return ECC.import_key(pk_pem)