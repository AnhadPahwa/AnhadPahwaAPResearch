import requests
from wallet.keygen import generate_wallet, wallet_pubkey_b64
from wallet.storage import save_credential_bundle
import argparse

ISSUER_URL = "http://127.0.0.1:5001"

def issue(age_group="18+", assurance_level="high", jurisdiction="GB", expiry_days=90):
    generate_wallet()
    payload = {
        "subject_pubkey": wallet_pubkey_b64(),
        "claims": {
            "age_group": age_group,
            "assurance_level": assurance_level,
            "jurisdiction": jurisdiction
        },
        "expiry_days": expiry_days
    }
    r = requests.post(f"{ISSUER_URL}/issue", json=payload, timeout=5)
    r.raise_for_status()
    bundle = r.json()
    save_credential_bundle(bundle)
    print("Credential saved to wallet_data/credential_bundle.json")

if __name__ == "__main__":  
    p = argparse.ArgumentParser()
    p.add_argument("--age_group", default="18+")
    p.add_argument("--assurance_level", default="high")
    p.add_argument("--jurisdiction", default="GB")
    p.add_argument("--expiry_days", type=int, default=90)
    args = p.parse_args()
    issue(
        age_group=args.age_group,
        assurance_level=args.assurance_level,
        jurisdiction=args.jurisdiction,
        expiry_days=args.expiry_days
    )
