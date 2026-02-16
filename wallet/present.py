import requests
import json
from pathlib import Path
import argparse

from wallet.presentation import build_presentation

VERIFIER_URL = "http://127.0.0.1:5002"

OUT_DIR = Path("wallet_data")
PRES_PATH = OUT_DIR / "last_presentation.json"
SALTS_PATH = OUT_DIR / "last_presentation_salts.json"

def main(policy_id="age_over_18"):
    # get challenge
    r = requests.get(f"{VERIFIER_URL}/challenge", params={"policy_id": policy_id}, timeout=5)
    r.raise_for_status()
    ch = r.json()

    domain = ch["domain"]
    nonce = ch["nonce"]

    pres, salts = build_presentation(domain=domain, policy_id=policy_id, nonce=nonce)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PRES_PATH.write_text(json.dumps(pres, indent=2, sort_keys=True), encoding="utf-8")
    SALTS_PATH.write_text(json.dumps(salts, indent=2, sort_keys=True), encoding="utf-8")

    print("Saved presentation to", PRES_PATH)
    print("Saved salts to", SALTS_PATH)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--policy_id", default="age_over_18")
    p.add_argument("--domain", default=None, help="Override domain instead of using challenge domain")
    args = p.parse_args()

    # get challenge
    r = requests.get(f"{VERIFIER_URL}/challenge", params={"policy_id": args.policy_id}, timeout=5)
    r.raise_for_status()
    ch = r.json()

    domain = args.domain or ch["domain"]
    nonce = ch["nonce"]
    policy_id = ch["policy_id"]

    pres, salts = build_presentation(domain=domain, policy_id=policy_id, nonce=nonce)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PRES_PATH.write_text(json.dumps(pres, indent=2, sort_keys=True), encoding="utf-8")
    SALTS_PATH.write_text(json.dumps(salts, indent=2, sort_keys=True), encoding="utf-8")

    print("Saved presentation to", PRES_PATH)
    print("Saved salts to", SALTS_PATH)

