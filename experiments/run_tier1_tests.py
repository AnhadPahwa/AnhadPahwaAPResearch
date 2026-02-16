import time
import csv
from pathlib import Path
import requests

from wallet.presentation import build_presentation
from wallet.storage import load_credential_bundle

VERIFIER = "http://127.0.0.1:5002"
ISSUER = "http://127.0.0.1:5001"

OUT = Path("experiments/results")
OUT.mkdir(parents=True, exist_ok=True)
CSV_PATH = OUT / "tier1_tests.csv"

def now_ms():
    return time.perf_counter() * 1000

def json_size_bytes(obj):
    import json
    return len(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

def get_challenge(policy_id):
    r = requests.get(f"{VERIFIER}/challenge", params={"policy_id": policy_id}, timeout=5)
    r.raise_for_status()
    return r.json()

def verify(pres):
    t0 = now_ms()
    r = requests.post(f"{VERIFIER}/verify", json=pres, timeout=5)
    t1 = now_ms()
    r.raise_for_status()
    return r.json(), (t1 - t0)

def revoke_current_credential():
    bundle = load_credential_bundle()
    handle = bundle["credential"]["revocation_handle"]
    r = requests.post(f"{ISSUER}/revoke", json={"revocation_handle": handle}, timeout=5)
    r.raise_for_status()
    return handle

def run_trial(policy_id="age_over_18", domain="example.com"):
    ch = get_challenge(policy_id)
    pres, _ = build_presentation(domain=domain, policy_id=policy_id, nonce=ch["nonce"])
    resp, verify_ms = verify(pres)
    return pres, resp, verify_ms

def main(n=10):
    rows = []
    # Scenario: valid
    for i in range(n):
        pres, resp, vms = run_trial("age_over_18", "example.com")
        rows.append({
            "scenario": "valid",
            "accepted": resp["accepted"],
            "reason": resp["reason"],
            "verify_ms": round(vms, 2),
            "presentation_bytes": json_size_bytes(pres),
        })

    # Scenario: replay
    pres, resp, vms = run_trial("age_over_18", "example.com")
    rows.append({
        "scenario": "replay_first",
        "accepted": resp["accepted"],
        "reason": resp["reason"],
        "verify_ms": round(vms, 2),
        "presentation_bytes": json_size_bytes(pres),
    })
    resp2, vms2 = verify(pres)
    rows.append({
        "scenario": "replay_second",
        "accepted": resp2["accepted"],
        "reason": resp2["reason"],
        "verify_ms": round(vms2, 2),
        "presentation_bytes": json_size_bytes(pres),
    })

    # Scenario: cross_site
    for i in range(n):
        pres, resp, vms = run_trial("age_over_18", "other.com")
        rows.append({
            "scenario": "cross_site",
            "accepted": resp["accepted"],
            "reason": resp["reason"],
            "verify_ms": round(vms, 2),
            "presentation_bytes": json_size_bytes(pres),
        })

    # Scenario: revoked 
    handle = revoke_current_credential()
    time.sleep(11)  # allow verifier revocation cache refresh
    pres, resp, vms = run_trial("age_over_18", "example.com")
    rows.append({
        "scenario": "revoked",
        "accepted": resp["accepted"],
        "reason": resp["reason"],
        "verify_ms": round(vms, 2),
        "presentation_bytes": json_size_bytes(pres),
        "revocation_handle": handle
    })

    # Write CSV
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with CSV_PATH.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print("Wrote:", CSV_PATH)
    print("Rows:", len(rows))

if __name__ == "__main__":
    main(n=20)
