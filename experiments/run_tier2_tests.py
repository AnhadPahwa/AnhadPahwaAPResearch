import csv
import json
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen, Request

ROOT = Path(__file__).resolve().parents[1]
WALLET_DATA = ROOT / "wallet_data"
BUNDLE_V2 = WALLET_DATA / "credential_bundle_v2.json"

VERIFIER_BASE = "http://127.0.0.1:5002"
ISSUER_BASE = "http://127.0.0.1:5001"

POLICY_ID = "age_over_18"
DOMAIN_A = "example.com"
DOMAIN_B = "evil.com"

REVEAL_CSV = "1,2,4" 

N_VALID = 20
REVOCATION_PROPAGATION_WAIT_S = 11


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def http_get_json(url: str) -> dict:
    with urlopen(url) as resp:
        raw = resp.read()
        return json.loads(raw.decode("utf-8"))


def http_post_json(url: str, obj: dict, timeout_s: int = 15) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()
        return json.loads(raw.decode("utf-8"))


def load_wallet_secret() -> bytes:
    p = WALLET_DATA / "wallet_secret.bin"
    if not p.exists():
        raise FileNotFoundError(f"Missing {p}. Create it once (32 random bytes).")
    return p.read_bytes()


def pairwise_nym(domain: str, secret: bytes) -> str:
    import hmac, hashlib
    digest = hmac.new(secret, domain.encode("utf-8"), hashlib.sha256).digest()
    return digest.hex()


def run_bbs_prove(bundle_path: Path, reveal_csv: str, context_str: str) -> tuple[dict, float]:
    cmd = ["node", str(ROOT / "verifier" / "bbs_tool.js"), "prove", str(bundle_path), reveal_csv, context_str]
    t0 = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    prove_ms = (time.perf_counter() - t0) * 1000.0
    if p.returncode != 0:
        raise RuntimeError(f"bbs_tool prove failed\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")
    return json.loads(p.stdout), prove_ms


def build_presentation(domain: str, policy_id: str, nonce: str, nym: str, proof_obj: dict) -> dict:
    return {
        "version": "v2",
        "domain": domain,
        "policy_id": policy_id,
        "nonce": nonce,
        "pairwise_nym": nym,
        "issuer_bbs_pubkey": proof_obj["issuer_bbs_pubkey"],
        "revealed_indices": proof_obj["revealed_indices"],
        "revealed_messages_by_index": proof_obj["revealed_messages_by_index"],
        "bbs_proof": proof_obj["bbs_proof"],
        "revocation_handle": proof_obj["revocation_handle"],
    }


def verify_v2(pres: dict) -> tuple[dict, float]:
    t0 = time.perf_counter()
    resp = http_post_json(f"{VERIFIER_BASE}/verify_v2", pres, timeout_s=15)
    verify_ms = (time.perf_counter() - t0) * 1000.0
    return resp, verify_ms


def revoke_handle(handle: str) -> dict:
    return http_post_json(f"{ISSUER_BASE}/revoke", {"revocation_handle": handle}, timeout_s=10)


def flatten_checks(resp: dict) -> dict:
    c = resp.get("checks") or {}
    return {
        "nonce_fresh": c.get("nonce_fresh"),
        "sig_valid": c.get("sig_valid"),
        "not_revoked": c.get("not_revoked"),
        "policy_satisfied": c.get("policy_satisfied"),
    }


def main():
    # health checks
    vh = http_get_json(f"{VERIFIER_BASE}/health")
    if not vh.get("ok"):
        raise RuntimeError(f"Verifier health not ok: {vh}")
    ih = http_get_json(f"{ISSUER_BASE}/health")
    if not ih.get("ok"):
        raise RuntimeError(f"Issuer health not ok: {ih}")

    if not BUNDLE_V2.exists():
        raise FileNotFoundError(
            f"Missing {BUNDLE_V2}. You must create it once before running the experiment.\n"
            f"e.g. node verifier/bbs_tool.js sign examples/cred_for_bbs.json > wallet_data/credential_bundle_v2.json"
        )

    secret = load_wallet_secret()
    nym_a = pairwise_nym(DOMAIN_A, secret)
    nym_b = pairwise_nym(DOMAIN_B, secret)

    out_dir = ROOT / "experiments" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"tier2_tests.csv"

    fieldnames = [
        "scenario",
        "run_idx",
        "domain",
        "policy_id",
        "accepted",
        "reason",
        "nonce_fresh",
        "sig_valid",
        "not_revoked",
        "policy_satisfied",
        "prove_ms",
        "verify_ms",
        "total_ms",
        "presentation_bytes",
        "pairwise_nym",
        "revocation_handle",
        "notes",
    ]

    rows = []

    # ---- 20x valid ----
    last_valid_pres = None
    last_valid_bytes = None
    last_valid_handle = None

    for i in range(1, N_VALID + 1):
        ch = http_get_json(f"{VERIFIER_BASE}/challenge?policy_id={POLICY_ID}&domain={DOMAIN_A}")
        nonce = ch["nonce"]

        proof_obj, prove_ms = run_bbs_prove(BUNDLE_V2, REVEAL_CSV, nonce)
        pres = build_presentation(DOMAIN_A, POLICY_ID, nonce, nym_a, proof_obj)
        pres_bytes = len(json.dumps(pres).encode("utf-8"))

        resp, verify_ms = verify_v2(pres)
        checks = flatten_checks(resp)

        total_ms = prove_ms + verify_ms

        rows.append({
            "scenario": "valid",
            "run_idx": i,
            "domain": DOMAIN_A,
            "policy_id": POLICY_ID,
            "accepted": resp.get("accepted"),
            "reason": resp.get("reason"),
            **checks,
            "prove_ms": round(prove_ms, 2),
            "verify_ms": round(verify_ms, 2),
            "total_ms": round(total_ms, 2),
            "presentation_bytes": pres_bytes,
            "pairwise_nym": pres.get("pairwise_nym"),
            "revocation_handle": pres.get("revocation_handle"),
            "notes": "",
        })

        if not resp.get("accepted", False):
            raise RuntimeError(f"Valid run {i} failed unexpectedly: {resp}")

        last_valid_pres = pres
        last_valid_bytes = pres_bytes
        last_valid_handle = pres.get("revocation_handle")

        print(f"[valid {i:02d}/{N_VALID}] OK prove_ms={prove_ms:.2f} verify_ms={verify_ms:.2f} total_ms={total_ms:.2f}")

    # ---- 1x replay (reuse last valid pres) ----
    resp_r, verify_ms_r = verify_v2(last_valid_pres)
    checks_r = flatten_checks(resp_r)

    rows.append({
        "scenario": "replay",
        "run_idx": "",
        "domain": DOMAIN_A,
        "policy_id": POLICY_ID,
        "accepted": resp_r.get("accepted"),
        "reason": resp_r.get("reason"),
        **checks_r,
        "prove_ms": 0.0,
        "verify_ms": round(verify_ms_r, 2),
        "total_ms": round(verify_ms_r, 2),
        "presentation_bytes": last_valid_bytes,
        "pairwise_nym": last_valid_pres.get("pairwise_nym"),
        "revocation_handle": last_valid_handle,
        "notes": "Replayed identical JSON; expected NONCE_INVALID (or NONCE_EXPIRED).",
    })

    # ---- 1x cross-site (domain B) ----
    ch_b = http_get_json(f"{VERIFIER_BASE}/challenge?policy_id={POLICY_ID}&domain={DOMAIN_B}")
    nonce_b = ch_b["nonce"]
    proof_b, prove_ms_b = run_bbs_prove(BUNDLE_V2, REVEAL_CSV, nonce_b)
    pres_b = build_presentation(DOMAIN_B, POLICY_ID, nonce_b, nym_b, proof_b)
    pres_bytes_b = len(json.dumps(pres_b).encode("utf-8"))

    resp_b, verify_ms_b = verify_v2(pres_b)
    checks_b = flatten_checks(resp_b)

    rows.append({
        "scenario": "cross_site",
        "run_idx": "",
        "domain": DOMAIN_B,
        "policy_id": POLICY_ID,
        "accepted": resp_b.get("accepted"),
        "reason": resp_b.get("reason"),
        **checks_b,
        "prove_ms": round(prove_ms_b, 2),
        "verify_ms": round(verify_ms_b, 2),
        "total_ms": round(prove_ms_b + verify_ms_b, 2),
        "presentation_bytes": pres_bytes_b,
        "pairwise_nym": pres_b.get("pairwise_nym"),
        "revocation_handle": pres_b.get("revocation_handle"),
        "notes": f"nym_domainA={nym_a} nym_same={nym_a == nym_b}",
    })

    # ---- 1x revocation ----
    if not last_valid_handle:
        raise RuntimeError("No revocation_handle captured from valid runs; cannot run revocation test.")

    revoke_resp = revoke_handle(last_valid_handle)
    time.sleep(REVOCATION_PROPAGATION_WAIT_S)

    ch_rev = http_get_json(f"{VERIFIER_BASE}/challenge?policy_id={POLICY_ID}&domain={DOMAIN_A}")
    nonce_rev = ch_rev["nonce"]
    proof_rev, prove_ms_rev = run_bbs_prove(BUNDLE_V2, REVEAL_CSV, nonce_rev)
    pres_rev = build_presentation(DOMAIN_A, POLICY_ID, nonce_rev, nym_a, proof_rev)
    pres_bytes_rev = len(json.dumps(pres_rev).encode("utf-8"))

    resp_rev, verify_ms_rev = verify_v2(pres_rev)
    checks_rev = flatten_checks(resp_rev)

    rows.append({
        "scenario": "revoked",
        "run_idx": "",
        "domain": DOMAIN_A,
        "policy_id": POLICY_ID,
        "accepted": resp_rev.get("accepted"),
        "reason": resp_rev.get("reason"),
        **checks_rev,
        "prove_ms": round(prove_ms_rev, 2),
        "verify_ms": round(verify_ms_rev, 2),
        "total_ms": round(prove_ms_rev + verify_ms_rev, 2),
        "presentation_bytes": pres_bytes_rev,
        "pairwise_nym": pres_rev.get("pairwise_nym"),
        "revocation_handle": pres_rev.get("revocation_handle"),
        "notes": f"issuer_revoke_resp={revoke_resp}",
    })

    # write CSV
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"\nWrote {out_path}\n")

    # quick stats for verify_ms
    valid_verify = [r["verify_ms"] for r in rows if r["scenario"] == "valid"]
    valid_prove = [r["prove_ms"] for r in rows if r["scenario"] == "valid"]

    def stats(xs):
        xs = [float(x) for x in xs]
        xs.sort()
        n = len(xs)
        avg = sum(xs) / n
        p50 = xs[n // 2]
        p95 = xs[int(n * 0.95) - 1]
        return avg, p50, p95, xs[0], xs[-1]

    v = stats(valid_verify)
    p = stats(valid_prove)

    print("VALID verify_ms: avg=%.2f p50=%.2f p95=%.2f min=%.2f max=%.2f" % v)
    print("VALID prove_ms : avg=%.2f p50=%.2f p95=%.2f min=%.2f max=%.2f" % p)

    if resp_r.get("accepted") is True:
        print("WARNING: replay did not fail. Nonce consumption may be broken.")
    if resp_b.get("accepted") is not True:
        print("WARNING: cross-site verify failed unexpectedly.")
    if resp_rev.get("reason") != "REVOKED":
        print("WARNING: revocation did not produce REVOKED. Cache wait may be too short or revocation not wired.")


if __name__ == "__main__":
    main()
