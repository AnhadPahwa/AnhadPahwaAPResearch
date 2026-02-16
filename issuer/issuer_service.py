from flask import Flask, request, jsonify
from Crypto.PublicKey import ECC

from crypto.keys import DEFAULT_SK_PATH, generate_issuer_keypair, load_issuer_sk
from issuer.issue import make_credential, sign_credential
from issuer.statuslist import build_statuslist, load_revoked, save_revoked

app = Flask(__name__)

def get_sk() -> ECC.EccKey:
    if not DEFAULT_SK_PATH.exists():
        generate_issuer_keypair()
    return load_issuer_sk()

@app.post('/issue')
def issue():
    """
    Request JSON:
    {
        "subject_pubkey": "base64url(...)",
        "claims": {...},
        "expiry_days": int (optional)
    }
    """
    data = request.get_json(force=True, silent=False)

    subject_pubkey = data.get("subject_pubkey")
    claims = data.get("claims")
    expiry_days = int(data.get("expiry_days", 365))

    if not isinstance(subject_pubkey, str) or not subject_pubkey:
        return jsonify({"error": "Invalid or missing subject_pubkey"}), 400
    if not isinstance(claims, dict) or not claims:
        return jsonify({"error": "Invalid or missing claims"}), 400

    #Minimal claim validation
    required = {"age_group", "assurance_level", "jurisdiction"}
    if not required.issubset(claims.keys()):
        return jsonify({"error": f"Missing required claims: {sorted(required)}"}), 400
    
    cred = make_credential(subject_pubkey, claims, expiry_days=expiry_days)
    issued = sign_credential(cred, get_sk())

    return jsonify({
        "credential": issued.credential,
        "issuer_sig": issued.issuer_sig
    }), 200

@app.get("/health")
def health():
    return {"ok": True}, 200

@app.get("/statuslist")
def statuslist():
    return jsonify(build_statuslist())

@app.post("/revoke")
def revoke():
    data = request.get_json(force=True)
    handle = data.get("revocation_handle")
    if not handle:
        return jsonify({"error": "revocation_handle required"}), 400
    revoked = load_revoked()
    if handle not in revoked:
        revoked.append(handle)
        save_revoked(revoked)
    return jsonify({"revoked": handle})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)