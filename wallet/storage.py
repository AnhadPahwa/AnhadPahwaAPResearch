from pathlib import Path
import json
from typing import Any, Dict

WALLET_DIR = Path("wallet_data")
CRED_PATH = WALLET_DIR / "credential_bundle.json"  # {"credential":..., "issuer_sig":...}

def save_credential_bundle(bundle: Dict[str, Any]) -> None:
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    CRED_PATH.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")

def load_credential_bundle() -> Dict[str, Any]:
    if not CRED_PATH.exists():
        raise FileNotFoundError("No credential stored. Run wallet 'issue' first.")
    return json.loads(CRED_PATH.read_text(encoding="utf-8"))
