import json
from typing import Any

def canonicalize(obj: Any) -> str:
    """
        Canonicalise JSON encoding for signature and verification.
        -sort_keys = True. ensures stable key order
        -separators = (',', ':') removes whitespace variations
        -ensure_ascii = False keeps UTF-8 stable (then encode to UTF-8)
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')