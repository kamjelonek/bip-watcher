# parsing/keyword_match.py
import re
from bip_watcher.config import KEYWORDS, STRICT_ONLY

def keyword_match_in_blob(blob: str):
    t = re.sub(r"\s+", " ", (blob or "")).strip().lower()
    if not t:
        return (False, None)

    strict_only = STRICT_ONLY if isinstance(STRICT_ONLY, (set, list, tuple)) else set()

    for kw in KEYWORDS:
        k = (kw or "").strip().lower()
        if not k:
            continue

        if (k in strict_only) or (len(k) <= 3):
            if re.search(rf"(?<!\w){re.escape(k)}(?!\w)", t):
                return (True, kw)
        else:
            if k in t:
                return (True, kw)

    return (False, None)
