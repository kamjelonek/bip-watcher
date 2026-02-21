# parsing/keyword_match.py

import re
from bip_watcher.config import KEYWORDS, STRICT_ONLY


def keyword_match_in_blob(blob: str):
    """
    Returns (True, keyword) if any keyword matches the blob.
    STRICT_ONLY keywords require exact word-boundary match.
    Others use substring match.
    """

    # normalize text
    t = re.sub(r"\s+", " ", (blob or "")).strip().lower()
    if not t:
        return (False, None)

    # normalize strict-only list
    strict_only = set(STRICT_ONLY) if STRICT_ONLY else set()

    for kw in KEYWORDS:
        k = (kw or "").strip().lower()

        # skip empty keywords
        if not k:
            continue

        # strict match (word boundary) for short keywords or strict-only
        if (k in strict_only) or (len(k) <= 3):
            if re.search(rf"(?<!\w){re.escape(k)}(?!\w)", t):
                return (True, kw)

        # substring match for longer keywords
        else:
            if k in t:
                return (True, kw)

    return (False, None)
