# parsing/link_extraction.py

import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from bip_watcher.utils import normalize_url, is_valid_url
from bip_watcher.config import ATT_EXT, IGNORE_URL_SUBSTR, IGNORE_ANCHOR_TEXT, BAD_EXT


def url_is_ignored(url: str) -> bool:
    u = (url or "").lower()
    return any(x in u for x in IGNORE_URL_SUBSTR)


def anchor_is_ignored(text: str) -> bool:
    t = re.sub(r"\s+", " ", (text or "").strip().lower())
    if not t or len(t) <= 2:
        return True
    return any(x in t for x in IGNORE_ANCHOR_TEXT)


def should_skip_href(abs_href: str) -> bool:
    u = (abs_href or "").lower()

    # Special-case hotfix from original script
    try:
        host = urlparse(abs_href).netloc.lower()
        if (
            "gminadomaniow.pl" in host
            and "/aktualnosci/" in u
            and "prognoza-pogody" in u
        ):
            return True
    except Exception:
        pass

    # Skip versioned URLs like /wersja/123
    if re.search(r"/wersja/\d+/?$", u):
        return True

    if url_is_ignored(u):
        return True

    # Skip bad extensions
    if any(u.endswith(ext) for ext in BAD_EXT):
        return True

    # Skip attachments (handled separately)
    if any(u.endswith(ext) for ext in ATT_EXT):
        return True

    return False


def iter_links_fast(soup: BeautifulSoup, base_url: str):
    yielded = set()
    priority = []

    # Extract priority links (breadcrumbs, nav)
    try:
        breadcrumbs = soup.find_all(
            ["nav", "ol", "ul"],
            class_=lambda x: isinstance(x, str)
            and ("breadcrumb" in x.lower() or "okruszek" in x.lower())
        )
        for bc in breadcrumbs:
            priority.extend(bc.find_all("a", href=True))

        nav_elements = soup.find_all(
            ["nav", "div"],
            class_=lambda x: isinstance(x, str)
            and ("nav" in x.lower() or "menu" in x.lower())
        )
        for nav in nav_elements[:3]:
            priority.extend(nav.find_all("a", href=True))

    except Exception:
        pass

    # All links
    try:
        all_links = soup.find_all("a", href=True)
    except Exception:
        all_links = []

    for a in priority + all_links:
        try:
            href = (a.get("href") or "").strip()
            if not href:
                continue

            abs_u = normalize_url(urljoin(base_url, href))
            if not is_valid_url(abs_u):
                continue

            txt = a.get_text(" ", strip=True)
            is_attachment = any(abs_u.lower().endswith(ext) for ext in ATT_EXT)

            # Skip unwanted links unless they are attachments
            if should_skip_href(abs_u) and not is_attachment:
                continue

            # Skip anchors with useless text
            if (not is_attachment) and anchor_is_ignored(txt):
                continue

            if abs_u in yielded:
                continue

            yielded.add(abs_u)
            yield abs_u, txt

        except Exception:
            continue
