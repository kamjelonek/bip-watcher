# networking/sitemap.py

from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

from bip_watcher.utils import (
    normalize_url,
    canonical_url,
    is_valid_url,
    safe_soup,
    now_iso,
    is_home_url,
    is_listing_url,
    same_base_domain,
    sha1,
)

from bip_watcher.config import (
    START_TIMEOUT_FAST,
    START_TIMEOUT_LONG,
    ATT_EXT,
    JS_EXTRA_SEED_PATHS,
    LISTING_URL_HINTS,
)

# ------------------------------------------------------------
# Helpers: XML sitemap detection
# ------------------------------------------------------------

def _looks_like_xml_sitemap(text: str) -> bool:
    if not text:
        return False
    low = text.lstrip().lower()
    return (
        "<urlset" in low[:4000]
        or "<sitemapindex" in low[:4000]
        or 'xmlns="http://www.sitemaps.org' in low[:4000]
    )

# ------------------------------------------------------------
# XML sitemap parser
# ------------------------------------------------------------

def parse_sitemap_xml(xml_text: str, base_url: str = "") -> tuple:
    urls = []
    children = []

    if not xml_text:
        return urls, children

    try:
        soup = BeautifulSoup(xml_text, "xml")
        if soup is None:
            return urls, children

        # <sitemap><loc>...</loc></sitemap>
        for sm in soup.find_all("sitemap"):
            loc = sm.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u):
                    children.append(normalize_url(u))

        # <url><loc>...</loc></url>
        for uel in soup.find_all("url"):
            loc = uel.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u):
                    urls.append(normalize_url(u))

    except Exception:
        # fallback regex
        try:
            for m in re.findall(
                r"<loc>\s*(https?://[^<\s]+)\s*</loc>",
                xml_text,
                flags=re.IGNORECASE,
            ):
                if is_valid_url(m):
                    urls.append(normalize_url(m))
        except Exception:
            pass

    # deduplication
    def _dedup(lst):
        seen = set()
        out = []
        for x in lst:
            cx = canonical_url(x)
            if cx in seen:
                continue
            seen.add(cx)
            out.append(x)
        return out

    return _dedup(urls), _dedup(children)

# ------------------------------------------------------------
# Missing function: collect_sitemap_urls
# ------------------------------------------------------------

from bip_watcher.networking.fetch_normal import fetch_text_best_effort

async def collect_sitemap_urls(session, base_url, diag, max_urls=4000):
    """
    Collects sitemap URLs from common sitemap locations and robots.txt.
    Returns a list of discovered URLs.
    """

    urls = []
    seen = set()

    candidates = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap.php",
        "/sitemap.txt",
        "/robots.txt",
    ]

    for path in candidates:
        test_url = normalize_url(urljoin(base_url, path))

        text, final, status, ctype, ms = await fetch_text_best_effort(session, test_url)

        diag["start_attempts"].append({
            "try_url": test_url,
            "kind": "sitemap_probe",
            "status": status,
            "ms": ms,
        })

        if not text or status != 200:
            continue

        # robots.txt → extract "Sitemap: ..."
        if "robots.txt" in test_url.lower():
            for line in text.splitlines():
                if "sitemap:" in line.lower():
                    sm = line.split(":", 1)[1].strip()
                    if is_valid_url(sm):
                        urls.append(sm)
            continue

        # XML sitemap
        u, children = parse_sitemap_xml(text, base_url)
        for x in u + children:
            cx = canonical_url(x)
            if cx not in seen:
                seen.add(cx)
                urls.append(x)
                if len(urls) >= max_urls:
                    return urls

    return urls
