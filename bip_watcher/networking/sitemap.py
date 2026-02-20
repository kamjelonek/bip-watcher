# networking/sitemap.py
from collections import deque
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, urlunparse
from bip_watcher.utils import normalize_url, canonical_url, is_valid_url, safe_soup
from bip_watcher.config import START_TIMEOUT_FAST, START_TIMEOUT_LONG
from bip_watcher.networking.rate_limiter import DomainRateLimiter
from bip_watcher.utils import sha1
from bip_watcher.config import ATT_EXT
from bip_watcher.utils import now_iso
from bip_watcher.utils import is_home_url
from bip_watcher.utils import is_listing_url
from bip_watcher.utils import same_base_domain
from bip_watcher.utils import safe_soup as _safe_soup
from bip_watcher.utils import canonical_url as _canonical_url
from bip_watcher.utils import normalize_url as _normalize_url
from bip_watcher.utils import is_valid_url as _is_valid_url
from bip_watcher.utils import sha1 as _sha1
from bip_watcher.config import JS_EXTRA_SEED_PATHS, LISTING_URL_HINTS
from bip_watcher.utils import safe_soup
from bip_watcher.utils import now_iso
from bip_watcher.utils import is_valid_url
from bip_watcher.utils import canonical_url
from bip_watcher.utils import normalize_url
from bip_watcher.utils import sha1
from bip_watcher.utils import is_home_url
from bip_watcher.utils import is_listing_url

# Note: fetch_text_best_effort and collect_sitemap_urls depend on fetch functions.
# They will be used by phases; fetch_text_best_effort is implemented in fetch_normal.py
# but we keep parse_sitemap_xml and helpers here.

def _looks_like_xml_sitemap(text: str) -> bool:
    if not text:
        return False
    low = text.lstrip().lower()
    return ("<urlset" in low[:4000]) or ("<sitemapindex" in low[:4000]) or ("xmlns=\"http://www.sitemaps.org" in low[:4000])

def parse_sitemap_xml(xml_text: str, base_url: str = "") -> tuple:
    urls = []
    children = []
    if not xml_text:
        return urls, children
    try:
        soup = BeautifulSoup(xml_text, "xml")
        if soup is None:
            return urls, children
        for sm in soup.find_all("sitemap"):
            loc = sm.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u):
                    children.append(normalize_url(u))
        for uel in soup.find_all("url"):
            loc = uel.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u):
                    urls.append(normalize_url(u))
    except Exception:
        try:
            for m in re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", xml_text, flags=re.IGNORECASE):
                if is_valid_url(m):
                    urls.append(normalize_url(m))
        except Exception:
            pass
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
