# utils.py
# General helpers: time, url normalization, hashing, retry_io, canonicalization, etc.

import re, time, json, os, random
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import hashlib
from bip_watcher.config import *
from bs4 import BeautifulSoup

def iso_now():
    return datetime.now()

def iso_parse(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def retry_io(action, tries: int = 5, base_sleep: float = 0.6):
    last_exc = None
    for i in range(tries):
        try:
            return action()
        except PermissionError as e:
            last_exc = e
            time.sleep(base_sleep + (i * 0.4) + random.uniform(0.0, 0.3))
        except OSError as e:
            msg = str(e).lower()
            if "permission" in msg or "access" in msg or "denied" in msg:
                last_exc = e
                time.sleep(base_sleep + (i * 0.4) + random.uniform(0.0, 0.3))
            else:
                raise
    if last_exc:
        raise last_exc

def normalize_url(url: str) -> str:
    try:
        p = urlparse(url)
        q = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            kl = (k or "").strip().lower()
            if not kl:
                continue
            if kl.startswith("utm_"):
                continue
            if kl in {
                "fbclid","gclid","yclid","sid","session","sessionid",
                "phpsessid","jsessionid","print","format",
                "lang","locale","language"
            }:
                continue
            q.append((kl, v))
        q.sort(key=lambda kv: kv[0])
        return urlunparse(p._replace(fragment="", query=urlencode(q, doseq=True)))
    except Exception:
        return url

def canonical_url(url: str) -> str:
    u = normalize_url((url or "").strip())
    try:
        p = urlparse(u)
        scheme = (p.scheme or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"
        scheme = "https"
        netloc = (p.netloc or "").lower().strip()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        return urlunparse((scheme, netloc, path, "", p.query, ""))
    except Exception:
        return u

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

def is_home_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return (p.path == "" or p.path == "/")
    except Exception:
        return False

def is_listing_url(u: str) -> bool:
    low = (u or "").lower()
    return any(x in low for x in [
        "/kategorie/", "/kategoria/", "kategoria=", "category", "/category/",
        "lista", "archiwum", "wszystkie", "tag", "/tag/",
        "page=", "strona=", "offset=", "start=", "limit=",
        "/rss", "/feed", "rss.xml", "feed.xml",
        "wyszuk", "szukaj", "search", "query=", "filter", "filtr",
    ])

def is_phase1_listing(u: str) -> bool:
    return is_listing_url(u) or is_home_url(u)

def url_key(url: str) -> str:
    return sha1(canonical_url(url))

def base_domain(host: str) -> str:
    h = (host or "").lower().strip()
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    if parts[-2] in {"com","net","org","gov","edu"} and parts[-1] in {"pl","uk"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def same_base_domain(host_a: str, host_b: str) -> bool:
    if not host_a or not host_b:
        return False
    a = host_a.lower().strip()
    b = host_b.lower().strip()
    if a.startswith("www."): a = a[4:]
    if b.startswith("www."): b = b[4:]
    if a == b:
        return True
    return base_domain(a) == base_domain(b)

def safe_soup(html: str):
    if not html:
        return None
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return None
