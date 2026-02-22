# -*- coding: utf-8 -*-
"""
BIP WATCHER v2.4 (CELL + VS Code / Windows) - PRODUCTION
Zmiany v2.4:
- _soup_fast_text: usuwa TYLKO script/style/noscript, bierze cały tekst strony
- Usunięty page_fingerprint i fp z cache (niepotrzebne, att_sig wystarczy)
- ENABLE_LINK_HITS=True: łapie ogłoszenia z anchor textu linków na stronach listingowych
- blob do matchowania = title + h1 + h2 + CAŁY tekst strony
"""

import os, csv, json, hashlib, asyncio, re, time, smtplib, warnings, socket, random, signal
from collections import deque, defaultdict, Counter
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from pathlib import Path
import subprocess

import aiohttp
import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def env_float(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

def get_shard_index():
    try:
        return int(os.getenv("SHARD_INDEX", "-1"))
    except:
        return -1

def _git_commit_file(filepath, message):
    if os.getenv("GITHUB_ACTIONS"):
        print(f"📁 Plik zapisany lokalnie (bez commita): {filepath}")
        return
    try:
        print(f"📤 Git commit: {filepath} with message: {message}")
        subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=False)
        subprocess.run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"], check=False)
        subprocess.run(["git", "pull", "--rebase"], check=False)
        subprocess.run(["git", "add", str(filepath)], check=False)
        subprocess.run(["git", "commit", "-m", message], check=False)
        subprocess.run(["git", "push"], check=False)
    except Exception as e:
        print(f"⚠️ git error: {e}")

async def save_shard_cache_and_commit(loop=None):
    shard = get_shard_index()
    if shard < 0:
        return

    out = {"schema": CACHE_SCHEMA}
    out["urls_seen"] = {}
    old_urls = (state.raw_cache or {}).get("urls_seen", {}) if isinstance(state.raw_cache, dict) else {}
    for h in state.urls_seen:
        out["urls_seen"][h] = old_urls.get(h, now_iso())
    out["content_seen"] = state.content_seen or {}
    out["gmina_seeds"] = state.gmina_seeds or {}
    out["gmina_frontiers"] = state.gmina_frontiers or {}
    out["gmina_retry"] = state.gmina_retry or {}
    out["dead_urls"] = getattr(state, 'dead_urls', {})

    filename = BASE_DIR / f"cache_shard_{shard}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"📁 Plik shardowy zapisany: {filename}")
    except Exception as e:
        print(f"⚠️ Failed to write shard cache: {e}")
        return

    if not os.getenv("GITHUB_ACTIONS"):
        if loop is None:
            loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _git_commit_file, filename, f"Auto-update cache shard {shard} [skip ci]")
    else:
        print("📌 W GHA – plik zapisany lokalnie, commit pominięty")

# ===================== PATHS =====================
BASE_DIR = Path(__file__).resolve().parent / "data"
BASE_DIR.mkdir(parents=True, exist_ok=True)
CSV_FILE = BASE_DIR / "bipy1.csv"
CACHE_FILE = BASE_DIR / "cache.json"
LOG_FILE = BASE_DIR / "log.csv"
DIAG_GMINY_CSV = BASE_DIR / "diag_gminy.csv"
DIAG_ERRORS_CSV = BASE_DIR / "diag_errors.csv"
SUMMARY_FILE = BASE_DIR / "summary_report.txt"
ONEDRIVE_EXPORT_DIR = Path(r"P:\WORKSPACE\PP_ALL")

# ===================== USER SWITCHES =====================
UNLIMITED_SCAN = True
USE_CACHE = True
ONLY_GMINA = None
CRAWL_ALL_INTERNAL_LINKS = True
BOOTSTRAP_MODE = False
FORCE_PHASE1_REDISCOVERY = True

# ===================== REPORTING RULES =====================
REAL_NEW_ONLY = True
CHANGE_ONLY_ATTACHMENTS = True
ENABLE_LINK_HITS = True        # ✅ WŁĄCZONE — łapie ogłoszenia z anchor textu na listingach
ALIAS_FINAL_AND_SOURCE_KEYS = True

# ===================== EMAIL =====================
EMAIL_TO = "planowanie@wpd-polska.pl"
ENABLE_EMAIL = False

# ===================== KEYWORDS =====================
KEYWORDS = [
    # mpzp / plany
    "mpzp", "miejscowy plan", "plan miejscowy", "miejscowego", "miejscowy plan zagospodarowania przestrzennego",
    "projekt mpzp", "miejscowego planu zagospodarowania przestrzennego",
    # plan ogólny
    "plan ogólny", "plan ogolny", "planu ogólnego",
    # studium
    "studium uwarunkowań", "studium uwarunkowan",
    # decyzje
    "warunki zabudowy", "decyzja o warunkach zabudowy", "decyzje o warunkach zabudowy",
    "decyzja środowiskowa", "decyzje środowiskowe",
    "decyzja o środowiskowych uwarunkowaniach", "środowiskowych uwarunkowaniach",
    "raport o oddziaływaniu na środowisko",
    # OZE: wiatr / PV
    "oze",
    "elektrownia wiatrowa", "farma wiatrowa", "wiatr", "wiatrow", "turbina",
    "fotowolta", "farma fotowoltaiczna", "magazyn energii",
]

STRICT_ONLY = {
    "wz", "mpzp", "oze"
}

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

# ===================== IGNORE =====================
IGNORE_URL_SUBSTR = [
    "kontakt", "mapa-strony", "mapa_strony", "wyszukiwarka", "statystyka",
    "rodo", "cookies", "deklaracja-dostepnosci", "deklaracja_dostepnosci",
    "oswiadczenia", "oświadczenia", "majatk", "majątk",
    "kadra", "struktura", "regulamin", "procedur", "sygnalis",
    "login", "logowanie", "rejestracja", "newsletter", "archiwum-2",
    "galeria-zdjec", "galeria_zdjec", "multimedia", "wideo",
]
IGNORE_ANCHOR_TEXT = [
    "przejdź do menu", "przejdz do menu",
    "przejdź do treści", "przejdz do tresci",
    "włącz wersję kontrastową", "wlacz wersje kontrastowa",
    "drukuj", "pobierz", "pobierz dane", "xml", "rss", "start", "home", "menu",
    "zamknij", "wróć", "wroc", "cofnij", "następna strona", "poprzednia strona",
    "czytaj więcej", "czytaj wiecej", "zobacz więcej", "zobacz wiecej",
]
BAD_EXT = (
    ".jpg",".jpeg",".png",".gif",".webp",".svg",
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",
    ".zip",".rar",".7z",".tar",".gz"
)

# ===================== PERFORMANCE =====================
CONCURRENT_GMINY = env_int("CONCURRENT_GMINY", 8)
CONCURRENT_REQUESTS = env_int("CONCURRENT_REQUESTS", 30)
LIMIT_PER_HOST = env_int("LIMIT_PER_HOST", 4)

PHASE1_MAX_PAGES = 1000
PHASE1_MAX_SEEDS = 12000
PHASE2_MAX_DEPTH = 4           # ✅ zwiększone z 4 — BIPy często mają głębszą strukturę
PHASE2_MAX_PAGES = 1000000

ABSOLUTE_MAX_SEC_PER_GMINA = 10**9
MAX_SEC_PER_GMINA = 10**9

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=8, sock_read=20)
START_TIMEOUT_FAST = aiohttp.ClientTimeout(total=None, sock_connect=8, sock_read=15)
START_TIMEOUT_LONG = aiohttp.ClientTimeout(total=None, sock_connect=12, sock_read=30)
START_MAX_TRIES = 16
START_AUX_HINTS = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]
START_TOTAL_TIMEOUT_SEC = 120

SCANNED_TTL_DAYS = 365
MAX_PRINT_PER_GMINA = 30
MAX_ERROR_SAMPLES_PER_GMINA = 60

PAGINATION_CAP_BASE = 700 if UNLIMITED_SCAN else 140
PAGINATION_CAP_HIGH = 12000 if UNLIMITED_SCAN else 2500
PAGINATION_CAP_LOW  = 1200 if UNLIMITED_SCAN else 300

CACHE_CHECKPOINT_EVERY_N_GMINY = 3
SEED_CACHE_TTL_DAYS = 30

# ✅ Brak limitu tekstu — skanujemy całą stronę
FAST_TEXT_MAX_CHARS = 999_999

HIT_RECHECK_TTL_HOURS = 24
NO_MATCH_RECHECK_TTL_HOURS = 24
BLOCKED_RECHECK_TTL_MIN = env_int("BLOCKED_RECHECK_TTL_MIN", 180)
FAILED_RECHECK_TTL_MIN  = env_int("FAILED_RECHECK_TTL_MIN", 120)

# ===================== USER AGENTS =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "DNT": "1",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }

# ===================== RATE LIMITING =====================
class DomainRateLimiter:
    def __init__(self, min_delay=0.5, max_delay=1.5):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.last_request = {}
        self.locks = defaultdict(asyncio.Lock)
        self.problem_domains = defaultdict(int)

    async def wait(self, domain: str):
        async with self.locks[domain]:
            last = self.last_request.get(domain, 0)
            now = time.time()
            elapsed = now - last
            base_delay = self.min_delay
            if self.problem_domains.get(domain, 0) > 3:
                base_delay = 2.0
            delay = random.uniform(base_delay, base_delay * 2)
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self.last_request[domain] = time.time()

    def report_403(self, domain: str):
        self.problem_domains[domain] += 1

rate_limiter = DomainRateLimiter(
    min_delay=env_float("RATE_MIN_DELAY", 0.5),
    max_delay=env_float("RATE_MAX_DELAY", 1.5),
)

# ===================== GLOBAL STATE =====================
class GlobalState:
    def __init__(self):
        self.shutdown_requested = False
        self.new_items_for_mail = []
        self.raw_cache = {}
        self.urls_seen = set()
        self.content_seen = {}
        self.gmina_seeds = {}
        self.diag_rows = []
        self.diag_errors = []
        self.gmina_frontiers = {}
        self.gmina_retry = {}
        self.dead_urls = {}
        self.cache_lock = asyncio.Lock()
        self.mail_dedup = set()

    def request_shutdown(self):
        self.shutdown_requested = True
        print("\n⚠️  CTRL+C detected - graceful shutdown...", flush=True)

state = GlobalState()

RUN_DEADLINE_MIN = env_int("RUN_DEADLINE_MIN", 0)
GLOBAL_T0 = time.time()

def signal_handler(signum, frame):
    state.request_shutdown()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ===================== UTILS =====================
def iso_now():
    return datetime.now()

def iso_parse(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def _canon(u: str) -> str:
    return canonical_url(normalize_url(u or ""))

def retry_add(gkey: str, retry_seen: set, url: str):
    cu = _canon(url)
    if not cu:
        return
    hu = sha1(cu)
    if hu in retry_seen:
        return
    retry_seen.add(hu)
    state.gmina_retry.setdefault(gkey, []).append(cu)

def dead_add(dead_key: str, dead_set: set, url: str):
    cu = _canon(url)
    if not cu:
        return
    if cu in dead_set:
        return
    dead_set.add(cu)
    state.dead_urls.setdefault(dead_key, []).append(cu)

def pick_rows_for_shard(rows, shard_index: int, shard_total: int):
    if shard_index < 0 or shard_index >= len(rows):
        return []
    return [rows[shard_index]]

def should_recheck_hit(prev: dict) -> bool:
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(hours=HIT_RECHECK_TTL_HOURS)

def should_recheck_no_match(prev: dict) -> bool:
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(hours=NO_MATCH_RECHECK_TTL_HOURS)

def should_recheck_block(prev: dict, ttl_min: int) -> bool:
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(minutes=int(ttl_min or 0))

def is_monitored_hit(prev: dict) -> bool:
    if not prev or not isinstance(prev, dict):
        return False
    return prev.get("status") in {"NOWE", "ZMIANA", "HIT"}

def export_summary_to_onedrive():
    try:
        if not ONEDRIVE_EXPORT_DIR or str(ONEDRIVE_EXPORT_DIR).strip() == "":
            print("ℹ️ OneDrive export: pominięty.")
            return
        if not ONEDRIVE_EXPORT_DIR.exists():
            print(f"ℹ️ OneDrive export: folder nie istnieje: {ONEDRIVE_EXPORT_DIR}")
            return
        if not SUMMARY_FILE.exists():
            print(f"ℹ️ OneDrive export: brak pliku summary: {SUMMARY_FILE}")
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        out_file = ONEDRIVE_EXPORT_DIR / f"summary_{ts}.txt"
        def _do():
            data = SUMMARY_FILE.read_text(encoding="utf-8", errors="ignore")
            out_file.write_text(data, encoding="utf-8")
        retry_io(_do, tries=5, base_sleep=0.4)
        print(f"✅ OneDrive export: {out_file}")
    except Exception as e:
        print(f"⚠️ OneDrive export failed: {e}")

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

# ===================== BLOCK PAGE DETECTOR =====================
_BLOCK_PATTERNS_SURE = [
    "#13",
    "zbyt dużo jednoczesnych połączeń",
    "zbyt wiele jednoczesnych połączeń",
    "spróbuj za moment",
    "sprobuj za moment",
    "spróbuj ponownie później",
    "sprobuj ponownie pozniej",
    "twoja aktywność została uznana",
    "twoja aktywnosc zostala uznana",
    "too many requests",
    "request blocked",
    "403 forbidden",
    "access denied",
]

_BLOCK_PATTERNS_CONTEXT = [
    r"\bservice unavailable\b",
    r"\btemporarily unavailable\b",
    r"\bsite is unavailable\b",
]

def is_block_page(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    for p in _BLOCK_PATTERNS_SURE:
        if p.lower() in low:
            return True
    import re as _re
    try:
        from bs4 import BeautifulSoup as _BS
        _soup = _BS(text[:8000], "html.parser")
        visible = _re.sub(r"\s+", " ", _soup.get_text(" ", strip=True)).strip()
    except Exception:
        visible = _re.sub(r"<[^>]+>", " ", text[:4000]).strip()
    if len(visible) < 600:
        for pattern in _BLOCK_PATTERNS_CONTEXT:
            if _re.search(pattern, low[:4000]):
                return True
    return False

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

def migrate_content_seen_to_url_dedup(content_seen: dict):
    if not isinstance(content_seen, dict) or not content_seen:
        return
    added = 0
    for _k, meta in list(content_seen.items()):
        if not isinstance(meta, dict):
            continue
        url = meta.get("url")
        if not url:
            continue
        url_dedup = sha1(canonical_url(url))
        if url_dedup in content_seen:
            continue
        kw = meta.get("keyword")
        kws = []
        if kw:
            kws = [kw]
        content_seen[url_dedup] = {
            "found_at": meta.get("found_at", now_iso()),
            "gmina": meta.get("gmina", ""),
            "title": (meta.get("title") or "")[:240],
            "url": url,
            "keywords": kws,
            "status": meta.get("status", "SEEN"),
        }
        added += 1
    if added:
        print(f"🔁 Migrated content_seen: added {added} url-keys")

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

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
    try:
        host = urlparse(abs_href).netloc.lower()
        if ("gminadomaniow.pl" in host) and ("/aktualnosci/" in u) and ("prognoza-pogody" in u):
            return True
    except Exception:
        pass
    if re.search(r"/wersja/\d+/?$", u):
        return True
    if url_is_ignored(u):
        return True
    if any(u.endswith(ext) for ext in BAD_EXT):
        return True
    if any(u.endswith(ext) for ext in ATT_EXT):
        return True
    return False

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

# ===================== SITEMAP + ROBOTS + JS HEAVY =====================
def detect_js_app(html: str) -> bool:
    if not html:
        return False
    low = html.lower()
    markers = [
        'id="root"', "id='root'",
        'id="app"', "id='app'",
        "__next_data__", "next.js",
        "data-reactroot", "react",
        "nuxt", "__nuxt", "vue",
        "webpack", "vite",
    ]
    has_marker = any(m in low for m in markers)
    try:
        soup = safe_soup(html)
        if not soup:
            return has_marker
        txt = soup.get_text(" ", strip=True)
        txt = re.sub(r"\s+", " ", txt).strip()
        if len(txt) < 200 and has_marker:
            return True
        scripts = len(soup.find_all("script"))
        if len(txt) < 120 and scripts >= 8:
            return True
        return False
    except Exception:
        return has_marker

def extract_sitemaps_from_robots(robots_text: str) -> list:
    out = []
    if not robots_text:
        return out
    for line in robots_text.splitlines():
        line = (line or "").strip()
        if not line:
            continue
        if line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[-1].strip()
            if sm and is_valid_url(sm):
                out.append(normalize_url(sm))
    uniq = []
    seen = set()
    for u in out:
        cu = canonical_url(u)
        if cu not in seen:
            seen.add(cu)
            uniq.append(u)
    return uniq

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

async def fetch_text_best_effort(session: aiohttp.ClientSession, url: str, timeout: aiohttp.ClientTimeout = None):
    if timeout is None:
        timeout = START_TIMEOUT_FAST
    url = normalize_url(url)
    domain = urlparse(url).netloc
    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            t0 = time.time()
            async with session.get(url, timeout=timeout, ssl=ssl_mode, allow_redirects=True, headers=headers) as resp:
                final = normalize_url(str(resp.url))
                status = resp.status
                ctype = (resp.headers.get("Content-Type", "") or "").lower()
                data = await resp.read()
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = data.decode("latin-1", errors="ignore")
                ms = round((time.time() - t0) * 1000)
                return text, final, status, ctype, ms
        except Exception:
            continue
    return "", url, None, "", None

async def collect_sitemap_urls(session: aiohttp.ClientSession, base_site_url: str, diag, max_urls: int = 4000):
    out_urls = []
    seen_sitemaps = set()
    try:
        robots_url = normalize_url(urljoin(base_site_url, "/robots.txt"))
        robots_text, r_final, r_status, r_ctype, r_ms = await fetch_text_best_effort(session, robots_url, timeout=START_TIMEOUT_FAST)
        if robots_text and (r_status and 200 <= int(r_status) < 400):
            diag["counts"]["robots_ok"] += 1
            sms = extract_sitemaps_from_robots(robots_text)
        else:
            diag["counts"]["robots_fail"] += 1
            sms = []
    except Exception:
        diag["counts"]["robots_fail"] += 1
        sms = []
    default_sms = [
        normalize_url(urljoin(base_site_url, "/sitemap.xml")),
        normalize_url(urljoin(base_site_url, "/sitemap_index.xml")),
        normalize_url(urljoin(base_site_url, "/sitemap-index.xml")),
    ]
    sitemap_queue = deque()
    for sm in (sms + default_sms):
        csm = canonical_url(sm)
        if csm not in seen_sitemaps:
            seen_sitemaps.add(csm)
            sitemap_queue.append(sm)
    processed = 0
    while sitemap_queue and len(out_urls) < max_urls and processed < 40:
        processed += 1
        sm_url = sitemap_queue.popleft()
        diag["counts"]["sitemap_fetch_attempts"] += 1
        xml_text, sm_final, sm_status, sm_ctype, sm_ms = await fetch_text_best_effort(session, sm_url, timeout=START_TIMEOUT_LONG)
        if not xml_text or not (sm_status and 200 <= int(sm_status) < 400):
            diag["counts"]["sitemap_fetch_fail"] += 1
            continue
        if ("xml" not in (sm_ctype or "").lower()) and (not _looks_like_xml_sitemap(xml_text)):
            diag["counts"]["sitemap_non_xml"] += 1
            continue
        diag["counts"]["sitemap_fetch_ok"] += 1
        urls, children = parse_sitemap_xml(xml_text, base_url=base_site_url)
        if urls:
            diag["counts"]["sitemap_urls_found"] += len(urls)
            out_urls.extend(urls)
        for ch in children[:200]:
            cch = canonical_url(ch)
            if cch not in seen_sitemaps:
                seen_sitemaps.add(cch)
                sitemap_queue.append(ch)
        if out_urls:
            tmp = []
            seen = set()
            for u in out_urls:
                cu = canonical_url(u)
                if cu in seen:
                    continue
                seen.add(cu)
                tmp.append(u)
            out_urls = tmp[:max_urls]
    return out_urls[:max_urls]

def extract_title_h1_h2(soup: BeautifulSoup):
    if not soup:
        return "", "", "", ""

    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    title = _clean(soup.title.get_text(" ", strip=True) if soup.title else "")

    h1 = soup.find("h1")
    h2 = soup.find("h2")
    h3 = soup.find("h3")

    h1t = _clean(h1.get_text(" ", strip=True) if h1 else "")
    h2t = _clean(h2.get_text(" ", strip=True) if h2 else "")
    h3t = _clean(h3.get_text(" ", strip=True) if h3 else "")

    if not (h1t or h2t or h3t):
        fallback_selectors = [
            "#page-title", "#pagetitle", "#content-title", "#title",
            ".page-title", ".entry-title", ".post-title", ".article-title",
            ".tytul", ".tytuł", ".naglowek", ".nagłowek", ".naglowekStrony",
            ".title", "header .title", "header .page-title",
        ]
        for sel in fallback_selectors:
            try:
                node = soup.select_one(sel)
                if node:
                    txt = _clean(node.get_text(" ", strip=True))
                    if txt and len(txt) >= 6:
                        h1t = txt
                        break
            except Exception:
                continue

    meta_desc = ""
    try:
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            meta_desc = _clean(meta.get("content", ""))
    except Exception:
        meta_desc = ""

    blob = _clean(f"{title} {h1t} {h2t} {h3t} {meta_desc}")
    return title, h1t, h2t, blob

def print_hit(tag: str, gmina: str, kw: str, title: str):
    shown = re.sub(r"\s+", " ", (title or "").strip())
    print(f"{tag} {gmina}: [{kw}] -> {shown[:180]}", flush=True)

# ===================== LISTING URL HINTS =====================
LISTING_URL_HINTS = [
    "ogloszenia", "ogłoszenia", "obwieszc", "komunikat", "zawiadom",
    "konsultac", "wylozen", "wyłożen", "przystap", "przystąp",
    "prawo-miejscowe", "prawo_miejscowe", "uchwaly", "uchwał",
    "rejestr-urbanist", "rejestr_urbanist", "urbanist",
    "mpzp", "plan-ogolny", "plan_ogolny", "studium", "planowanie",
    "warunki-zabudowy", "warunki_zabudowy", "wz",
    "ochrona-srodowiska", "ochrona_srodowiska",
    "srodowisko", "środowisko", "pv", "fotowolta", "fotowoltaika", "slonecz", "słonecz",
    "oze", "energia", "energetyka", "decyzje-srodowisk", "decyzje_srodowisk", "ooś", "oos",
    "archiwum-ogloszen", "archiwum_ogloszen", "bip-archiwum",
    "kategoria", "kategorie", "lista-ogloszen", "lista_ogloszen",
    "decyzje", "decyzja", "postanowienie", "obwieszczenie",
    "srodowiskowe", "srodowiskowa", "srodowiskowych",
    "plany", "plan", "plany-zagospodarowania", "plany_zagospodarowania",
    "uchwala", "uchwaly", "uchwal", "uchwalone",
]

JS_EXTRA_SEED_PATHS = [
    "/rss", "/feed", "/rss.xml", "/feed.xml",
    "/wp-json", "/wp-json/wp/v2/posts",
    "/api", "/api/ogloszenia", "/api/announcements",
    "/sitemap.xml.gz", "/sitemap_index.xml.gz", "/sitemap.php",
    "/sitemap.xml?page=1", "/sitemap.xml?page=2",
    "/ogloszenia.xml", "/ogloszenia.rss",
    "/kategorie.xml", "/kategorie.rss",
    "/bip-sitemap.xml", "/bip-sitemap_index.xml",
]

# ===================== FAST TEXT =====================
# ✅ KLUCZOWA ZMIANA v2.4:
# Usuwa TYLKO script/style/noscript — bierze CAŁY tekst strony.
# Nie filtrujemy nav/footer/header/aside ani klas UI.
# Keyword może być gdziekolwiek na stronie — w tytule dokumentu,
# w treści tabeli, w stopce kategorii, w metatagu — wszędzie.
def _soup_fast_text(soup: BeautifulSoup, max_chars: int = FAST_TEXT_MAX_CHARS) -> str:
    try:
        if not soup:
            return ""
        # Usuń tylko kod i style — nic więcej
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        # Weź CAŁY widoczny tekst strony
        txt = soup.get_text(" ", strip=True)
        txt = re.sub(r"\s+", " ", (txt or "")).strip()
        txt = _strip_dynamic_noise(txt)
        return txt
    except Exception:
        return ""

def _strip_dynamic_noise(txt: str) -> str:
    if not txt:
        return ""
    txt = re.sub(
        r"wygenerowano:\s*\d{1,2}\s+[a-ząćęłńóśźż]+\s+\d{4}\s*r?\.?\s*\d{1,2}:\d{2}:\d{2}",
        "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(
        r"wygenerowano:\s*\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\s+\d{1,2}:\d{2}:\d{2}",
        "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(r"(wyświetleń|wyswietlen|odsłon|odslon|pobrań|pobran)\s*:\s*\d+", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"odsłony:\s*\d+", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt

# ===================== GENERIC BIP PAGE FILTER =====================
SITEWIDE_TITLES_RE = re.compile(
    r"(biuletyn informacji publicznej|\bbip\b|gmina|urząd gminy|urzad gminy|"
    r"miasto|urząd miasta|urzad miasta|starostwo|powiat|województwo|wojewodztwo)",
    re.IGNORECASE
)

GENERIC_CATEGORY_TITLES_RE = re.compile(
    r"^(warunki zabudowy|decyzje? (o |środowiskow|srodowiskow)|"
    r"miejscowy plan|plan miejscowy|plan ogólny|plan ogolny|"
    r"studium uwarunkowań|studium uwarunkowan|"
    r"mpzp|oze|farma wiatrowa|elektrownia wiatrowa|fotowolta|"
    r"obwieszczenia?|zawiadomienia?|komunikaty?|ogłoszenia?|ogloszenia?|"
    r"uchwały?|uchwaly?|postanowienia?|decyzje?|"
    r"planowanie przestrzenne|zagospodarowanie przestrzenne|"
    r"ochrona środowiska|ochrona srodowiska|"
    r"biuletyn informacji publicznej|bip)\s*$",
    re.IGNORECASE
)

def is_generic_bip_page(title: str, h1: str, url: str, fast_text: str = "") -> bool:
    """
    Zwraca True dla stron-listingów kategorii BIP.
    Nie blokuje crawlowania — tylko nie raportujemy jej jako NOWE/ZMIANA strony jako całości.
    Linki NA tej stronie nadal są analizowane przez ENABLE_LINK_HITS.
    """
    t = (title or "").strip().lower()
    h = (h1 or "").strip().lower()
    txt = (fast_text or "").strip()

    if is_listing_url(url):
        return True

    if is_home_url(url) and len(txt) < 600:
        return True

    blob = re.sub(r"\s+", " ", f"{t} {h}").strip()
    if not blob:
        return False

    if len(blob) <= 90 and SITEWIDE_TITLES_RE.search(blob) and len(txt) < 300:
        return True

    check_label = (h or t or "").strip()
    if check_label and GENERIC_CATEGORY_TITLES_RE.match(check_label):
        return True

    return False

# ===================== ATT_EXT + ATTACHMENTS =====================
ATT_EXT = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".rtf",
    ".gml", ".xml", ".gpx", ".kml", ".kmz", ".geojson", ".json",
    ".shp", ".dbf", ".shx", ".prj",
    ".dwg", ".dxf",
    ".tif", ".tiff",
)

def attachments_signature(soup: BeautifulSoup, base_url: str) -> set:
    if not soup:
        return set()
    result = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        abs_u = normalize_url(urljoin(base_url, href))
        low = abs_u.lower()
        if not any(low.endswith(ext) for ext in ATT_EXT):
            continue
        p = urlparse(abs_u)
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        clean_url = urlunparse(("https", netloc, p.path, "", "", ""))
        result.add(clean_url)
    return result

def att_sig_serialize(att_set: set) -> str:
    return json.dumps(sorted(att_set), ensure_ascii=False)

def att_sig_deserialize(stored) -> set:
    if not stored:
        return set()
    if isinstance(stored, set):
        return stored
    if isinstance(stored, list):
        return set(stored)
    if isinstance(stored, str):
        try:
            data = json.loads(stored)
            if isinstance(data, list):
                return set(data)
        except Exception:
            pass
        return set()
    return set()

def cache_mark_url(u: str):
    if not USE_CACHE:
        return
    if is_phase1_listing(u):
        return
    h = url_key(u)
    state.urls_seen.add(h)
    if isinstance(state.raw_cache, dict):
        d = state.raw_cache.setdefault("urls_seen", {})
        if isinstance(d, dict):
            d[h] = now_iso()

# ===================== START URL VARIANTS =====================
def _www_variants(netloc: str):
    n = (netloc or "").strip()
    if not n:
        return []
    if n.startswith("www."):
        return [n, n[4:]]
    return [n, "www." + n]

def candidate_start_urls(start_url: str):
    u0 = (start_url or "").strip()
    if not u0:
        return
    if not re.match(r"^[a-zA-Z]+://", u0):
        u0 = "https://" + u0
    u0 = normalize_url(u0)
    p0 = urlparse(u0)
    schemes = [p0.scheme] if p0.scheme else ["https", "http"]
    if "https" not in schemes: schemes.append("https")
    if "http" not in schemes: schemes.append("http")
    hosts = _www_variants(p0.netloc.lower() if p0.netloc else "")
    base_paths = [
        p0.path or "/", "/",
        "/bip/", "/BIP/",
        "/start", "/start.html",
        "/index.php", "/index.html",
        "/asp/start", "/asp/index.php",
        "/strona-glowna", "/strona_glowna",
        "/gmina", "/gmina.html",
        "/projekty-mpzp", "/projekty_mpzp",
        "/planowanie", "/planowanie-przestrzenne",
        "/dokumenty", "/prawo-miejscowe",
    ]
    yielded = set()
    for sch in schemes:
        for host in hosts:
            base = urlunparse((sch, host, "/", "", "", ""))
            for path in base_paths:
                full = normalize_url(urljoin(base, path))
                if full not in yielded:
                    yielded.add(full)
                    yield full
                if not full.endswith("/"):
                    full2 = full + "/"
                    if full2 not in yielded:
                        yielded.add(full2)
                        yield full2
            for ax in START_AUX_HINTS:
                auxu = normalize_url(urljoin(base, ax))
                if auxu not in yielded:
                    yielded.add(auxu)
                    yield auxu

# ===================== CACHE =====================
CACHE_SCHEMA = 11  # ✅ bump — usunięto page_fprints i fp

def _empty_cache():
    return {
        "schema": CACHE_SCHEMA,
        "urls_seen": {},
        "content_seen": {},
        "gmina_seeds": {},
        "gmina_frontiers": {},
        "gmina_retry": {},
        "dead_urls": {},
    }

def load_cache_v2():
    if not USE_CACHE:
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

    if not CACHE_FILE.exists():
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            c = json.load(f) or {}

        if "schema" not in c and "found_items" in c:
            print("🔄 Legacy cache detected. Upgrading...")
            c = _empty_cache()

        if not isinstance(c.get("schema"), int):
            c["schema"] = CACHE_SCHEMA

        if c.get("schema", 0) < CACHE_SCHEMA:
            print(f"🔄 Migrating cache schema {c.get('schema')} -> {CACHE_SCHEMA}")
            c["schema"] = CACHE_SCHEMA
            c.setdefault("urls_seen", {})
            c.setdefault("content_seen", {})
            c.setdefault("gmina_seeds", {})
            c.setdefault("gmina_frontiers", {})
            c.setdefault("gmina_retry", {})
            c.setdefault("dead_urls", {})
            # usuń stare page_fprints jeśli istnieją
            c.pop("page_fprints", None)

        urls = c.get("urls_seen", {})
        if not isinstance(urls, dict):
            urls = {}
            c["urls_seen"] = urls

        content = c.get("content_seen", {})
        if not isinstance(content, dict):
            content = {}
            c["content_seen"] = content

        gseeds = c.get("gmina_seeds", {})
        if not isinstance(gseeds, dict):
            gseeds = {}
            c["gmina_seeds"] = gseeds

        gf = c.get("gmina_frontiers", {})
        if not isinstance(gf, dict):
            gf = {}
            c["gmina_frontiers"] = gf

        gr = c.get("gmina_retry", {})
        if not isinstance(gr, dict):
            gr = {}
            c["gmina_retry"] = gr

        dead = c.get("dead_urls", {})
        if not isinstance(dead, dict):
            dead = {}
            c["dead_urls"] = dead

        print(f"📦 Cache loaded: {len(urls)} URLs, {len(content)} content, {len(gseeds)} gmina seeds, {len(dead)} dead entries")
        return c, set(urls.keys()), content, gseeds, gf, gr, dead

    except Exception as e:
        print(f"⚠️  Cache load error: {e}")
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

def save_cache_v2(raw_cache, urls_seen_set, content_seen, gmina_seeds):
    out = {"schema": CACHE_SCHEMA}
    out["urls_seen"] = {}
    old_urls = (raw_cache or {}).get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    for h in urls_seen_set:
        out["urls_seen"][h] = old_urls.get(h, now_iso())
    out["content_seen"] = content_seen or {}
    out["gmina_seeds"] = gmina_seeds or {}
    out["gmina_frontiers"] = (state.gmina_frontiers or {}) if isinstance(state.gmina_frontiers, dict) else {}
    out["gmina_retry"] = (state.gmina_retry or {}) if isinstance(state.gmina_retry, dict) else {}
    out["dead_urls"] = getattr(state, 'dead_urls', {})

    tmp = str(CACHE_FILE) + ".tmp"
    def _do_save():
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CACHE_FILE)
    retry_io(_do_save, tries=6, base_sleep=0.7)
    print(f"💾 Cache saved: {len(urls_seen_set)} URLs, {len(out['content_seen'])} content, {len(out['gmina_seeds'])} seeds, {len(out['dead_urls'])} dead")

def purge_old_cache(raw_cache: dict, urls_seen_set: set, content_seen: dict, gmina_seeds: dict, dead_urls: dict):
    cutoff = datetime.now() - timedelta(days=SCANNED_TTL_DAYS)
    urls_dict = raw_cache.get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    to_del = []
    for h, ts in list(urls_dict.items()):
        try:
            if datetime.fromisoformat(ts) < cutoff:
                to_del.append(h)
        except Exception:
            to_del.append(h)
    for h in to_del:
        urls_seen_set.discard(h)
        urls_dict.pop(h, None)

    seed_cutoff = datetime.now() - timedelta(days=SEED_CACHE_TTL_DAYS)
    to_del_seeds = []
    for k, meta in list((gmina_seeds or {}).items()):
        try:
            ts = meta.get("ts", "")
            if ts and datetime.fromisoformat(ts) < seed_cutoff:
                to_del_seeds.append(k)
        except Exception:
            to_del_seeds.append(k)
    for k in to_del_seeds:
        gmina_seeds.pop(k, None)

    if to_del or to_del_seeds:
        print(f"🧹 Purged: {len(to_del)} URL, {len(to_del_seeds)} seeds")

# ===================== LOG =====================
def log_new_item(gmina: str, title: str, url: str, kw: str):
    new_file = not LOG_FILE.exists()
    with open(LOG_FILE, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["datetime_found", "gmina", "keyword", "title", "url"])
        w.writerow([now_iso(), gmina, kw, title, url])

def read_bipy_csv(path: Path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("name") or "").strip()
            url = (row.get("url") or "").strip()
            if name and url:
                if not re.match(r"^[a-zA-Z]+://", url):
                    url = "https://" + url
                rows.append((name, url))
    return rows

# ===================== DIAG =====================
def diag_new():
    return {
        "start_attempts": [],
        "start_matrix": [],
        "errors": [],
        "counts": defaultdict(int),
        "notes": [],
        "trace": {"phase":"", "last_url":"", "last_kind":"", "last_status":None, "last_ms":None},
    }

def diag_add_error(diag, gmina, url, stage, kind, status, err):
    diag["counts"][f"err_{kind}"] += 1
    if status:
        diag["counts"][f"status_{status}"] += 1
    if len(diag["errors"]) < MAX_ERROR_SAMPLES_PER_GMINA:
        diag["errors"].append({
            "gmina": gmina, "url": url, "stage": stage, "kind": kind,
            "status": status, "err": (err or "")[:260]
        })

def trace_set(diag, phase, url="", kind="", status=None, ms=None):
    diag["trace"]["phase"] = phase or diag["trace"]["phase"]
    if url: diag["trace"]["last_url"] = url
    if kind: diag["trace"]["last_kind"] = kind
    if status is not None: diag["trace"]["last_status"] = status
    if ms is not None: diag["trace"]["last_ms"] = ms

def print_start_fail_report(diag, gmina: str, start_url: str):
    print(f"\n🧩 START_FAIL REPORT: {gmina}")
    tr = diag["trace"]
    print(f"   trace: phase={tr.get('phase')} kind={tr.get('last_kind')} status={tr.get('last_status')} ms={tr.get('last_ms')}")
    if diag.get("notes"):
        print(f"   notes: {' | '.join(diag['notes'])[:900]}")
    sa = diag.get("start_attempts", [])
    print(f"   start_attempts={len(sa)} (TOP 8)")
    for i, x in enumerate(sa[:8], 1):
        print(f"   {i:02d}) kind={x.get('kind')} status={x.get('status')} ms={x.get('ms')} url={x.get('try_url')[:100]}")

# ===================== FETCH WITH RETRY =====================
async def fetch_with_retry(session: aiohttp.ClientSession, url: str, timeout: aiohttp.ClientTimeout,
                           ssl_mode, max_retries=3, method="GET"):
    url = normalize_url(url)
    domain = urlparse(url).netloc
    for attempt in range(max_retries):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            t0 = time.time()
            async with session.request(method, url, timeout=timeout, ssl=ssl_mode,
                                       allow_redirects=True, headers=headers) as resp:
                final = normalize_url(str(resp.url))
                status = resp.status
                ctype = (resp.headers.get("Content-Type", "") or "").lower()
                data = await resp.read()
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = data.decode("latin-1", errors="ignore")
                ms = round((time.time() - t0) * 1000)
                if status in (403, 429):
                    rate_limiter.report_403(domain)
                if status in (403, 429) and attempt < max_retries - 1:
                    await asyncio.sleep((2 ** attempt) * random.uniform(0.5, 1.0))
                    continue
                if status >= 500 and attempt < max_retries - 1:
                    await asyncio.sleep((2 ** attempt) * random.uniform(0.3, 0.7))
                    continue
                return final, status, ctype, text, ms
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            raise
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.3 * (attempt + 1))
                continue
            raise
    return url, None, "", "", None

async def _aio_fetch_raw(session, url, timeout, ssl_mode, method="GET"):
    return await fetch_with_retry(session, url, timeout, ssl_mode, max_retries=3, method=method)

async def _probe_with_requests(url: str, timeout_sec: float, verify: bool):
    def run():
        t0 = time.time()
        headers = get_random_headers()
        try:
            r = requests.get(url, timeout=timeout_sec, verify=verify, headers=headers, allow_redirects=True)
            ms = round((time.time() - t0) * 1000)
            return str(r.url), r.status_code, r.headers.get("Content-Type",""), (r.text or "")[:20000], ms
        except Exception:
            ms = round((time.time() - t0) * 1000)
            return url, None, "", "", ms
    return await asyncio.to_thread(run)

async def fetch_start_matrix(session_default, session_ipv4, url, diag):
    url = normalize_url(url)
    def looks_html(ctype: str, text: str) -> bool:
        low = (text or "").lower()
        return ("html" in (ctype or "").lower()) or ("<html" in low[:2000]) or ("<!doctype" in low[:2000]) or ("<body" in low[:2000])
    STRATEGIES = []
    for timeout, tname in ((START_TIMEOUT_FAST, "FAST"),):
        STRATEGIES.append(("aio_default", tname, "ssl=off", "GET", timeout, False))
        STRATEGIES.append(("aio_ipv4", tname, "ssl=off", "GET", timeout, False))
    for timeout, tname in ((START_TIMEOUT_FAST, "FAST"), (START_TIMEOUT_LONG, "LONG")):
        for ssl_mode, sname in ((None, "ssl=verify"), (False, "ssl=off")):
            for method in ("GET", "HEAD"):
                STRATEGIES.append(("aio_default", tname, sname, method, timeout, ssl_mode))
                STRATEGIES.append(("aio_ipv4", tname, sname, method, timeout, ssl_mode))
    STRATEGIES.append(("requests", "FAST", "verify=False", "GET", 18.0, False))
    STRATEGIES.append(("requests", "LONG", "verify=False", "GET", 40.0, False))
    last_fail = None
    for family, tname, sname, method, to, sslmode in STRATEGIES:
        strategy_name = f"{family}:{tname}:{sname}:{method}"
        try:
            if family == "aio_default":
                final, status, ctype, text, ms = await _aio_fetch_raw(session_default, url, to, sslmode, method=method)
            elif family == "aio_ipv4":
                final, status, ctype, text, ms = await _aio_fetch_raw(session_ipv4, url, to, sslmode, method=method)
            elif family == "requests":
                res = await _probe_with_requests(url, timeout_sec=to, verify=sslmode)
                if not res:
                    final, status, ctype, text, ms = url, None, "", "", None
                else:
                    try:
                        final, status, ctype, text, ms = res
                    except Exception:
                        final, status, ctype, text, ms = url, None, "", "", None
            else:
                continue
            lu = url.lower()
            if any(ax in lu for ax in ("/robots.txt", "sitemap")):
                ok = (status is not None) and (200 <= int(status) < 400) and bool(text)
                diag["start_matrix"].append({"ok": ok, "strategy": strategy_name, "url": url, "status": status, "kind": ("aux_ok" if ok else "aux_fail")})
                continue
            if status is None or int(status) != 200:
                diag["start_matrix"].append({"ok": False, "strategy": strategy_name, "url": url, "status": status, "kind": "http_err"})
                last_fail = (None, final, "http_err", status, ctype, f"HTTP {status}", ms)
                continue
            if looks_html(ctype, text) and text:
                diag["start_matrix"].append({"ok": True, "strategy": strategy_name, "url": url, "status": status, "kind": "html"})
                return text, final, "html", status, ctype, None, ms
            diag["start_matrix"].append({"ok": False, "strategy": strategy_name, "url": url, "status": status, "kind": "non_html"})
            last_fail = (None, final, "non_html", status, ctype, "start_non_html", ms)
        except Exception as e:
            msg = str(e)
            kind = "exc"
            if "ssl" in msg.lower() or "certificate" in msg.lower():
                kind = "ssl"
            diag["start_matrix"].append({"ok": False, "strategy": strategy_name, "url": url, "status": None, "kind": kind})
            last_fail = (None, url, kind, None, "", msg, None)
    return last_fail if last_fail else (None, url, "fail", None, "", "no_strategy_worked", None)

# ===================== NORMAL FETCH =====================
async def fetch(session: aiohttp.ClientSession, url: str, extra_headers: dict = None):
    url = normalize_url(url)
    domain = urlparse(url).netloc
    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            if extra_headers:
                headers.update(extra_headers)
            t0 = time.time()
            async with session.get(url, timeout=REQUEST_TIMEOUT, ssl=ssl_mode, allow_redirects=True, headers=headers) as resp:
                final = normalize_url(str(resp.url))
                status = resp.status
                ctype = (resp.headers.get("Content-Type", "") or "").lower()
                data = await resp.read()
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = data.decode("latin-1", errors="ignore")
                ms = round((time.time() - t0) * 1000)
                if status in (403, 429):
                    rate_limiter.report_403(domain)
                if status == 200 and is_block_page(text):
                    rate_limiter.report_403(domain)
                    return None, final, "blocked", 429, ctype, "block_page_detected", ms
                if "pdf" in ctype or final.lower().endswith(".pdf"):
                    return None, final, "pdf", status, ctype, None, ms
                if status != 200:
                    if ssl_mode is None:
                        return None, final, "http_err", status, ctype, f"HTTP {status}", ms
                    continue
                if text and len(text) > 800 and re.search(r"<[^>]+>", text[:2500]) is None:
                    return None, final, "non_html", status, ctype, None, ms
                return text, final, "html", status, ctype, None, ms
        except asyncio.TimeoutError:
            if ssl_mode is None:
                return None, url, "timeout", None, "", "request_timeout", 0
            continue
        except Exception as e:
            if ssl_mode is None:
                return None, url, "exc", None, "", str(e), 0
            continue
    return None, url, "exc", None, "", "fetch_failed", 0

# ===================== PAGINATION GUARD =====================
PAGINATION_KEYS = {"page","strona","p","start","offset","from","limit","per_page"}

def pagination_pattern(url: str) -> str:
    try:
        p = urlparse(url)
        qs = parse_qsl(p.query, keep_blank_values=True)
        kept = []
        for k, v in qs:
            kl = (k or "").lower().strip()
            if kl in PAGINATION_KEYS:
                kept.append((kl, ""))
            else:
                kept.append((kl, v))
        kept.sort()
        return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(kept, doseq=True)}"
    except Exception:
        return url

# ===================== SEED CACHE =====================
def gmina_cache_key(gmina: str, start_url: str) -> str:
    host = urlparse(normalize_url(start_url)).netloc.lower()
    return sha1(f"{gmina.strip().lower()}|{base_domain(host)}")

def seed_cache_get(gmina: str, start_url: str):
    k = gmina_cache_key(gmina, start_url)
    meta = state.gmina_seeds.get(k)
    if not meta:
        return None
    try:
        ts = meta.get("ts")
        if ts and datetime.fromisoformat(ts) < (datetime.now() - timedelta(days=SEED_CACHE_TTL_DAYS)):
            return None
    except Exception:
        return None
    return meta

def seed_cache_put(gmina: str, start_url: str, allowed_host: str, start_final: str, seeds: list):
    k = gmina_cache_key(gmina, start_url)
    state.gmina_seeds[k] = {
        "allowed_host": allowed_host,
        "start_final": start_final,
        "seeds": seeds,
        "ts": now_iso()
    }

# ===================== LINK EXTRACTION =====================
def iter_links_fast(soup: BeautifulSoup, base_url: str):
    """
    Iteruje po wszystkich linkach na stronie.
    Zwraca (abs_url, anchor_text) dla każdego linka który nie jest odfiltrowany.
    NIE filtrujemy po anchor_is_ignored tutaj dla linków do podstron HTML —
    to robi phase2 tylko dla crawlowania, nie dla keyword match.
    """
    yielded = set()
    all_links = []
    try:
        all_links = soup.find_all("a", href=True)
    except Exception:
        all_links = []

    for a in all_links:
        try:
            href = (a.get("href") or "").strip()
            if not href:
                continue
            abs_u = normalize_url(urljoin(base_url, href))
            if not is_valid_url(abs_u):
                continue
            txt = a.get_text(" ", strip=True)
            is_attachment = any(abs_u.lower().endswith(ext) for ext in ATT_EXT)
            if should_skip_href(abs_u) and not is_attachment:
                continue
            if abs_u in yielded:
                continue
            yielded.add(abs_u)
            yield abs_u, txt
        except Exception:
            continue

# ===================== PHASE 1 =====================
async def phase1_discover(gmina: str, start_url: str,
                         session_default, session_ipv4, session_crawl,
                         urls_seen: set, diag):
    if state.shutdown_requested:
        return [], {"status": "SHUTDOWN"}

    cached = seed_cache_get(gmina, start_url)
    if (not FORCE_PHASE1_REDISCOVERY) and cached and (not CRAWL_ALL_INTERNAL_LINKS):
        diag["notes"].append("PHASE1_SKIP: seed_cache_hit")
        return cached.get("seeds", []) or [], {
            "status": "OK",
            "allowed_host": cached.get("allowed_host", ""),
            "start_final": cached.get("start_final", ""),
            "seeds": len(cached.get("seeds", []) or [])
        }

    seeds = {}
    visited = set()
    q = deque()
    html0 = final0 = None
    kind0 = "fail"
    status0 = None
    allowed_host = ""

    trace_set(diag, "PHASE1_START", url=start_url)
    tried = 0
    start_time = time.time()

    for su in candidate_start_urls(start_url):
        if (time.time() - start_time) > START_TOTAL_TIMEOUT_SEC:
            diag["notes"].append(f"START_TIMEOUT after {int(time.time()-start_time)}s")
            break
        if state.shutdown_requested:
            break
        tried += 1
        if tried > START_MAX_TRIES:
            break
        html0, final0, kind0, status0, ctype0, err0, ms = await fetch_start_matrix(session_default, session_ipv4, su, diag)
        diag["start_attempts"].append({"try_url": su, "kind": kind0, "status": status0, "final": (final0 or "")[:220], "ms": ms})
        trace_set(diag, "PHASE1_START", url=su, kind=kind0, status=status0, ms=ms)
        if len(diag["start_attempts"]) >= 8:
            recent = diag["start_attempts"][-8:]
            if all(x.get("status") == 403 for x in recent):
                diag["notes"].append("EARLY_EXIT: 8/8 = 403 (WAF)")
                break
            if all(x.get("kind") == "ssl" for x in recent):
                diag["notes"].append("EARLY_EXIT: 8/8 = SSL (cert invalid)")
                break
        if kind0 == "html" and html0:
            allowed_host = urlparse(final0).netloc.lower()
            okm = [m for m in diag["start_matrix"] if m.get("ok")]
            if okm:
                diag["notes"].append(f"START_OK strategy={okm[-1].get('strategy')}")
            try:
                if detect_js_app(html0):
                    diag["notes"].append("JS_HEAVY_DETECTED")
                    diag["counts"]["js_heavy_detected"] += 1
                    try:
                        base_site = urlunparse((urlparse(final0).scheme, urlparse(final0).netloc, "/", "", "", ""))
                        for pth in JS_EXTRA_SEED_PATHS:
                            u2 = normalize_url(urljoin(base_site, pth))
                            if same_base_domain(urlparse(u2).netloc.lower(), allowed_host):
                                seeds[u2] = max(seeds.get(u2, 0), 16)
                    except Exception:
                        pass
            except Exception:
                pass
            break

    if kind0 != "html" or not html0:
        diag["notes"].append(f"START_FAIL tried={tried}")
        diag_add_error(diag, gmina, start_url, "phase1_start", kind0, status0, "no_html_start")
        return [], {"status": "START_FAIL"}

    def allow_url(u: str) -> bool:
        return same_base_domain(urlparse(u).netloc.lower(), allowed_host)

    try:
        base_site = urlunparse((urlparse(final0).scheme, urlparse(final0).netloc, "/", "", "", ""))
        sitemap_urls = await collect_sitemap_urls(session_crawl, base_site, diag, max_urls=4000)
        added_sm = 0
        for u in sitemap_urls:
            if not allow_url(u):
                continue
            if should_skip_href(u):
                continue
            score = 10
            ul = (u or "").lower()
            if any(h in ul for h in LISTING_URL_HINTS):
                score = 18
            if u not in seeds or score > seeds.get(u, 0):
                seeds[u] = score
                added_sm += 1
        if added_sm:
            diag["counts"]["seeds_from_sitemap_added"] += added_sm
            diag["notes"].append(f"SITEMAP_SEEDS_ADDED={added_sm}")
    except Exception:
        diag["counts"]["sitemap_block_exc"] += 1
        diag["notes"].append("SITEMAP_BLOCK_FAILED")

    q.append(final0)
    visited.add(final0)
    pages = 0
    trace_set(diag, "PHASE1_DISCOVERY", url=final0)

    while q and pages < PHASE1_MAX_PAGES and not state.shutdown_requested:
        url = normalize_url(q.popleft())
        html, final, kind, status, ctype, err, ms = await fetch(session_crawl, url)
        trace_set(diag, "PHASE1_DISCOVERY", url=url, kind=kind, status=status, ms=ms)
        if kind != "html" or not html:
            diag_add_error(diag, gmina, url, "phase1_fetch", kind, status, err)
            continue
        pages += 1
        diag["counts"]["phase1_pages_ok"] += 1
        if USE_CACHE:
            cache_mark_url(url)
            cache_mark_url(final)
        soup = safe_soup(html)
        if not soup:
            continue
        for abs_u, txt in iter_links_fast(soup, final):
            if not allow_url(abs_u):
                continue
            if CRAWL_ALL_INTERNAL_LINKS:
                low_u = abs_u.lower()
                if any(low_u.endswith(ext) for ext in ATT_EXT):
                    continue
                if anchor_is_ignored(txt):
                    continue
                seeds.setdefault(abs_u, 1)
                if abs_u not in visited:
                    visited.add(abs_u)
                    q.append(abs_u)

    seed_urls = list(seeds.keys())[:PHASE1_MAX_SEEDS]
    seed_cache_put(gmina, start_url, allowed_host, final0, seed_urls)
    return seed_urls, {"status": "OK", "allowed_host": allowed_host, "start_final": final0, "seeds": len(seed_urls)}

# ===================== FETCH CONDITIONAL =====================
async def fetch_conditional(session: aiohttp.ClientSession, url: str, extra_headers: dict = None):
    url = normalize_url(url)
    domain = urlparse(url).netloc
    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            if extra_headers:
                headers.update(extra_headers)
            t0 = time.time()
            async with session.get(url, timeout=REQUEST_TIMEOUT, ssl=ssl_mode, allow_redirects=True, headers=headers) as resp:
                final = normalize_url(str(resp.url))
                status = resp.status
                ctype = (resp.headers.get("Content-Type", "") or "").lower()
                etag = resp.headers.get("ETag", "") or resp.headers.get("Etag", "") or ""
                last_mod = resp.headers.get("Last-Modified", "") or resp.headers.get("last-modified", "") or ""
                resp_meta = {"etag": etag, "last_modified": last_mod}
                if status == 304:
                    ms = round((time.time() - t0) * 1000)
                    return None, final, "not_modified", status, ctype, None, ms, resp_meta
                data = await resp.read()
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = data.decode("latin-1", errors="ignore")
                ms = round((time.time() - t0) * 1000)
                if status in (403, 429):
                    rate_limiter.report_403(domain)
                if status == 200 and is_block_page(text):
                    rate_limiter.report_403(domain)
                    return None, final, "blocked", 429, ctype, "block_page_detected", ms, resp_meta
                if "pdf" in ctype or final.lower().endswith(".pdf"):
                    return None, final, "pdf", status, ctype, None, ms, resp_meta
                if status != 200:
                    if ssl_mode is None:
                        return None, final, "http_err", status, ctype, f"HTTP {status}", ms, resp_meta
                    continue
                if text and len(text) > 800 and re.search(r"<[^>]+>", text[:2500]) is None:
                    return None, final, "non_html", status, ctype, None, ms, resp_meta
                return text, final, "html", status, ctype, None, ms, resp_meta
        except asyncio.TimeoutError:
            if ssl_mode is None:
                return None, url, "timeout", None, "", "request_timeout", 0, {}
            continue
        except Exception as e:
            if ssl_mode is None:
                return None, url, "exc", None, "", str(e), 0, {}
            continue
    return None, url, "exc", None, "", "fetch_failed", 0, {}

# ===================== PHASE 2 =====================
async def phase2_focus(gmina: str, seed_urls, session_crawl, allowed_host: str,
                      urls_seen: set, content_seen: dict, diag):

    if state.shutdown_requested:
        return [], {"status": "SHUTDOWN"}

    found = []
    visited = set()
    q = deque()

    gkey = gmina_cache_key(gmina, "https://" + allowed_host)
    dead_key = f"dead_{gkey}"
    dead_set = set(state.dead_urls.get(dead_key, []) or [])

    retry_seen = set()
    existing_retry = (state.gmina_retry or {}).get(gkey, []) or []
    for u in existing_retry:
        retry_seen.add(sha1(_canon(u)))

    # frontier z poprzedniego runu
    saved_frontier = (state.gmina_frontiers or {}).get(gkey, []) or []
    if saved_frontier:
        print(f"  ↩️  Kontynuacja: {len(saved_frontier)} URL z poprzedniego runu ({gmina})", flush=True)
        for item in saved_frontier:
            try:
                fu, fd = item[0], int(item[1])
            except Exception:
                continue
            cu = _canon(fu)
            if cu and cu not in visited and cu not in dead_set:
                visited.add(cu)
                q.append((cu, fd))
        state.gmina_frontiers.pop(gkey, None)

    # retry
    retry_list = (state.gmina_retry or {}).get(gkey, []) or []
    retry_added = 0
    for u in retry_list[:200]:
        cu = _canon(u)
        if cu and cu not in visited and cu not in dead_set:
            visited.add(cu)
            q.appendleft((cu, 0))
            retry_added += 1
    if retry_added:
        print(f"  🔁 Retry: {retry_added} URL ({gmina})", flush=True)
    if isinstance(state.gmina_retry, dict):
        state.gmina_retry[gkey] = []

    # seeds
    if not saved_frontier:
        for su in seed_urls:
            cu = _canon(su)
            if cu and cu not in visited and cu not in dead_set:
                visited.add(cu)
                q.append((cu, 0))

    def allow_url(u: str) -> bool:
        return same_base_domain(urlparse(u).netloc.lower(), allowed_host)

    pages_ok = 0

    while q and not state.shutdown_requested:

        url, depth = q.popleft()
        if depth > PHASE2_MAX_DEPTH:
            continue

        url = _canon(url)
        if not url:
            continue

        url_hash = url_key(url)
        is_listing = is_listing_url(url) or is_home_url(url)
        url_dedup = sha1(canonical_url(url))
        prev_pre = content_seen.get(url_dedup)

        # TTL logic
        if USE_CACHE and prev_pre and not is_listing:
            status_prev = prev_pre.get("status")
            if status_prev in {"NOWE", "ZMIANA", "HIT"}:
                if not should_recheck_hit(prev_pre):
                    diag["counts"]["hit_ttl_skip"] += 1
                    continue
            elif status_prev == "NO_MATCH":
                if not should_recheck_no_match(prev_pre):
                    diag["counts"]["no_match_ttl_skip"] += 1
                    continue
            elif status_prev == "BLOCKED":
                if not should_recheck_block(prev_pre, BLOCKED_RECHECK_TTL_MIN):
                    diag["counts"]["blocked_ttl_skip"] += 1
                    continue
            elif status_prev == "FAILED":
                if not should_recheck_block(prev_pre, FAILED_RECHECK_TTL_MIN):
                    diag["counts"]["failed_ttl_skip"] += 1
                    continue

        extra_headers = {}
        if prev_pre and prev_pre.get("etag"):
            extra_headers["If-None-Match"] = prev_pre.get("etag")
        if prev_pre and prev_pre.get("last_modified"):
            extra_headers["If-Modified-Since"] = prev_pre.get("last_modified")

        html, final, kind, status, ctype, err, ms, resp_meta = await fetch_conditional(
            session_crawl, url, extra_headers
        )

        final_c = _canon(final or url)
        url_dedup_final = sha1(canonical_url(final_c))
        prev = content_seen.get(url_dedup_final) or prev_pre

        if final_c and final_c != url:
            diag["counts"]["redirected"] += 1

        # 304
        if kind == "not_modified":
            async with state.cache_lock:
                if url_dedup_final in content_seen:
                    content_seen[url_dedup_final]["last_checked"] = now_iso()
                    content_seen[url_dedup_final]["status"] = "HIT"
                if ALIAS_FINAL_AND_SOURCE_KEYS and (url_dedup != url_dedup_final):
                    if url_dedup in content_seen:
                        content_seen[url_dedup]["last_checked"] = now_iso()
                        content_seen[url_dedup]["status"] = "HIT"
                    else:
                        content_seen[url_dedup] = content_seen.get(url_dedup_final, {}).copy()
            continue

        # BLOCKED
        if kind == "blocked":
            diag["counts"]["blocked_13"] += 1
            async with state.cache_lock:
                prevb = content_seen.get(url_dedup_final) or prev_pre
                content_seen[url_dedup_final] = {
                    "found_at": (prevb.get("found_at") if prevb else now_iso()),
                    "last_checked": now_iso(),
                    "etag": "", "last_modified": "",
                    "gmina": gmina,
                    "title": (prevb.get("title") if prevb else ""),
                    "url": final_c,
                    "keywords": (prevb.get("keywords") if prevb else []),
                    "att_sig": (prevb.get("att_sig") if prevb else ""),
                    "status": "BLOCKED",
                }
                if ALIAS_FINAL_AND_SOURCE_KEYS and (url_dedup != url_dedup_final):
                    content_seen[url_dedup] = content_seen[url_dedup_final]
            retry_add(gkey, retry_seen, final_c)
            urls_seen.discard(url_hash)
            continue

        # FAILED
        if kind != "html" or not html:
            if status in (404, 410):
                dead_add(dead_key, dead_set, final_c)
                continue
            if status in (403, 429) or kind in {"timeout", "exc"} or (status and int(status) >= 500):
                async with state.cache_lock:
                    prevf = content_seen.get(url_dedup_final) or prev_pre
                    content_seen[url_dedup_final] = {
                        "found_at": (prevf.get("found_at") if prevf else now_iso()),
                        "last_checked": now_iso(),
                        "etag": "", "last_modified": "",
                        "gmina": gmina,
                        "title": (prevf.get("title") if prevf else ""),
                        "url": final_c,
                        "keywords": (prevf.get("keywords") if prevf else []),
                        "att_sig": (prevf.get("att_sig") if prevf else ""),
                        "status": "FAILED",
                    }
                    if ALIAS_FINAL_AND_SOURCE_KEYS and (url_dedup != url_dedup_final):
                        content_seen[url_dedup] = content_seen[url_dedup_final]
                retry_add(gkey, retry_seen, final_c)
                urls_seen.discard(url_hash)
            continue

        # ================= HTML =================
        pages_ok += 1
        soup = safe_soup(html)
        if not soup:
            continue

        title, h1, h2, meta_blob = extract_title_h1_h2(soup)

        # ✅ att_set PRZED _soup_fast_text (bo fast_text robi decompose na script/style)
        att_set = attachments_signature(soup, final_c)

        # ✅ CAŁY tekst strony — bez żadnego filtrowania poza script/style
        fast_text = _soup_fast_text(soup)

        # ✅ blob = wszystko: tytuł + nagłówki + CAŁY tekst strony
        blob = f"{title} {h1} {h2} {fast_text}"
        ok_any, kw_any = keyword_match_in_blob(blob)

        # ================= STATUS LOGIC =================
        # Nie raportujemy samej strony listingowej jako NOWE/ZMIANA —
        # ale jej linki analizujemy przez ENABLE_LINK_HITS poniżej.
        is_generic = is_generic_bip_page(title, h1, final_c, fast_text)

        if is_generic:
            # Strona-listing: nie raportuj jej samej, ale crawluj dalej
            status_new = "NO_MATCH"
        elif prev is None:
            status_new = "NOWE" if ok_any else "NO_MATCH"
        else:
            status_new = "HIT" if ok_any else "NO_MATCH"
            prev_att_set = att_sig_deserialize(prev.get("att_sig") or "")
            added_files = att_set - prev_att_set
            if added_files and ok_any:
                status_new = "ZMIANA"
                diag["counts"]["att_added"] += len(added_files)

        page_title = (h1 or h2 or title or "").strip()
        if not page_title:
            page_title = final_c

        meta = {
            "found_at": (prev.get("found_at") if prev else now_iso()),
            "last_checked": now_iso(),
            "etag": (resp_meta.get("etag") if resp_meta else ""),
            "last_modified": (resp_meta.get("last_modified") if resp_meta else ""),
            "gmina": gmina,
            "title": page_title[:240],
            "url": final_c,
            "keywords": [kw_any] if ok_any else [],
            "att_sig": att_sig_serialize(att_set),
            "status": status_new,
        }

        async with state.cache_lock:
            content_seen[url_dedup_final] = meta
            if ALIAS_FINAL_AND_SOURCE_KEYS and (url_dedup != url_dedup_final):
                content_seen[url_dedup] = meta

        if status_new in {"NOWE", "ZMIANA"}:
            print_hit(f"🟢 {status_new}", gmina, kw_any, page_title)
            found.append((gmina, kw_any, page_title, final_c, status_new))

        # ================= LINK HITS =================
        # ✅ Analizuj KAŻDY link na stronie (w tym na listingach kategorii).
        # Jeśli anchor text linka zawiera keyword → zapisz URL linka jako NOWE.
        # To łapie ogłoszenia typu:
        #   "Plan ogólny Gminy X - Projekt" → link do document_id=2259580
        #   "Decyzja środowiskowa dla farmy wiatrowej" → link do document_id=...
        for abs_u, txt in iter_links_fast(soup, final_c):
            cu = _canon(abs_u)
            if not cu or not allow_url(cu):
                continue
            if cu in dead_set:
                continue

            # Matchuj keyword w anchor text + nazwie pliku
            filename = urlparse(cu).path.split("/")[-1]
            # ✅ Użyj SAMEGO anchor textu do matchowania (nie crawlowanej treści)
            blob_link = f"{txt} {filename}"
            ok_link, kw_link = keyword_match_in_blob(blob_link)

            if ENABLE_LINK_HITS and ok_link and txt:
                link_title = txt.strip()

                # Filtruj generyczne etykiety nawigacyjne
                lt = link_title.lower()
                skip_generic = (
                    "biuletyn informacji publicznej" in lt
                    or lt == "bip"
                    or (len(lt) <= 6 and "bip" in lt)
                    or anchor_is_ignored(lt)
                )

                if not skip_generic:
                    key = sha1(canonical_url(cu))
                    prev_link = content_seen.get(key)

                    if prev_link is None:
                        # Pierwszy raz widzimy ten link z keywordem — NOWE
                        async with state.cache_lock:
                            content_seen[key] = {
                                "found_at": now_iso(),
                                "last_checked": now_iso(),
                                "etag": "",
                                "last_modified": "",
                                "gmina": gmina,
                                "title": link_title[:240],
                                "url": cu,
                                "keywords": [kw_link],
                                "att_sig": "",
                                "status": "NOWE",
                            }
                        print_hit("🟢 NOWE (LINK)", gmina, kw_link, link_title)
                        found.append((gmina, kw_link, link_title, cu, "NOWE"))
                        diag["counts"]["link_hits_new"] += 1
                    # jeśli prev_link istnieje — już widzieliśmy, nie duplikuj

            # Dodaj do kolejki crawlowania (niezależnie od keyword match)
            if cu not in visited and cu not in dead_set:
                visited.add(cu)
                q.append((cu, depth + 1))

    # Zapisz frontier
    if q:
        state.gmina_frontiers[gkey] = [[url, depth] for url, depth in list(q)]
    else:
        state.gmina_frontiers.pop(gkey, None)

    return found, {
        "status": "OK",
        "pages_ok": pages_ok,
        "stop_reason": ("SHUTDOWN" if state.shutdown_requested else "QUEUE_EMPTY"),
        "frontier_len": len(q),
        "retry_len": len((state.gmina_retry or {}).get(gkey, []) or []),
    }

# ===================== DIAG SAVE + SUMMARY =====================
def save_diag(diag_rows, diag_errors):
    try:
        def _do():
            new_file = not DIAG_GMINY_CSV.exists()
            with open(DIAG_GMINY_CSV, "a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                if new_file:
                    w.writerow(["datetime", "gmina", "start_url", "status", "phase1_seeds", "phase2_pages_ok", "notes", "counts_json"])
                for r in (diag_rows or []):
                    w.writerow([
                        r.get("datetime"), r.get("gmina"), r.get("start_url"), r.get("status"),
                        r.get("phase1_seeds"), r.get("phase2_pages_ok"),
                        " | ".join(r.get("notes", []) or [])[:900],
                        json.dumps(r.get("counts", {}), ensure_ascii=False)[:5000],
                    ])
            new_file2 = not DIAG_ERRORS_CSV.exists()
            with open(DIAG_ERRORS_CSV, "a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                if new_file2:
                    w.writerow(["datetime", "gmina", "stage", "kind", "status", "url", "err"])
                for e in (diag_errors or []):
                    w.writerow([
                        now_iso(), e.get("gmina"), e.get("stage"), e.get("kind"),
                        e.get("status"), (e.get("url") or "")[:400], (e.get("err") or "")[:300],
                    ])
        retry_io(_do, tries=6, base_sleep=0.7)
    except Exception as ex:
        print(f"⚠️ save_diag failed: {ex}")

def write_summary(diag_rows, new_items_for_mail):
    try:
        total = len(diag_rows or [])
        ok = sum(1 for r in (diag_rows or []) if r.get("status") == "OK")
        start_fail = sum(1 for r in (diag_rows or []) if r.get("status") == "START_FAIL")
        lines = []
        lines.append(f"BIP WATCHER SUMMARY @ {now_iso()}")
        lines.append(f"gminy_total={total} ok={ok} start_fail={start_fail}")
        lines.append(f"mail_items={len(new_items_for_mail or [])}")
        lines.append("")
        lines.append("TOP 500 mail items:")
        for x in (new_items_for_mail or [])[:500]:
            lines.append("- " + re.sub(r"\s+", " ", x).strip())
        def _do():
            with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        retry_io(_do, tries=6, base_sleep=0.7)
        print(f"🧾 Summary saved: {SUMMARY_FILE}")
    except Exception as ex:
        print(f"⚠️ write_summary failed: {ex}")

# ===================== WORKER =====================
async def worker(name: str, queue: asyncio.Queue,
                 session_default, session_ipv4, session_crawl,
                 urls_seen: set, content_seen: dict, checkpoint_counter: dict):
    while True:
        got_item = False
        gmina = start_url = None
        diag = diag_new()
        try:
            gmina, start_url = await queue.get()
            got_item = True
            if RUN_DEADLINE_MIN > 0 and (time.time() - GLOBAL_T0) > (RUN_DEADLINE_MIN * 60):
                state.request_shutdown()
            if state.shutdown_requested:
                try:
                    await queue.put((gmina, start_url))
                except Exception:
                    pass
                return
            if ONLY_GMINA and ONLY_GMINA.strip().lower() != (gmina or "").strip().lower():
                return

            print(f"\n🔎 [{name}] START: {gmina} -> {start_url}", flush=True)
            seed_urls, p1meta = await phase1_discover(
                gmina=gmina, start_url=start_url,
                session_default=session_default, session_ipv4=session_ipv4,
                session_crawl=session_crawl, urls_seen=urls_seen, diag=diag
            )
            if (p1meta or {}).get("status") != "OK":
                print_start_fail_report(diag, gmina, start_url)
                state.diag_rows.append({
                    "datetime": now_iso(), "gmina": gmina, "start_url": start_url,
                    "status": "START_FAIL",
                    "phase1_seeds": int((p1meta or {}).get("seeds", 0) or 0),
                    "phase2_pages_ok": 0,
                    "notes": (diag.get("notes", []) or []),
                    "counts": dict(diag.get("counts", {})),
                })
                for e in diag.get("errors", []):
                    state.diag_errors.append(e)
                print(f"✅ [{name}] DONE: {gmina} (found 0)", flush=True)
                continue

            allowed_host = (p1meta or {}).get("allowed_host", "")
            found, p2meta = await phase2_focus(
                gmina=gmina, seed_urls=seed_urls, session_crawl=session_crawl,
                allowed_host=allowed_host, urls_seen=urls_seen,
                content_seen=content_seen, diag=diag
            )

            stop_reason = ((p2meta or {}).get("stop_reason") or "")
            frontier_len = int((p2meta or {}).get("frontier_len", 0) or 0)
            retry_len = int((p2meta or {}).get("retry_len", 0) or 0)
            status = "OK" if (not stop_reason or stop_reason == "QUEUE_EMPTY") else "INCOMPLETE"

            state.diag_rows.append({
                "datetime": now_iso(), "gmina": gmina, "start_url": start_url,
                "status": status,
                "phase1_seeds": int((p1meta or {}).get("seeds", 0) or 0),
                "phase2_pages_ok": int((p2meta or {}).get("pages_ok", 0) or 0),
                "notes": (diag.get("notes", []) or []) + [
                    f"stop_reason={stop_reason}",
                    f"frontier_len={frontier_len}",
                    f"retry_len={retry_len}",
                ],
                "counts": dict(diag.get("counts", {})),
            })
            for e in diag.get("errors", []):
                state.diag_errors.append(e)

            checkpoint_counter["done"] = int(checkpoint_counter.get("done", 0) or 0) + 1
            if USE_CACHE and (checkpoint_counter["done"] % CACHE_CHECKPOINT_EVERY_N_GMINY == 0):
                try:
                    if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                        await save_shard_cache_and_commit(asyncio.get_event_loop())
                    else:
                        save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
                        purge_old_cache(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.dead_urls)
                except Exception as ex:
                    print(f"⚠️ checkpoint save failed: {ex}", flush=True)

            print(f"✅ [{name}] DONE: {gmina} (found {len(found)}, frontier={frontier_len}, retry={retry_len})", flush=True)
            if frontier_len == 0 and retry_len == 0:
                print(f"   ✅ Gmina {gmina} – pełne przeskanowanie")

        except asyncio.CancelledError:
            return
        except Exception as e:
            print(f"❌ [{name}] ERROR: {gmina} -> {e}", flush=True)
            try:
                diag_add_error(diag, gmina or "", start_url or "", "worker", "exc", None, str(e))
                for er in diag.get("errors", []):
                    state.diag_errors.append(er)
            except Exception:
                pass
            try:
                state.diag_rows.append({
                    "datetime": now_iso(), "gmina": gmina or "", "start_url": start_url or "",
                    "status": "WORKER_ERROR", "phase1_seeds": 0, "phase2_pages_ok": 0,
                    "notes": (diag.get("notes", []) or []) + [f"worker_exc={str(e)[:160]}"],
                    "counts": dict(diag.get("counts", {})),
                })
            except Exception:
                pass
            if gmina and start_url:
                try:
                    await queue.put((gmina, start_url))
                except Exception:
                    pass
        finally:
            if got_item:
                if USE_CACHE and os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                    await save_shard_cache_and_commit(asyncio.get_event_loop())
                queue.task_done()

# ===================== MAIN =====================
async def main():
    if os.getenv("RESET_CACHE", "0").strip() == "1":
        print("🗑️  RESET_CACHE=1 — czyszczę cache...")
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            print(f"   ✅ Usunięto: {CACHE_FILE}")
        for shard_file in BASE_DIR.glob("cache_shard_*.json"):
            shard_file.unlink()
            print(f"   ✅ Usunięto: {shard_file}")
        print("   ✅ Cache wyczyszczony.")
        print()

    # ✅ load_cache_v2 zwraca 7 wartości (usunięto page_fprints)
    (state.raw_cache, state.urls_seen, state.content_seen,
     state.gmina_seeds, state.gmina_frontiers,
     state.gmina_retry, state.dead_urls) = load_cache_v2()

    migrate_content_seen_to_url_dedup(state.content_seen)
    purge_old_cache(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.dead_urls)

    if not CSV_FILE.exists():
        print(f"❌ Brak pliku CSV: {CSV_FILE}")
        return
    rows = read_bipy_csv(CSV_FILE)
    if not rows:
        print("❌ CSV pusty / brak poprawnych rekordów.")
        return

    shard_total = int(os.getenv("SHARD_TOTAL", "1"))
    shard_index = int(os.getenv("SHARD_INDEX", "0"))
    rows_all = rows
    rows = pick_rows_for_shard(rows_all, shard_index, shard_total)
    print(f"🧩 SHARD {shard_index}/{shard_total} -> {len(rows)}/{len(rows_all)} gmin", flush=True)
    if not rows:
        print("ℹ️ Brak gmin w tym shardzie.")
        return

    conn_default = aiohttp.TCPConnector(limit=CONCURRENT_REQUESTS, limit_per_host=LIMIT_PER_HOST, ttl_dns_cache=600, enable_cleanup_closed=True, ssl=False)
    conn_ipv4 = aiohttp.TCPConnector(family=socket.AF_INET, limit=CONCURRENT_REQUESTS, limit_per_host=LIMIT_PER_HOST, ttl_dns_cache=600, enable_cleanup_closed=True, ssl=False)
    conn_crawl = aiohttp.TCPConnector(limit=CONCURRENT_REQUESTS, limit_per_host=LIMIT_PER_HOST, ttl_dns_cache=600, enable_cleanup_closed=True, ssl=False)
    timeout_quick = aiohttp.ClientTimeout(total=None, sock_connect=12, sock_read=35)

    async with aiohttp.ClientSession(connector=conn_default, timeout=timeout_quick) as s_default, \
               aiohttp.ClientSession(connector=conn_ipv4, timeout=timeout_quick) as s_ipv4, \
               aiohttp.ClientSession(connector=conn_crawl, timeout=timeout_quick) as s_crawl:

        queue: asyncio.Queue = asyncio.Queue()
        for gmina, start_url in rows:
            await queue.put((gmina, start_url))
        checkpoint_counter = {"done": 0}

        async def periodic_checkpoint():
            every = env_int("CHECKPOINT_EVERY_SEC", 60)
            while True:
                await asyncio.sleep(every)
                try:
                    if USE_CACHE:
                        if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                            await save_shard_cache_and_commit(asyncio.get_event_loop())
                        else:
                            save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
                    save_diag(state.diag_rows, state.diag_errors)
                except Exception as ex:
                    print(f"⚠️ periodic checkpoint failed: {ex}", flush=True)

        workers = [
            asyncio.create_task(worker(
                name=f"W{i+1}", queue=queue,
                session_default=s_default, session_ipv4=s_ipv4, session_crawl=s_crawl,
                urls_seen=state.urls_seen, content_seen=state.content_seen,
                checkpoint_counter=checkpoint_counter
            ))
            for i in range(CONCURRENT_GMINY)
        ]
        checkpoint_task = asyncio.create_task(periodic_checkpoint())

        try:
            await queue.join()
        except KeyboardInterrupt:
            state.request_shutdown()
        finally:
            checkpoint_task.cancel()
            await asyncio.gather(checkpoint_task, return_exceptions=True)
            for t in workers:
                t.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    # FINAL SAVE
    try:
        if USE_CACHE:
            if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                await save_shard_cache_and_commit(asyncio.get_event_loop())
            else:
                save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
        save_diag(state.diag_rows, state.diag_errors)
        write_summary(state.diag_rows, state.new_items_for_mail)
        export_summary_to_onedrive()
    except Exception as e:
        print(f"⚠️  Final save failed: {e}")

    # EMAIL
    try:
        if ENABLE_EMAIL and state.new_items_for_mail and not state.shutdown_requested:
            subject = f"BIP WATCHER: {len(state.new_items_for_mail)} nowych/zmienionych wpisów ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
            body = "\n\n".join(state.new_items_for_mail[:1200])
            if len(state.new_items_for_mail) > 1200:
                body += f"\n\n... truncated ({len(state.new_items_for_mail)} total)"
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = EMAIL_TO
            msg["To"] = EMAIL_TO
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as srv:
                srv.send_message(msg)
            print("📨 Email: SENT ✅")
        else:
            print("📨 Email: pominięty.")
    except Exception as e:
        print(f"⚠️  Email failed: {e}")

    print("✅ SKAN ZAKOŃCZONY")

# ===================== RUNNER =====================
def run_main_vscode_style():
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_running():
        print("ℹ️ Wykryto działający event loop. W komórce użyj:  await main()")
        return
    loop.run_until_complete(main())

if __name__ == "__main__":
    run_main_vscode_style()
