# -*- coding: utf-8 -*-
"""
BIP WATCHER v2.21 - PRODUCTION
Zmiany v2.21 vs v2.20:

[1] DETEKTOR STRON DYNAMICZNYCH — nowy moduł DynamicPageDetector
    Jeden wspólny detektor używany w Phase1 i Phase2.
    System punktowy (scoring) z wieloma sygnałami:
    - React/Vue/Angular/Next.js markery w HTML
    - Stosunek tekstu do skryptów
    - Liczba linków <a href> vs rozmiar HTML
    - Puste body lub bardzo mało tekstu
    - webpack/vite/nuxt markery
    - data-reactroot, __NEXT_DATA__, __nuxt itp.
    Próg >= 3 punkty = strona dynamiczna (konfigurowalne DYNAMIC_SCORE_THRESHOLD)

[2] PLAYWRIGHT BFS — pełnoprawny równoległy crawler
    - Startuje od tej samej strony głównej co aiohttp BFS
    - Działa RÓWNOLEGLE z aiohttp BFS w Phase1
    - Głębokość PLAYWRIGHT_MAX_DEPTH (domyślnie 4, jak PHASE1_MAX_DEPTH)
    - Odkryte URL-e trafiają do WSPÓLNEGO frontieru (gmina_frontiers)
    - Persystowane w cache — Phase2 przetwarza je w kolejnych runach
    - Oznaczone source="playwright" w frontierze dla diagnostyki

[3] PHASE1 — równoległy BFS
    - aiohttp BFS + Playwright BFS startują jednocześnie (asyncio.gather)
    - Wyniki łączone w jeden frontier
    - Playwright BFS aktywowany zawsze (nie tylko dla SPA) — decyzja architektoniczna
      żeby nie przegapić niczego, szczególnie dla bip.lubelskie.pl i podobnych

[4] PHASE2 — Playwright jako fallback per-URL
    - Każdy URL najpierw pobierany przez aiohttp
    - Jeśli DynamicPageDetector wykryje stronę dynamiczną → Playwright fetch
    - Wyniki z obu ścieżek przez ten sam keyword matching
    - Nowe linki odkryte przez Playwright w Phase2 dopisywane do frontieru

[5] fetch_with_fallback — naprawiony
    - Teraz używa fetch_conditional (8 wartości z resp_meta)
    - Zwraca 8 wartości (html, final, kind, status, ctype, err, ms, resp_meta)
    - Phase2 poprawnie obsługuje etag/last-modified

[6] crawl_with_playwright — naprawiony wyciek zasobów
    - try/finally gwarantuje zamknięcie każdej strony

Zmiany v2.20 vs v2.18 (zachowane):
- normalize_url: lang/locale/language NIE są filtrowane
- IGNORE_URL_SUBSTR: bez "kadra" i "struktura"
- SPA_FALLBACK_HINTS + collect_spa_fallback_urls
- PHASE1_MAX_DEPTH=4
"""

import os, sys, csv, json, hashlib, asyncio, re, time, smtplib, warnings, socket, random, signal
from collections import deque, defaultdict
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from pathlib import Path

import aiohttp
import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ===================== ENV HELPERS =====================
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
    except Exception:
        return -1

# ===================== GIT / SHARD SAVE =====================
def _git_commit_file(filepath, message):
    print(f"📁 (git pominięty — plik zapisany na dysk): {filepath}")

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
    out["dead_urls"] = getattr(state, "dead_urls", {})
    filename = BASE_DIR / f"cache_shard_{shard}.json"
    try:
        tmp = str(filename) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        os.replace(tmp, filename)
        print(f"📁 Plik shardowy zapisany: {filename}")
    except Exception as e:
        print(f"⚠️ Failed to write shard cache: {e}")
        return
    if loop is None:
        loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _git_commit_file, filename, f"Auto-update cache shard {shard} [skip ci]")

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
FORCE_PHASE1_REDISCOVERY = False

# ===================== REPORTING RULES =====================
ENABLE_LINK_HITS = True
ALIAS_FINAL_AND_SOURCE_KEYS = True

# ===================== EMAIL =====================
EMAIL_TO = "planowanie@wpd-polska.pl"
ENABLE_EMAIL = False

# ===================== KEYWORDS =====================
KEYWORDS = [
    "miejscowy plan zagospodarowania przestrzennego",
    "miejscowego planu zagospodarowania przestrzennego",
    "miejscowych planów zagospodarowania przestrzennego",
    "miejscowych planow zagospodarowania przestrzennego",
    "planu zagospodarowania przestrzennego",
    "plan zagospodarowania przestrzennego",
    "projekt mpzp",
    "plan ogólny gminy",
    "plan ogólny miasta",
    "planu ogólnego gminy",
    "planu ogólnego miasta",
    "plan ogólny",
    "planu ogólnego",
    "plan ogolny",
    "planu ogolnego",
    "studium uwarunkowań i kierunków zagospodarowania przestrzennego",
    "studium uwarunkowan i kierunkow zagospodarowania przestrzennego",
    "studium uwarunkowań",
    "studium uwarunkowan",
    "decyzja o warunkach zabudowy",
    "decyzji o warunkach zabudowy",
    "decyzje o warunkach zabudowy",
    "warunki zabudowy",
    "decyzja o środowiskowych uwarunkowaniach",
    "decyzji o środowiskowych uwarunkowaniach",
    "decyzja o srodowiskowych uwarunkowaniach",
    "decyzji o srodowiskowych uwarunkowaniach",
    "środowiskowych uwarunkowaniach",
    "srodowiskowych uwarunkowaniach",
    "raport o oddziaływaniu na środowisko",
    "elektrownia wiatrowa",
    "elektrowni wiatrowej",
    "park wiatrowy",
    "farma wiatrowa",
    "farmy wiatrowej",
    "wiatrow",
    "fotowolta",
    "farma fotowoltaiczna",
    "magazyn energii",
]

STRICT_ONLY = {"wz", "oze", "ris"}

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
    "majatk", "majątk",
    "regulamin", "sygnalis",
    "login", "logowanie", "rejestracja", "newsletter",
    "galeria-zdjec", "galeria_zdjec", "multimedia", "wideo",
]

IGNORE_URL_PATH_PATTERNS = [
    r"prognoza.pogody",
    r"prognoza_pogody",
    r"/wersja/\d+/?$",
    r"/wersja[_/]",
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
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz"
)

ATT_EXT = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".rtf",
    ".gml", ".xml", ".gpx", ".kml", ".kmz", ".geojson", ".json",
    ".shp", ".dbf", ".shx", ".prj",
    ".dwg", ".dxf",
    ".tif", ".tiff",
)

DOWNLOAD_URL_SEGMENTS = [
    "/pobierz/", "/download/", "/pobieranie/",
    "/file/", "/files/", "/attachment/", "/attachments/",
    "/getfile/", "/get-file/",
    "/dokumenty/pobierz/",
    "/media/", "/uploads/",
    "/file_add/", "/file_add/download/",
    "/filedownload/", "/file-download/",
    "/pobierz-plik/", "/get-file/",
]

DOWNLOAD_URL_PARAMS = [
    "file=", "pobierz=", "download=", "attachment=", "getfile=",
]

_DOWNLOAD_SUFFIX_RE = re.compile(
    r"(pdf|docx?|xlsx?|odt|rtf|zip|rar|7z|gml|xml|tiff?|dwg|dxf)$",
    re.IGNORECASE
)

_PAGINATION_RE = re.compile(
    r"[?&](page|strona|p|offset|start|from|skip|pg)=\d+"
    r"|/page/\d+"
    r"|/strona/\d+"
    r"|[?&]p=\d+"
    r"|/wersja/\d*(?:[/?_]|$)",
    re.IGNORECASE
)

def is_download_url(u: str) -> bool:
    low = (u or "").lower()
    for seg in DOWNLOAD_URL_SEGMENTS:
        if seg in low:
            return True
    for param in DOWNLOAD_URL_PARAMS:
        if param in low:
            return True
    path = urlparse(u).path
    if path and not path.endswith("/"):
        if _DOWNLOAD_SUFFIX_RE.search(path.split("/")[-1]):
            return True
    return False

# ===================== GENERIC TITLE FILTER =====================
_GENERIC_TITLE_PATTERNS = [
    "biuletyn informacji publicznej", "biuletyn informacji", "archiwum bip",
    "bip archiwum", "strona główna", "strona glowna", "aktualności", "aktualnosci",
    "redakcja", "rejestr zmian", "mapa strony",
    "mapa serwisu", "szukaj", "wyszukiwarka", "kontakt", "start", "home",
    "biznes", "informacje", "informacja", "dla mieszkańców", "dla mieszkancow",
    "urząd", "urzad", "gmina", "miasto", "powiat", "więcej", "wiecej",
    "czytaj więcej", "czytaj wiecej", "zobacz więcej", "wszystkie", "kategoria",
    "tagi", "archiwum", "newsletter", "galeria", "multimedia", "przetargi",
    "zamówienia", "zamowienia", "rada miasta", "zarząd", "zarzad",
    "burmistrz", "wójt", "wojt", "starosta",
    "najnowsze informacje", "najnowsze", "więcej informacji", "wiecej informacji",
    "lista zmian", "rejestr zmian strony", "historia zmian",
    "projekty unijne", "projekty europejskie",
    "dla mediów", "dla mediow",
]

def is_generic_page_title(title: str) -> bool:
    t = re.sub(r"\s+", " ", (title or "")).strip().lower()
    if not t or len(t) < 3:
        return True
    for pat in _GENERIC_TITLE_PATTERNS:
        if t == pat:
            return True
        if t.startswith(pat) and len(t) < len(pat) + 15:
            return True
    return False

_JUNK_LINK_TITLE_RE = re.compile(
    r"""
    ^\d+\.html?$
    | ^[\d\s\.\-/\\]+$
    | ^[a-z0-9_\-]+\.[a-z]{2,4}$
    | ^\d+$
    | ^(19|20)\d{2}$
    | ^(pobierz|download|files?|add|get|view|open|click|tutaj|here)\s*[\d\.\-/]*$
    | ^\w+\s+\d+\s*(roku?|r\.?)$
    """,
    re.VERBOSE | re.IGNORECASE
)

_DOWNLOAD_WORDS_RE = re.compile(
    r"\b(pobierz|download|files?|attachment|załącznik|zalacznik|pobieranie)\b",
    re.IGNORECASE
)

def is_junk_link_title(title: str, url: str = "") -> bool:
    t = re.sub(r"\s+", " ", (title or "")).strip()
    lt = t.lower()
    if is_generic_page_title(t):
        return True
    if len(t) < 10:
        return True
    if _JUNK_LINK_TITLE_RE.match(t):
        return True
    if _DOWNLOAD_WORDS_RE.search(lt) and len(t) < 80:
        ok, _ = keyword_match_in_blob(lt)
        if not ok:
            return True
    if url and is_download_url(url):
        return True
    alnum = re.sub(r"[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF]", "", t)
    if len(alnum) < 6:
        return True
    return False

# ===================== PERFORMANCE =====================
CONCURRENT_GMINY = env_int("CONCURRENT_GMINY", 1)
CONCURRENT_REQUESTS = env_int("CONCURRENT_REQUESTS", 50)
LIMIT_PER_HOST = env_int("LIMIT_PER_HOST", 6)

PHASE1_MAX_DEPTH = env_int("PHASE1_MAX_DEPTH", 4)
PHASE1_MAX_URLS = env_int("PHASE1_MAX_URLS", 999999)

PHASE2_MAX_DEPTH = 4
PHASE2_MAX_PAGES = 999999

# v2.21: Playwright BFS — głębokość taka sama jak Phase1
PLAYWRIGHT_MAX_DEPTH = env_int("PLAYWRIGHT_MAX_DEPTH", 4)

# v2.21: próg punktowy detektora dynamicznych stron
# >= DYNAMIC_SCORE_THRESHOLD punktów = strona dynamiczna → użyj Playwright
DYNAMIC_SCORE_THRESHOLD = env_int("DYNAMIC_SCORE_THRESHOLD", 3)

# v2.20 compat
SPA_FALLBACK_MIN_LINKS = env_int("SPA_FALLBACK_MIN_LINKS", 20)

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=12, sock_read=35)
START_TIMEOUT_FAST = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=18)
START_TIMEOUT_LONG = aiohttp.ClientTimeout(total=None, sock_connect=18, sock_read=45)
START_MAX_TRIES = 8
START_AUX_HINTS = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]
START_TOTAL_TIMEOUT_SEC = 60

SCANNED_TTL_DAYS = 365
MAX_PRINT_PER_GMINA = 30
MAX_ERROR_SAMPLES_PER_GMINA = 60

CACHE_CHECKPOINT_EVERY_N_GMINY = 3
SEED_CACHE_TTL_DAYS = 999
FAST_TEXT_MAX_CHARS = 400_000

HIT_RECHECK_TTL_HOURS = 0
NO_MATCH_RECHECK_TTL_HOURS = 0
BLOCKED_RECHECK_TTL_MIN = env_int("BLOCKED_RECHECK_TTL_MIN", 0)
FAILED_RECHECK_TTL_MIN = env_int("FAILED_RECHECK_TTL_MIN", 0)

FRONTIER_CHECKPOINT_EVERY = 500

# ===================== USER AGENTS =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

def get_random_headers(referer: str = "") -> dict:
    sec_fetch_site = "same-origin" if referer else "none"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": sec_fetch_site,
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "DNT": "1",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    if referer:
        headers["Referer"] = referer
    return headers

# ===================== RATE LIMITING =====================
class DomainRateLimiter:
    def __init__(self, min_delay=0.3, max_delay=1.0):
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
    min_delay=env_float("RATE_MIN_DELAY", 0.3),
    max_delay=env_float("RATE_MAX_DELAY", 1.0),
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
        self.reported_urls_this_run: set = set()
        self.last_printed: dict = {}

    def request_shutdown(self):
        self.shutdown_requested = True
        print("\n⚠️  Shutdown requested...", flush=True)

state = GlobalState()

RUN_DEADLINE_MIN = env_int("RUN_DEADLINE_MIN", 0)
GLOBAL_T0 = time.time()

# ===================== SIGNAL HANDLER =====================
_signal_received = False

def signal_handler(signum, frame):
    global _signal_received
    print(f"\n🛑 SIGNAL {signum} received (pid={os.getpid()})", flush=True)
    state.request_shutdown()
    _signal_received = True

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# ===================== UTILS =====================
def iso_now():
    return datetime.now()

def iso_parse(s: str):
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def _canon(u: str) -> str:
    return canonical_url(normalize_url(u or ""))

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def retry_add(gkey: str, retry_seen: set, url: str):
    if any((url or "").lower().endswith(ext) for ext in ATT_EXT):
        return
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
    if shard_index < 0 or shard_total <= 0:
        return rows
    return rows[shard_index::shard_total]

def should_recheck_hit(prev: dict) -> bool:
    if (HIT_RECHECK_TTL_HOURS or 0) <= 0:
        return True
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(hours=HIT_RECHECK_TTL_HOURS)

def should_recheck_no_match(prev: dict) -> bool:
    if (NO_MATCH_RECHECK_TTL_HOURS or 0) <= 0:
        return True
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(hours=NO_MATCH_RECHECK_TTL_HOURS)

def should_recheck_block(prev: dict, ttl_min: int) -> bool:
    if int(ttl_min or 0) <= 0:
        return True
    if not prev or not isinstance(prev, dict):
        return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt:
        return True
    return (iso_now() - dt) >= timedelta(minutes=int(ttl_min or 0))

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

# ===================== BLOCK PAGE DETECTOR =====================
_BLOCK_PATTERNS_SURE = [
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

def is_block_page(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    for p in _BLOCK_PATTERNS_SURE:
        if p.lower() in low:
            return True
    return False

# ===================== DYNAMIC PAGE DETECTOR (v2.21) =====================
# Jeden wspólny detektor używany zarówno w Phase1 jak i Phase2.
# System punktowy — im więcej sygnałów, tym pewniejsza decyzja o użyciu Playwright.
#
# Sygnały i ich wagi:
#   +3  React/Vue/Angular/Next.js markery w HTML (data-reactroot, __NEXT_DATA__ itp.)
#   +3  id="root" lub id="app" w body (typowe dla SPA)
#   +3  Puste body lub <body> z < 200 znaków tekstu przy HTML > 5 KB
#   +3  Bardzo mało linków <a href> (< 5) przy dużym HTML (> 10 KB)
#   +2  Tekst < 300 znaków przy HTML > 5 KB (strona renderuje się przez JS)
#   +2  Skrypty z atrybutem src > 8 (dużo zewnętrznych JS)
#   +1  webpack/vite/nuxt w src skryptów
#   +1  Brak tagu <title> lub bardzo krótki title (< 5 znaków)
#   +2  Odpowiedź serwera: kind == "timeout" lub "exc" przy status None
#        (strona może wymagać JS do załadowania)

class DynamicPageDetector:
    """
    Ocenia czy strona jest dynamiczna (SPA/JS-rendered) i wymaga Playwright.

    Użycie:
        detector = DynamicPageDetector()
        score, reasons = detector.score(html, url, kind, status)
        is_dynamic = score >= DYNAMIC_SCORE_THRESHOLD
    """

    # Markery frameworków JS — bardzo silny sygnał
    _FRAMEWORK_MARKERS = [
        # React
        ("data-reactroot", 3),
        ("__next_data__", 3),
        ("_next/static", 3),
        ("react-dom", 2),
        # Vue
        ("__vue__", 3),
        ("data-v-", 2),
        ("__nuxt", 3),
        ("nuxt.js", 2),
        # Angular
        ("ng-version", 3),
        ("ng-app", 2),
        ("[ng-", 2),
        # Svelte
        ("__svelte", 3),
        # Generyczne SPA markery
        ("webpack", 1),
        ("vite", 1),
        ("chunk.js", 1),
        ("bundle.js", 1),
    ]

    # id/class typowe dla SPA root container
    _ROOT_PATTERNS = re.compile(
        r'(id=["\'])(root|app|__next|__nuxt|app-root|ng-app|vue-app)(["\'])',
        re.IGNORECASE
    )

    def score(self, html: str, url: str = "", kind: str = "html", status: int = None) -> tuple:
        """
        Zwraca (score: int, reasons: list[str]).
        score >= DYNAMIC_SCORE_THRESHOLD → użyj Playwright.
        """
        total = 0
        reasons = []

        if not html:
            # Brak HTML przy braku błędu → prawie na pewno SPA
            if kind == "html" and status == 200:
                total += 3
                reasons.append("empty_html_200")
            return total, reasons

        low = html.lower()
        html_size = len(html)

        # --- Sygnał 1: Markery frameworków JS ---
        fw_score = 0
        fw_hits = []
        for marker, weight in self._FRAMEWORK_MARKERS:
            if marker.lower() in low:
                fw_score = max(fw_score, weight)
                fw_hits.append(marker)
        if fw_score > 0:
            total += fw_score
            reasons.append(f"js_framework({','.join(fw_hits[:3])})")

        # --- Sygnał 2: id="root" / id="app" ---
        if self._ROOT_PATTERNS.search(html):
            total += 3
            reasons.append("spa_root_container")

        # Parsowanie soup — używamy tylko jeśli potrzebne
        soup = None

        def _get_soup():
            nonlocal soup
            if soup is None:
                try:
                    soup = BeautifulSoup(html, "lxml")
                except Exception:
                    soup = None
            return soup

        # --- Sygnał 3: Analiza tekstu vs rozmiar HTML ---
        try:
            s = _get_soup()
            if s:
                for tag in s(["script", "style", "noscript"]):
                    tag.decompose()
                visible_text = re.sub(r"\s+", " ", s.get_text(" ", strip=True)).strip()
                text_len = len(visible_text)

                if html_size > 5000 and text_len < 200:
                    total += 3
                    reasons.append(f"near_empty_body(text={text_len},html={html_size})")
                elif html_size > 5000 and text_len < 300:
                    total += 2
                    reasons.append(f"sparse_text(text={text_len},html={html_size})")
        except Exception:
            pass

        # --- Sygnał 4: Liczba linków <a href> ---
        try:
            s = _get_soup()
            if s:
                links = s.find_all("a", href=True)
                link_count = len(links)
                if html_size > 10000 and link_count < 5:
                    total += 3
                    reasons.append(f"very_few_links(links={link_count},html={html_size})")
                elif html_size > 5000 and link_count < 10:
                    total += 1
                    reasons.append(f"few_links(links={link_count},html={html_size})")
        except Exception:
            pass

        # --- Sygnał 5: Liczba skryptów zewnętrznych ---
        try:
            s = _get_soup()
            if s:
                scripts_with_src = s.find_all("script", src=True)
                if len(scripts_with_src) > 8:
                    total += 2
                    reasons.append(f"many_ext_scripts({len(scripts_with_src)})")
                elif len(scripts_with_src) > 4:
                    total += 1
                    reasons.append(f"ext_scripts({len(scripts_with_src)})")
        except Exception:
            pass

        # --- Sygnał 6: Brak lub bardzo krótki title ---
        try:
            s = _get_soup()
            if s:
                title_tag = s.find("title")
                title_text = (title_tag.get_text(strip=True) if title_tag else "")
                if not title_text or len(title_text) < 5:
                    total += 1
                    reasons.append(f"no_title")
        except Exception:
            pass

        # --- Sygnał 7: Znane dynamiczne ścieżki / parametry URL ---
        # Tylko gdy kombinacja z innymi sygnałami (nie standalone)
        # aby nie być zbyt agresywnym dla zwykłych BIP-ów z ?id=
        if total >= 1:
            url_low = (url or "").lower()
            dynamic_url_hints = [
                "/#/", "/#!/", "/_next/", "/__nuxt/", "/static/js/",
            ]
            if any(h in url_low for h in dynamic_url_hints):
                total += 2
                reasons.append("dynamic_url_pattern")

        return total, reasons

    def is_dynamic(self, html: str, url: str = "", kind: str = "html", status: int = None) -> tuple:
        """
        Zwraca (is_dynamic: bool, score: int, reasons: list[str]).
        Wygodna metoda do użycia w kodzie.
        """
        score, reasons = self.score(html, url, kind, status)
        return score >= DYNAMIC_SCORE_THRESHOLD, score, reasons


# Singleton — jeden detektor dla całego programu
dynamic_detector = DynamicPageDetector()


# ===================== PLAYWRIGHT HELPERS (v2.21) =====================

async def fetch_with_playwright(url: str) -> tuple:
    """
    Pobiera pojedynczą stronę przez Playwright.
    Zwraca (html, final_url, kind, status, ctype, err, ms, resp_meta).
    8 wartości — kompatybilne z fetch_conditional.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None, url, "exc", None, "", "playwright_not_installed", 0, {}

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                t0 = time.time()
                await page.goto(url, wait_until="domcontentloaded", timeout=60000)
                # Poczekaj na załadowanie linków — do 10s
                try:
                    await page.wait_for_selector("a", timeout=10000)
                except Exception:
                    pass  # Brak linków też jest wynikiem
                content = await page.content()
                final_url = page.url
                ms = round((time.time() - t0) * 1000)
                return content, final_url, "html", 200, "text/html", None, ms, {}
            except Exception as e:
                return None, url, "exc", None, "", str(e), 0, {}
            finally:
                try:
                    await page.close()
                except Exception:
                    pass
        except Exception as e:
            return None, url, "exc", None, "", f"browser_launch_error: {e}", 0, {}
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass


async def playwright_bfs(
    start_url: str,
    allowed_host: str,
    max_depth: int,
    diag: dict,
    existing_visited: set = None,
) -> set:
    """
    Pełny BFS przez Playwright — odpowiednik aiohttp BFS z Phase1.

    Startuje od start_url, odkrywa wszystkie wewnętrzne linki do głębokości max_depth.
    Używa tej samej logiki filtrowania co aiohttp BFS (should_skip_href, same_base_domain).

    Parametry:
        start_url       — strona główna gminy
        allowed_host    — host domeny (filtr same-origin)
        max_depth       — maksymalna głębokość BFS (domyślnie PLAYWRIGHT_MAX_DEPTH=4)
        diag            — słownik diagnostyczny
        existing_visited — zbiór URL-i już odwiedzonych przez aiohttp BFS
                          (żeby nie crawlować dwa razy tych samych stron)

    Zwraca:
        set canonicznych URL-i odkrytych przez Playwright (gotowe do frontieru)
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        diag["notes"].append("PLAYWRIGHT_BFS_SKIP: playwright not installed")
        print("  ⚠️  Playwright BFS: playwright nie jest zainstalowany", flush=True)
        return set()

    if existing_visited is None:
        existing_visited = set()

    found_urls = set()
    visited = set(existing_visited)  # kopia — nie modyfikujemy oryginału
    queue = deque()

    cu_start = _canon(start_url)
    if cu_start:
        visited.add(cu_start)
    queue.append((start_url, 0))

    pages_crawled = 0
    pages_failed = 0
    t0 = time.time()

    print(
        f"  🎭 Playwright BFS start: {start_url} "
        f"(max_depth={max_depth}, already_visited={len(existing_visited)})",
        flush=True
    )

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(headless=True)

            while queue and not state.shutdown_requested:
                url, depth = queue.popleft()

                if depth > max_depth:
                    # URL zbyt głęboko — dodaj do frontieru ale nie crawluj
                    cu = _canon(url)
                    if cu:
                        found_urls.add(cu)
                    continue

                # Limit czasu dla Playwright BFS
                if RUN_DEADLINE_MIN > 0 and (time.time() - GLOBAL_T0) > (RUN_DEADLINE_MIN * 60 * 0.3):
                    diag["notes"].append(f"PW_BFS_TIME_LIMIT pages={pages_crawled}")
                    print(f"  ⏱️  Playwright BFS przerwany — limit czasu (pages={pages_crawled})", flush=True)
                    break

                page = None
                try:
                    page = await browser.new_page()

                    # Blokuj zasoby niepotrzebne do odkrywania linków
                    await page.route("**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot}", lambda r: r.abort())

                    await page.goto(url, wait_until="domcontentloaded", timeout=45000)

                    # Poczekaj na linki — max 8s
                    try:
                        await page.wait_for_selector("a[href]", timeout=8000)
                    except Exception:
                        pass

                    final_url = page.url
                    pages_crawled += 1

                    # Pobierz wszystkie linki przez JavaScript
                    try:
                        raw_links = await page.eval_on_selector_all(
                            "a[href]",
                            "els => els.map(e => ({href: e.href, text: e.innerText || e.textContent || ''}))"
                        )
                    except Exception:
                        raw_links = []

                    for link_obj in raw_links:
                        try:
                            href = (link_obj.get("href") or "").strip()
                            if not href or href.startswith("mailto:") or href.startswith("tel:") or href.startswith("javascript:"):
                                continue

                            abs_u = normalize_url(urljoin(final_url, href))
                            if not is_valid_url(abs_u):
                                continue
                            if not same_base_domain(urlparse(abs_u).netloc, allowed_host):
                                continue
                            if should_skip_href(abs_u):
                                continue

                            cu = _canon(abs_u)
                            if not cu or cu in visited:
                                continue

                            visited.add(cu)
                            found_urls.add(cu)

                            # Dodaj do kolejki BFS jeśli nie za głęboko
                            if depth + 1 <= max_depth:
                                queue.append((abs_u, depth + 1))

                        except Exception:
                            continue

                    if pages_crawled % 50 == 0:
                        elapsed = round((time.time() - t0) / 60, 1)
                        print(
                            f"  🎭 Playwright BFS: pages={pages_crawled} "
                            f"found={len(found_urls)} queue={len(queue)} "
                            f"depth={depth} time={elapsed}min",
                            flush=True
                        )

                except Exception as e:
                    pages_failed += 1
                    diag["counts"]["pw_bfs_page_errors"] = int(diag["counts"].get("pw_bfs_page_errors", 0)) + 1
                    if pages_failed <= 5:
                        print(f"  ⚠️  Playwright BFS error @ {url}: {str(e)[:80]}", flush=True)
                finally:
                    # GWARANTOWANE zamknięcie strony — nawet przy błędzie
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass

        except Exception as e:
            diag["notes"].append(f"PW_BFS_FATAL: {str(e)[:100]}")
            print(f"  ❌ Playwright BFS fatal error: {e}", flush=True)
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass

    elapsed = round((time.time() - t0) / 60, 1)
    print(
        f"  🎭 Playwright BFS ZAKOŃCZONY: "
        f"pages_crawled={pages_crawled} "
        f"pages_failed={pages_failed} "
        f"urls_found={len(found_urls)} "
        f"time={elapsed}min",
        flush=True
    )
    diag["notes"].append(
        f"PW_BFS pages={pages_crawled} failed={pages_failed} found={len(found_urls)} time={elapsed}min"
    )
    diag["counts"]["pw_bfs_pages"] = pages_crawled
    diag["counts"]["pw_bfs_found"] = len(found_urls)

    return found_urls


async def fetch_with_fallback(
    session: aiohttp.ClientSession,
    url: str,
    extra_headers: dict = None,
) -> tuple:
    """
    Pobiera stronę przez aiohttp. Jeśli detektor wykryje stronę dynamiczną,
    próbuje przez Playwright.

    Zwraca 8 wartości: (html, final, kind, status, ctype, err, ms, resp_meta)
    Kompatybilne z fetch_conditional.

    Logika:
    1. Pobierz przez aiohttp (fetch_conditional — obsługuje etag/304)
    2. Uruchom DynamicPageDetector na wyniku
    3. Jeśli dynamiczna i aiohttp nie zwróciło dobrego HTML → Playwright
    4. Jeśli Playwright też się nie powiedzie → zwróć wynik aiohttp
    """
    # Krok 1: standardowe pobranie
    result = await fetch_conditional(session, url, extra_headers)
    html, final, kind, status, ctype, err, ms, resp_meta = result

    # Nie próbuj Playwright dla:
    # - plików binarnych (PDF, DOCX itp.)
    # - odpowiedzi 304 Not Modified
    # - stron zablokowanych (403/429) — Playwright też nie przejdzie WAF
    # - błędów DNS / timeout — Playwright też nie pomoże przy problemach sieciowych
    if kind in ("pdf", "not_modified", "blocked"):
        return result
    if kind == "exc" and err and ("dns" in (err or "").lower() or "connect" in (err or "").lower()):
        return result

    # Krok 2: sprawdź czy strona jest dynamiczna
    is_dyn, dyn_score, dyn_reasons = dynamic_detector.is_dynamic(
        html=html or "",
        url=url,
        kind=kind,
        status=status,
    )

    # Playwright potrzebny gdy:
    # a) Detektor wykrył stronę dynamiczną
    # b) LUB aiohttp w ogóle nie zwróciło HTML (timeout, błąd, 5xx)
    need_playwright = is_dyn or (kind != "html") or (not html)

    if not need_playwright:
        return result

    # Krok 3: próba przez Playwright
    reason_str = f"score={dyn_score} reasons={dyn_reasons[:2]}" if is_dyn else f"aiohttp_kind={kind}"
    print(
        f"  🎭 Playwright fetch: {url[:80]} ({reason_str})",
        flush=True
    )

    pw_result = await fetch_with_playwright(url)
    pw_html, pw_final, pw_kind, pw_status, pw_ctype, pw_err, pw_ms, pw_meta = pw_result

    if pw_kind == "html" and pw_html:
        # Playwright udany — zwróć jego wynik z resp_meta z aiohttp (etag itp.)
        # etag/last-modified z Playwright są niedostępne, więc zachowaj z aiohttp
        merged_meta = resp_meta or {}
        return pw_html, pw_final, "html", pw_status, pw_ctype, None, pw_ms, merged_meta
    else:
        # Playwright się nie powiódł — zwróć oryginalny wynik aiohttp
        print(
            f"  ⚠️  Playwright fetch failed ({pw_err[:60] if pw_err else 'unknown'}), "
            f"używam aiohttp result",
            flush=True
        )
        return result


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

# ===================== FUNKCJE POMOCNICZE =====================

def save_diag(diag_rows, diag_errors):
    try:
        def _do():
            new_file = not DIAG_GMINY_CSV.exists()
            with open(DIAG_GMINY_CSV, "a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                if new_file:
                    w.writerow(["datetime", "gmina", "start_url", "status",
                                "phase1_seeds", "phase2_pages_ok", "notes", "counts_json"])
                for r in (diag_rows or []):
                    w.writerow([
                        r.get("datetime"), r.get("gmina"), r.get("start_url"),
                        r.get("status"), r.get("phase1_seeds"), r.get("phase2_pages_ok"),
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
        lines = [
            f"BIP WATCHER v2.21 SUMMARY @ {now_iso()}",
            f"gminy_total={total} ok={ok} start_fail={start_fail}",
            f"mail_items={len(new_items_for_mail or [])}",
            "",
            "TOP hits:",
        ]
        for x in (new_items_for_mail or [])[:500]:
            lines.append("- " + re.sub(r"\s+", " ", x).strip())
        def _do():
            with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        retry_io(_do, tries=6, base_sleep=0.7)
        print(f"🧾 Summary saved: {SUMMARY_FILE}")
    except Exception as ex:
        print(f"⚠️ write_summary failed: {ex}")


def panic_save_checkpoint_sync(reason: str = "SIGTERM"):
    try:
        if not USE_CACHE:
            return
        if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
            shard = get_shard_index()
            out = {"schema": CACHE_SCHEMA}
            out["urls_seen"] = {}
            old_urls = (state.raw_cache or {}).get("urls_seen", {}) if isinstance(state.raw_cache, dict) else {}
            for h in state.urls_seen:
                out["urls_seen"][h] = old_urls.get(h, now_iso())
            out["content_seen"] = state.content_seen or {}
            out["gmina_seeds"] = state.gmina_seeds or {}
            out["gmina_frontiers"] = state.gmina_frontiers or {}
            out["gmina_retry"] = state.gmina_retry or {}
            out["dead_urls"] = getattr(state, "dead_urls", {})
            filename = BASE_DIR / f"cache_shard_{shard}.json"
            tmp = str(filename) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
            os.replace(tmp, filename)
            print(f"🧯 PANIC SAVE (shard) OK [{reason}]: {filename}", flush=True)
            _git_commit_file(filename, f"Panic-save shard {shard} [{reason}] [skip ci]")
        else:
            save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
            print(f"🧯 PANIC SAVE (cache.json) OK [{reason}]", flush=True)
        try:
            save_diag(state.diag_rows, state.diag_errors)
            print(f"🧯 PANIC SAVE (diag) OK [{reason}]", flush=True)
        except Exception as e:
            print(f"⚠️ PANIC diag save failed: {e}", flush=True)
    except Exception as e:
        print(f"⚠️ PANIC SAVE FAILED [{reason}]: {e}", flush=True)

# ===================== URL NORMALIZATION =====================
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
            # v2.20: NIE filtrujemy lang/locale/language — są funkcjonalne w BIP PHP
            if kl in {
                "fbclid", "gclid", "yclid", "sid", "session", "sessionid",
                "phpsessid", "jsessionid", "print", "format",
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
        return p.path == "" or p.path == "/"
    except Exception:
        return False

def is_listing_url(u: str) -> bool:
    low = (u or "").lower()
    return any(x in low for x in [
        "/kategorie/", "/kategoria/", "kategoria=", "category", "/category/",
        "/lista", "lista=", "archiwum", "wszystkie", "tag", "/tag/",
        "page=", "strona=", "offset=", "limit=",
        "/rss", "/feed", "rss.xml", "feed.xml",
        "wyszuk", "szukaj", "search", "query=", "filter", "filtr",
        "ostatnio_dodane", "ostatnio_zaktualizowane",
        "action=", "widok=",
        "/ogloszenia", "/obwieszczenia", "/planowanie", "/mpzp", "/studium",
        "/decyzje", "/uchwaly", "/prawo-miejscowe",
        "?id=",
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
        kws = [kw] if kw else []
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
    for pattern in IGNORE_URL_PATH_PATTERNS:
        if re.search(pattern, u):
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
    if parts[-2] in {"com", "net", "org", "gov", "edu"} and parts[-1] in {"pl", "uk"} and len(parts) >= 3:
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

# ===================== SITEMAP + ROBOTS =====================
def detect_js_app(html: str) -> bool:
    """
    Prosty detektor JS app — używany jako dodatkowy sygnał w Phase1.
    Dla pełnej analizy używaj DynamicPageDetector.is_dynamic().
    """
    if not html:
        return False
    is_dyn, _, _ = dynamic_detector.is_dynamic(html)
    return is_dyn

def extract_sitemaps_from_robots(robots_text: str) -> list:
    out = []
    if not robots_text:
        return out
    for line in robots_text.splitlines():
        line = (line or "").strip()
        if line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[-1].strip()
            if sm and is_valid_url(sm):
                out.append(normalize_url(sm))
    seen = set()
    uniq = []
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
    return ("<urlset" in low[:4000]) or ("<sitemapindex" in low[:4000]) or ('xmlns="http://www.sitemaps.org' in low[:4000])

def parse_sitemap_xml(xml_text: str, base_url: str = "") -> tuple:
    urls = []
    children = []
    if not xml_text:
        return urls, children
    try:
        soup = BeautifulSoup(xml_text, "xml")
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
            if cx not in seen:
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
            async with session.get(url, timeout=timeout, ssl=ssl_mode, allow_redirects=True, headers=headers) as resp:
                final = normalize_url(str(resp.url))
                status = resp.status
                ctype = (resp.headers.get("Content-Type", "") or "").lower()
                data = await resp.read()
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    text = data.decode("latin-1", errors="ignore")
                return text, final, status, ctype, None
        except Exception:
            continue
    return "", url, None, "", None

async def collect_sitemap_urls(session: aiohttp.ClientSession, base_site_url: str, diag, max_urls: int = 4000):
    out_urls = []
    seen_sitemaps = set()
    try:
        robots_url = normalize_url(urljoin(base_site_url, "/robots.txt"))
        robots_text, _, r_status, _, _ = await fetch_text_best_effort(session, robots_url, timeout=START_TIMEOUT_FAST)
        if robots_text and r_status and 200 <= int(r_status) < 400:
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
        xml_text, _, sm_status, sm_ctype, _ = await fetch_text_best_effort(session, sm_url, timeout=START_TIMEOUT_LONG)
        if not xml_text or not (sm_status and 200 <= int(sm_status) < 400):
            diag["counts"]["sitemap_fetch_fail"] += 1
            continue
        if "xml" not in (sm_ctype or "").lower() and not _looks_like_xml_sitemap(xml_text):
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
            seen = set()
            tmp = []
            for u in out_urls:
                cu = canonical_url(u)
                if cu not in seen:
                    seen.add(cu)
                    tmp.append(u)
            out_urls = tmp[:max_urls]

    return out_urls[:max_urls]

# ===================== SPA FALLBACK (v2.20, zachowane) =====================
SPA_FALLBACK_HINTS = [
    "/planowanie-przestrzenne",
]

def _count_internal_links(soup: BeautifulSoup, allowed_host: str) -> int:
    if not soup:
        return 0
    seen = set()
    count = 0
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        try:
            abs_u = urljoin("https://" + allowed_host, href)
            cu = canonical_url(abs_u)
            if not cu or cu in seen:
                continue
            if not same_base_domain(urlparse(cu).netloc, allowed_host):
                continue
            seen.add(cu)
            count += 1
        except Exception:
            continue
    return count


async def collect_spa_fallback_urls(
    session: aiohttp.ClientSession,
    base_site_url: str,
    allowed_host: str,
    diag: dict,
    max_urls: int = 3000,
) -> list:
    found_urls = []
    seen = set()
    hints_hit = 0

    for hint in SPA_FALLBACK_HINTS:
        if len(found_urls) >= max_urls:
            break
        try:
            url = normalize_url(urljoin(base_site_url, hint))
            result = await fetch_with_fallback(session, url)
            html, final, kind, status, ctype, err, ms, resp_meta = result
            if kind != "html" or not html:
                continue
            soup = safe_soup(html)
            if not soup:
                continue

            links_found = 0
            for a in soup.find_all("a", href=True):
                href = (a.get("href") or "").strip()
                if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                    continue
                try:
                    abs_u = normalize_url(urljoin(final, href))
                    if not is_valid_url(abs_u):
                        continue
                    if not same_base_domain(urlparse(abs_u).netloc, allowed_host):
                        continue
                    if should_skip_href(abs_u):
                        continue
                    cu = canonical_url(abs_u)
                    if not cu or cu in seen:
                        continue
                    seen.add(cu)
                    found_urls.append(abs_u)
                    links_found += 1
                except Exception:
                    continue

            if links_found > 0:
                hints_hit += 1
                diag["notes"].append(f"SPA_FALLBACK_HIT hint={hint} links={links_found}")
        except Exception as ex:
            diag["notes"].append(f"SPA_FALLBACK_ERR hint={hint} err={str(ex)[:60]}")
            continue

    return found_urls[:max_urls]


# ===================== TEXT EXTRACTION =====================
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

def _soup_fast_text(soup: BeautifulSoup, max_chars: int = FAST_TEXT_MAX_CHARS) -> str:
    try:
        if not soup:
            return ""
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        has_main_content = bool(
            soup.find("main") or
            soup.find(id=re.compile(r"(content|tresc|main|article)", re.I)) or
            soup.find(class_=re.compile(r"(content|tresc|main|article)", re.I))
        )
        if has_main_content:
            for tag in soup(["nav", "header", "footer", "aside"]):
                tag.decompose()
        txt = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        txt = _strip_dynamic_noise(txt)
        return txt[:max_chars]
    except Exception:
        return ""

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
        pass

    blob = _clean(f"{title} {h1t} {h2t} {h3t} {meta_desc}")
    return title, h1t, h2t, blob

def print_hit(tag: str, gmina: str, kw: str, title: str):
    shown = re.sub(r"\s+", " ", (title or "").strip())
    print(f"{tag} {gmina}: [{kw}] -> {shown[:180]}", flush=True)

# ===================== ATTACHMENTS =====================
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

# ===================== LISTING URL HINTS =====================
LISTING_URL_HINTS = [
    "ogloszenia", "ogłoszenia", "obwieszc", "komunikat", "zawiadom",
    "konsultac", "wylozen", "wyłożen", "przystap", "przystąp",
    "prawo-miejscowe", "prawo_miejscowe", "uchwaly", "uchwał",
    "rejestr-urbanist", "rejestr_urbanist", "urbanist",
    "plan-ogolny", "plan_ogolny", "studium", "planowanie",
    "warunki-zabudowy", "warunki_zabudowy", "wz",
    "ochrona-srodowiska", "ochrona_srodowiska",
    "srodowisko", "środowisko", "pv", "fotowolta", "fotowoltaika", "slonecz", "słonecz",
    "energia", "energetyka", "decyzje-srodowisk", "decyzje_srodowisk", "ooś", "oos",
    "archiwum-ogloszen", "archiwum_ogloszen", "bip-archiwum",
    "kategoria", "kategorie", "lista-ogloszen", "lista_ogloszen",
    "decyzje", "decyzja", "postanowienie", "obwieszczenie",
    "srodowiskowe", "srodowiskowa", "srodowiskowych",
    "plany", "plan", "plany-zagospodarowania", "plany_zagospodarowania",
    "uchwala", "uchwaly", "uchwal", "uchwalone",
    "ostatnio_dodane", "ostatnio_zaktualizowane",
]

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
CACHE_SCHEMA = 15  # v2.21: +1 dla nowych pól playwright

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

    shard = get_shard_index()
    if os.getenv("GITHUB_ACTIONS") and shard >= 0:
        cache_path = BASE_DIR / f"cache_shard_{shard}.json"
    else:
        cache_path = CACHE_FILE

    if not cache_path.exists():
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            c = json.load(f) or {}

        if "schema" not in c and "found_items" in c:
            print("🔄 Legacy cache detected. Upgrading...")
            c = _empty_cache()

        if not isinstance(c.get("schema"), int):
            c["schema"] = CACHE_SCHEMA

        if c.get("schema", 0) < CACHE_SCHEMA:
            print(f"🔄 Migrating cache schema {c.get('schema')} -> {CACHE_SCHEMA} (keeping data)")
            c["schema"] = CACHE_SCHEMA
            c.setdefault("urls_seen", {})
            c.setdefault("content_seen", {})
            c.setdefault("gmina_seeds", {})
            c.setdefault("gmina_frontiers", {})
            c.setdefault("gmina_retry", {})
            c.setdefault("dead_urls", {})
            c.pop("page_fprints", None)

        def _ensure_dict(key):
            if not isinstance(c.get(key), dict):
                c[key] = {}
            return c[key]

        urls = _ensure_dict("urls_seen")
        content = _ensure_dict("content_seen")
        gseeds = _ensure_dict("gmina_seeds")
        gf = _ensure_dict("gmina_frontiers")
        gr = _ensure_dict("gmina_retry")
        dead = _ensure_dict("dead_urls")

        print(f"📦 Cache loaded: {len(urls)} URLs, {len(content)} content, {len(gseeds)} gmina seeds, {len(gf)} frontiers, {len(dead)} dead entries")
        return c, set(urls.keys()), content, gseeds, gf, gr, dead

    except Exception as e:
        print(f"⚠️  Cache load error: {e}")
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

def save_cache_v2(raw_cache, urls_seen_set, content_seen, gmina_seeds):
    out = {"schema": CACHE_SCHEMA}
    old_urls = (raw_cache or {}).get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    print(f"💾 save_cache_v2: urls_seen={len(urls_seen_set)} | content_seen={len(content_seen or {})} | seeds={len(gmina_seeds or {})} | frontiers={len(state.gmina_frontiers or {})} | dead={len(getattr(state,'dead_urls',{}) or {})}")
    out["content_seen"] = content_seen or {}
    out["gmina_seeds"] = gmina_seeds or {}
    out["gmina_frontiers"] = state.gmina_frontiers or {}
    out["gmina_retry"] = state.gmina_retry or {}
    out["dead_urls"] = getattr(state, "dead_urls", {})
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
    to_del = [h for h, ts in list(urls_dict.items()) if _ts_older_than(ts, cutoff)]
    for h in to_del:
        urls_seen_set.discard(h)
        urls_dict.pop(h, None)
    seed_cutoff = datetime.now() - timedelta(days=SEED_CACHE_TTL_DAYS)
    to_del_seeds = [k for k, meta in list((gmina_seeds or {}).items()) if _ts_older_than((meta or {}).get("ts", ""), seed_cutoff)]
    for k in to_del_seeds:
        gmina_seeds.pop(k, None)
    if to_del or to_del_seeds:
        print(f"🧹 Purged: {len(to_del)} URL, {len(to_del_seeds)} seeds")

def _ts_older_than(ts: str, cutoff: datetime) -> bool:
    try:
        return datetime.fromisoformat(ts) < cutoff
    except Exception:
        return True

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
        "trace": {"phase": "", "last_url": "", "last_kind": "", "last_status": None, "last_ms": None},
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

# ===================== FETCH =====================
async def fetch_with_retry(session, url, timeout, ssl_mode, max_retries=3, method="GET"):
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
                    await asyncio.sleep((2 ** attempt) * random.uniform(0.5, 1.5))
                    continue
                if status >= 500 and attempt < max_retries - 1:
                    await asyncio.sleep((2 ** attempt) * random.uniform(0.3, 1.0))
                    continue
                return final, status, ctype, text, ms
        except asyncio.TimeoutError:
            if attempt < max_retries - 1:
                await asyncio.sleep(1.0 * (attempt + 1))
                continue
            raise
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
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
            return str(r.url), r.status_code, r.headers.get("Content-Type", ""), (r.text or "")[:20000], ms
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
                final, status, ctype, text, ms = res if res else (url, None, "", "", None)
            else:
                continue

            lu = url.lower()
            if any(ax in lu for ax in ("/robots.txt", "sitemap")):
                ok = status is not None and 200 <= int(status) < 400 and bool(text)
                diag["start_matrix"].append({"ok": ok, "strategy": strategy_name, "url": url, "status": status, "kind": "aux_ok" if ok else "aux_fail"})
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
            kind = "ssl" if ("ssl" in msg.lower() or "certificate" in msg.lower()) else "exc"
            diag["start_matrix"].append({"ok": False, "strategy": strategy_name, "url": url, "status": None, "kind": kind})
            last_fail = (None, url, kind, None, "", msg, None)

    return last_fail if last_fail else (None, url, "fail", None, "", "no_strategy_worked", None)

_BINARY_MAGIC = [
    b"%PDF", b"\xD0\xCF\x11\xE0", b"PK\x03\x04", b"\x1F\x8B",
    b"BM", b"\xFF\xD8\xFF", b"\x89PNG", b"GIF8",
]

_BINARY_CTYPE_RE = re.compile(
    r"(application/pdf|application/msword|application/vnd\.|"
    r"application/octet|application/zip|application/x-|"
    r"image/|audio/|video/)",
    re.IGNORECASE
)

_BINARY_URL_SUFFIX_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|odt|rtf|zip|rar|7z|gml|tiff?|dwg|dxf|jpg|jpeg|png|gif|mp4|mp3)$"
    r"|pdf$|docx?$|xlsx?$",
    re.IGNORECASE
)

def _is_binary_response(ctype: str, data: bytes, url: str) -> bool:
    if _BINARY_CTYPE_RE.search(ctype or ""):
        return True
    if data and len(data) >= 4:
        header = data[:8]
        for magic in _BINARY_MAGIC:
            if header.startswith(magic):
                return True
    path = urlparse(url or "").path
    if path and _BINARY_URL_SUFFIX_RE.search(path.split("/")[-1]):
        return True
    return False

async def fetch(session: aiohttp.ClientSession, url: str, extra_headers: dict = None):
    """Bazowa funkcja fetch — zwraca 7 wartości (bez resp_meta)."""
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
                if _is_binary_response(ctype, data, final):
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

async def fetch_conditional(session: aiohttp.ClientSession, url: str, extra_headers: dict = None):
    """
    Fetch z obsługą warunkowego HTTP (etag, last-modified, 304 Not Modified).
    Zwraca 8 wartości: (html, final, kind, status, ctype, err, ms, resp_meta).
    """
    url = normalize_url(url)
    domain = urlparse(url).netloc
    parsed = urlparse(url)
    referer = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))

    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers(referer=referer)
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
                if _is_binary_response(ctype, data, final):
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
    yielded = set()
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

# ============================================================
# POMOCNICZE — stan cyklu gminy
# ============================================================

def gmina_cycle_key(gkey: str) -> str:
    return f"cycle_{gkey}"

def is_frontier_complete(gkey: str) -> bool:
    meta = state.gmina_seeds.get(gmina_cycle_key(gkey), {})
    return bool(meta.get("frontier_complete", False))

def mark_frontier_complete(gkey: str, total_urls: int):
    state.gmina_seeds[gmina_cycle_key(gkey)] = {
        "frontier_complete": True,
        "frontier_total": total_urls,
        "cycle_started": now_iso(),
        "ts": now_iso(),
    }

def mark_frontier_reset(gkey: str):
    state.gmina_seeds.pop(gmina_cycle_key(gkey), None)


# ============================================================
# PHASE 1 — Jeden adaptacyjny BFS (v2.22)
#
# Na każdym kroku BFS:
#   1. Pobierz stronę przez aiohttp
#   2. should_try_playwright() ocenia czy warto też odpytać Playwright:
#      - URL sugeruje ogłoszenia/planowanie (LISTING_URL_HINTS)
#        ALE treść jest pusta/krótka lub mało linków → JS nie wyrenderował
#      - LUB aiohttp w ogóle nie zwróciło HTML (błąd, timeout)
#   3. Jeśli tak → Playwright pobiera TĘ SAMĄ stronę (networkidle)
#   4. Scal linki z OBU źródeł — bierzemy WSZYSTKO
#
# Logika jest uniwersalna — działa dla każdej gminy bez sztywnych progów.
# ============================================================


def _extract_links_from_html(html: str, base_url: str, allowed_host: str) -> set:
    """Wyciąga wszystkie wewnętrzne linki z HTML. Zwraca zbiór canonicznych URL."""
    links = set()
    soup = safe_soup(html)
    if not soup:
        return links
    for abs_u, txt in iter_links_fast(soup, base_url):
        if not same_base_domain(urlparse(abs_u).netloc, allowed_host):
            continue
        cu = _canon(abs_u)
        if cu:
            links.add(cu)
    return links


def should_try_playwright(url: str, html: str, aiohttp_kind: str) -> tuple:
    """
    Ocenia czy warto odpytać Playwright dla tej strony.
    Zwraca (bool, reason: str).

    Playwright odpala się gdy:
    1. aiohttp w ogóle nie zwróciło HTML (błąd, timeout, http_err)
    2. URL sugeruje że strona powinna zawierać ogłoszenia/listy
       ALE treść jest podejrzanie pusta lub mało linków wewnętrznych
    3. Strona ma dużo HTML ale bardzo mało widocznego tekstu
       (klasyczny objaw SPA — React/Vue renderuje przez JS)
    """
    url_low = (url or "").lower()

    # Przypadek 1: aiohttp w ogóle nie dostało HTML
    if aiohttp_kind != "html":
        return True, f"aiohttp_failed(kind={aiohttp_kind})"

    if not html:
        return True, "empty_html"

    html_size = len(html)

    try:
        soup = safe_soup(html)
        if not soup:
            return True, "no_soup"

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        all_links = soup.find_all("a", href=True)
        text_len = len(text)
        links_count = len(all_links)

        # Przypadek 2: dużo HTML ale mało tekstu — klasyczny SPA
        # np. html=50KB ale tekst=200 znaków → JS renderuje treść
        if html_size > 10000 and text_len < 400:
            return True, f"spa_suspect(html={html_size},text={text_len})"

        # Przypadek 3: URL z parametrem ?id= lub podobnym — BIP-y PHP często
        # mają taką strukturę gdzie podstrony są dynamiczne mimo statycznego menu
        url_has_id_param = bool(re.search(r"[?&](id|art|kat|dz|sub|nid)=\d+", url_low))
        if url_has_id_param and text_len < 800:
            return True, f"id_param_sparse(text={text_len})"

        # Przypadek 4: URL sugeruje ogłoszenia/planowanie
        url_relevant = any(h in url_low for h in LISTING_URL_HINTS)
        if url_relevant:
            # Usuń nav/header/footer żeby nie liczyć menu jako treści listingu
            for tag in soup(["nav", "header", "footer", "aside"]):
                tag.decompose()
            content_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
            content_links = soup.find_all("a", href=True)

            if len(content_text) < 500:
                return True, f"listing_sparse(text={len(content_text)},links={len(content_links)})"
            if len(content_links) < 6:
                return True, f"listing_few_links(links={len(content_links)})"

    except Exception:
        return True, "parse_error"

    return False, "ok"


async def _fetch_links_playwright(url: str, allowed_host: str) -> set:
    """
    Pobiera stronę przez Playwright (networkidle) i zwraca zbiór wewnętrznych linków.
    networkidle czeka aż JS skończy renderować — kluczowe dla SPA/React/Angular.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return set()

    links = set()
    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                await page.route(
                    "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3}",
                    lambda r: r.abort()
                )
                await page.goto(url, wait_until="networkidle", timeout=45000)
                final_url = page.url
                raw_links = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href).filter(h => h && !h.startsWith('javascript:'))"
                )
                for href in raw_links:
                    try:
                        abs_u = normalize_url(urljoin(final_url, href))
                        if not is_valid_url(abs_u):
                            continue
                        if not same_base_domain(urlparse(abs_u).netloc, allowed_host):
                            continue
                        if should_skip_href(abs_u):
                            continue
                        cu = _canon(abs_u)
                        if cu:
                            links.add(cu)
                    except Exception:
                        continue
            except Exception:
                pass
            finally:
                try:
                    await page.close()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
    return links


async def phase1_full_crawl(
    gmina: str,
    start_url: str,
    session_default,
    session_ipv4,
    session_crawl,
    diag,
) -> tuple:
    """
    Phase1 v2.22 — jeden adaptacyjny BFS.

    Na każdej stronie:
    - aiohttp pobiera HTML → wyciągamy linki
    - jeśli should_try_playwright() → Playwright pobiera TĘ SAMĄ stronę
      i dodajemy jego linki DO PULI (nie zamiast, ale OPRÓCZ)
    - wszystkie zebrane linki trafiają do kolejki BFS i do frontieru

    Dzięki temu strony które mają część linków w HTML a część w JS
    (np. menu statyczne + lista ogłoszeń przez AJAX) są obsługiwane poprawnie.
    """
    if state.shutdown_requested:
        return [], {"status": "SHUTDOWN"}

    html0 = final0 = None
    kind0 = "fail"
    status0 = None
    allowed_host = ""

    trace_set(diag, "PHASE1_START", url=start_url)
    tried = 0
    start_time = time.time()

    # ── Krok 1: Pobierz stronę główną ─────────────────────────────────────────
    for su in candidate_start_urls(start_url):
        if (time.time() - start_time) > START_TOTAL_TIMEOUT_SEC:
            diag["notes"].append(f"START_TIMEOUT after {int(time.time()-start_time)}s")
            break
        if state.shutdown_requested:
            break
        tried += 1
        if tried > START_MAX_TRIES:
            break

        html0, final0, kind0, status0, ctype0, err0, ms = await fetch_start_matrix(
            session_default, session_ipv4, su, diag
        )
        diag["start_attempts"].append({
            "try_url": su, "kind": kind0, "status": status0,
            "final": (final0 or "")[:220], "ms": ms,
        })
        trace_set(diag, "PHASE1_START", url=su, kind=kind0, status=status0, ms=ms)

        if len(diag["start_attempts"]) >= 6:
            recent = diag["start_attempts"][-6:]
            if all(x.get("status") == 403 for x in recent):
                diag["notes"].append("EARLY_EXIT: 6/6 = 403 (WAF)")
                break

        if kind0 == "html" and html0:
            allowed_host = urlparse(final0).netloc.lower()
            okm = [m for m in diag["start_matrix"] if m.get("ok")]
            if okm:
                diag["notes"].append(f"START_OK strategy={okm[-1].get('strategy')}")
            break

    if kind0 != "html" or not html0:
        diag["notes"].append(f"START_FAIL tried={tried}")
        diag_add_error(diag, gmina, start_url, "phase1_start", kind0, status0, "no_html_start")
        print(f"  ❌ Phase1 START_FAIL [{gmina}]: tried={tried} last_kind={kind0} last_status={status0}", flush=True)
        return [], {"status": "START_FAIL"}

    base_site = urlunparse((
        urlparse(final0).scheme,
        urlparse(final0).netloc,
        "/", "", "", ""
    ))

    def allow_url(u: str) -> bool:
        return same_base_domain(urlparse(u).netloc.lower(), allowed_host)

    seeds = {}
    visited = set()
    q = deque()

    # ── Krok 2: Sitemap ────────────────────────────────────────────────────────
    try:
        sitemap_urls = await collect_sitemap_urls(session_crawl, base_site, diag, max_urls=5000)
        sitemap_added = 0
        for u in sitemap_urls:
            if allow_url(u) and not should_skip_href(u):
                cu = _canon(u)
                if cu:
                    score = 20 if any(h in u.lower() for h in LISTING_URL_HINTS) else 10
                    seeds[cu] = max(seeds.get(cu, 0), score)
                    if cu not in visited:
                        visited.add(cu)
                    sitemap_added += 1
        diag["notes"].append(f"SITEMAP_SEEDS={sitemap_added}")
        print(f"  🗺️  Sitemap [{gmina}]: {sitemap_added} URL", flush=True)
    except Exception as ex:
        diag["notes"].append(f"SITEMAP_FAILED: {str(ex)[:80]}")

    # Strona główna jako punkt startowy BFS
    cu0 = _canon(final0)
    if cu0 not in visited:
        visited.add(cu0)
    q.appendleft((final0, 0))
    seeds[cu0] = seeds.get(cu0, 5)

    pages_crawled = 0
    pw_fetches = 0
    pw_extra_links = 0

    print(
        f"  🕷️  BFS [{gmina}] @ {allowed_host} "
        f"sitemap_seeds={len(seeds)} max_depth={PHASE1_MAX_DEPTH}",
        flush=True
    )

    # ── Krok 3: Adaptacyjny BFS ────────────────────────────────────────────────
    while q and not state.shutdown_requested:
        if RUN_DEADLINE_MIN > 0 and (time.time() - GLOBAL_T0) > (RUN_DEADLINE_MIN * 60 * 0.35):
            diag["notes"].append(f"PHASE1_TIME_LIMIT pages={pages_crawled}")
            print(f"  ⏱️  Phase1 limit czasu [{gmina}]: pages={pages_crawled}", flush=True)
            break

        url, depth = q.popleft()
        url = normalize_url(url)

        if depth > PHASE1_MAX_DEPTH:
            cu = _canon(url)
            if cu and not any(url.lower().endswith(ext) for ext in ATT_EXT):
                seeds[cu] = seeds.get(cu, 1)
            continue

        # --- aiohttp ---
        result = await fetch_conditional(session_crawl, url)
        html, final, kind, status, ctype, err, ms, resp_meta = result

        if kind != "html" or not html:
            cu = _canon(url)
            if cu and not any(url.lower().endswith(ext) for ext in ATT_EXT):
                seeds[cu] = seeds.get(cu, 1)
            diag_add_error(diag, gmina, url, "phase1_bfs", kind, status, err)
            continue

        pages_crawled += 1
        final_c = _canon(final or url)

        # --- Linki z aiohttp ---
        aiohttp_links = _extract_links_from_html(html, final, allowed_host)

        # --- Playwright jeśli strona wygląda jakby JS nie wyrenderował treści ---
        pw_links = set()
        use_pw, pw_reason = should_try_playwright(url, html, kind)
        if use_pw:
            pw_fetches += 1
            print(
                f"  🎭 [{gmina}] Playwright @ depth={depth} "
                f"reason={pw_reason} aiohttp_links={len(aiohttp_links)} "
                f"url={url[:65]}",
                flush=True
            )
            try:
                pw_links = await _fetch_links_playwright(final, allowed_host)
                new_from_pw = len(pw_links - aiohttp_links)
                pw_extra_links += new_from_pw
                print(
                    f"  🎭 Playwright: {len(pw_links)} linków "
                    f"(+{new_from_pw} nowych) @ {url[:60]}",
                    flush=True
                )
            except Exception as ex:
                diag["notes"].append(f"PW_ERR {url[:50]}: {str(ex)[:60]}")

        # --- Scal WSZYSTKIE linki z obu źródeł ---
        all_links = aiohttp_links | pw_links

        for cu in all_links:
            if not cu or not allow_url(cu):
                continue
            if any(cu.lower().endswith(ext) for ext in ATT_EXT):
                continue
            ul = cu.lower()
            score = 15 if any(h in ul for h in LISTING_URL_HINTS) else 1
            seeds[cu] = max(seeds.get(cu, 0), score)
            if cu not in visited:
                visited.add(cu)
                next_depth = depth + 2 if is_listing_url(cu) else depth + 1
                q.append((cu, next_depth))

        if pages_crawled % 100 == 0:
            elapsed = round((time.time() - start_time) / 60, 1)
            print(
                f"  🕷️  BFS [{gmina}] pages={pages_crawled} seeds={len(seeds)} "
                f"q={len(q)} depth={depth} pw_fetches={pw_fetches} time={elapsed}min",
                flush=True
            )

        if len(seeds) >= PHASE1_MAX_URLS:
            diag["notes"].append(f"PHASE1_MAX_URLS_REACHED={len(seeds)}")
            break

    phase1_complete = not state.shutdown_requested
    all_urls = sorted(seeds.keys(), key=lambda u: -seeds.get(u, 0))

    diag["notes"].append(
        f"PHASE1_DONE pages={pages_crawled} seeds={len(all_urls)} "
        f"pw_fetches={pw_fetches} pw_extra_links={pw_extra_links}"
    )
    print(
        f"  ✅ Phase1 {'KOMPLETNA' if phase1_complete else 'PRZERWANA'} [{gmina}]: "
        f"pages={pages_crawled} frontier={len(all_urls)} "
        f"pw_fetches={pw_fetches} pw_extra_links={pw_extra_links} "
        f"czas={round((time.time()-start_time)/60,1)}min",
        flush=True
    )

    return all_urls, {
        "status": "OK",
        "allowed_host": allowed_host,
        "start_final": final0,
        "seeds": len(all_urls),
        "phase1_complete": phase1_complete,
        "pages_crawled": pages_crawled,
        "pw_fetches": pw_fetches,
        "pw_extra_links": pw_extra_links,
    }

# PHASE 2 — sprawdza zawartość + odkrywa nowe linki (v2.21)
# ============================================================

async def phase2_focus(
    gmina: str,
    session_crawl,
    allowed_host: str,
    content_seen: dict,
    diag,
) -> tuple:
    """
    Phase2 v2.21 — bez zmian w logice głównej relative to v2.20,
    ale teraz fetch_with_fallback automatycznie używa Playwright
    gdy detektor wykryje stronę dynamiczną.

    Każdy URL z frontieru:
    1. Pobierany przez fetch_with_fallback (aiohttp + Playwright fallback)
    2. Sprawdzany przez keyword matching
    3. Nowe linki odkryte podczas skanowania → dopisywane do frontieru
    """
    if state.shutdown_requested:
        return [], {"status": "SHUTDOWN"}

    found = []
    gkey = gmina_cache_key(gmina, "https://" + allowed_host)
    dead_key = f"dead_{gkey}"
    dead_set = set(state.dead_urls.get(dead_key, []) or [])
    retry_seen = set()

    raw_frontier = (state.gmina_frontiers or {}).get(gkey, []) or []
    if not raw_frontier:
        print(f"  ⚠️  Phase2 [{gmina}]: brak frontieru (gkey={gkey[:8]}...) — pomijam", flush=True)
        return [], {"status": "NO_FRONTIER"}

    q = deque()
    seen_in_frontier = set()
    for item in raw_frontier:
        try:
            fu = item[0] if isinstance(item, list) else str(item)
            fd = int(item[1]) if isinstance(item, list) and len(item) > 1 else 0
        except Exception:
            continue
        cu = _canon(fu)
        if cu and cu not in seen_in_frontier and cu not in dead_set:
            seen_in_frontier.add(cu)
            q.append((cu, fd))

    total_in_frontier = len(q)

    retry_list = (state.gmina_retry or {}).get(gkey, []) or []
    retry_added = 0
    for u in retry_list:
        cu = _canon(u)
        if cu and cu not in seen_in_frontier and cu not in dead_set:
            seen_in_frontier.add(cu)
            q.appendleft((cu, 0))
            retry_seen.add(sha1(cu))
            retry_added += 1
    if retry_added:
        print(f"  🔁 Retry: {retry_added} URL [{gmina}]", flush=True)

    if isinstance(state.gmina_retry, dict):
        state.gmina_retry[gkey] = []

    print(
        f"  🔍 Phase2 start [{gmina}]: "
        f"frontier={total_in_frontier} | retry={retry_added} | dead={len(dead_set)}",
        flush=True
    )

    def allow_url(u: str) -> bool:
        return same_base_domain(urlparse(u).netloc.lower(), allowed_host)

    pages_ok = 0
    pages_skipped_ttl = 0
    new_links_added = 0

    while q and not state.shutdown_requested:
        if RUN_DEADLINE_MIN > 0 and (time.time() - GLOBAL_T0) > (RUN_DEADLINE_MIN * 60):
            state.request_shutdown()
            break

        url, depth = q.popleft()

        if pages_ok > 0 and pages_ok % FRONTIER_CHECKPOINT_EVERY == 0:
            async with state.cache_lock:
                state.gmina_frontiers[gkey] = [[u, d] for u, d in q]
            print(
                f"  📊 [{gmina}] pages_ok={pages_ok} pominięte={pages_skipped_ttl} "
                f"nowe_linki={new_links_added} pozostało={len(q)} "
                f"czas={round((time.time()-GLOBAL_T0)/60,1)}min",
                flush=True
            )

        url = _canon(url)
        if not url:
            continue

        url_dedup = sha1(canonical_url(url))
        prev_pre = content_seen.get(url_dedup)
        is_listing = is_listing_url(url) or is_home_url(url)

        if USE_CACHE and prev_pre and not is_listing:
            status_prev = prev_pre.get("status")
            if status_prev in {"NOWE", "ZMIANA", "HIT"}:
                if not should_recheck_hit(prev_pre):
                    diag["counts"]["hit_ttl_skip"] += 1
                    pages_skipped_ttl += 1
                    continue
            elif status_prev == "NO_MATCH":
                if not should_recheck_no_match(prev_pre):
                    diag["counts"]["no_match_ttl_skip"] += 1
                    pages_skipped_ttl += 1
                    continue
            elif status_prev == "BLOCKED":
                if not should_recheck_block(prev_pre, BLOCKED_RECHECK_TTL_MIN):
                    diag["counts"]["blocked_ttl_skip"] += 1
                    pages_skipped_ttl += 1
                    continue
            elif status_prev == "FAILED":
                if not should_recheck_block(prev_pre, FAILED_RECHECK_TTL_MIN):
                    diag["counts"]["failed_ttl_skip"] += 1
                    pages_skipped_ttl += 1
                    continue

        extra_headers = {}
        if prev_pre and prev_pre.get("etag"):
            extra_headers["If-None-Match"] = prev_pre["etag"]
        if prev_pre and prev_pre.get("last_modified"):
            extra_headers["If-Modified-Since"] = prev_pre["last_modified"]

        # fetch_with_fallback — automatycznie używa Playwright jeśli detektor to wskaże
        html, final, kind, status, ctype, err, ms, resp_meta = await fetch_with_fallback(
            session_crawl, url, extra_headers
        )

        final_c = _canon(final or url)
        url_dedup_final = sha1(canonical_url(final_c))
        prev = content_seen.get(url_dedup_final) or prev_pre

        if final_c != url:
            diag["counts"]["redirected"] += 1

        if kind == "not_modified":
            async with state.cache_lock:
                if url_dedup_final in content_seen:
                    content_seen[url_dedup_final]["last_checked"] = now_iso()
                    content_seen[url_dedup_final]["status"] = "HIT"
                if ALIAS_FINAL_AND_SOURCE_KEYS and url_dedup != url_dedup_final:
                    entry = content_seen.get(url_dedup_final, {}).copy()
                    entry["last_checked"] = now_iso()
                    entry["status"] = "HIT"
                    content_seen[url_dedup] = entry
            diag["counts"]["not_modified"] += 1
            continue

        if kind == "blocked":
            diag["counts"]["blocked_13"] += 1
            retry_add(gkey, retry_seen, final_c)
            async with state.cache_lock:
                prevb = content_seen.get(url_dedup_final) or prev_pre
                entry = {
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
                content_seen[url_dedup_final] = entry
                if ALIAS_FINAL_AND_SOURCE_KEYS and url_dedup != url_dedup_final:
                    content_seen[url_dedup] = entry.copy()
            continue

        if kind != "html" or not html:
            if status in (404, 410):
                dead_add(dead_key, dead_set, final_c)
                diag["counts"]["dead_urls"] += 1
                continue
            if status in (403, 429) or kind in {"timeout", "exc"} or (status and int(status) >= 500):
                retry_add(gkey, retry_seen, final_c)
                async with state.cache_lock:
                    prevf = content_seen.get(url_dedup_final) or prev_pre
                    entry = {
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
                    content_seen[url_dedup_final] = entry
                    if ALIAS_FINAL_AND_SOURCE_KEYS and url_dedup != url_dedup_final:
                        content_seen[url_dedup] = entry.copy()
                diag["counts"]["failed_urls"] += 1
            continue

        pages_ok += 1
        soup = safe_soup(html)
        if not soup:
            continue

        title, h1, h2, meta_blob = extract_title_h1_h2(soup)
        att_set = attachments_signature(soup, final_c)
        fast_text = _soup_fast_text(soup)

        blob = f"{title} {h1} {h2} {fast_text}"
        ok_any, kw_any = keyword_match_in_blob(blob)

        page_title = ""
        for candidate in [h1, h2, title]:
            c = (candidate or "").strip()
            if c and not is_generic_page_title(c):
                page_title = c
                break
        if not page_title:
            page_title = final_c

        if prev is None:
            status_new = "NOWE" if ok_any else "NO_MATCH"
        else:
            if ok_any:
                prev_att_set = att_sig_deserialize(prev.get("att_sig") or "")
                added_files = att_set - prev_att_set
                if added_files:
                    status_new = "ZMIANA"
                    diag["counts"]["att_added"] += len(added_files)
                else:
                    status_new = "HIT"
            else:
                status_new = "NO_MATCH"

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
            if ALIAS_FINAL_AND_SOURCE_KEYS and url_dedup != url_dedup_final:
                content_seen[url_dedup] = meta.copy()

        if status_new in {"NOWE", "ZMIANA"}:
            diag["counts"][f"hit_{status_new.lower()}"] += 1
            if final_c not in state.reported_urls_this_run:
                state.reported_urls_this_run.add(final_c)
                print_hit(f"🟢 {status_new}", gmina, kw_any, page_title)
                found.append((gmina, kw_any, page_title, final_c, status_new))
            else:
                diag["counts"]["dedup_skipped"] += 1

        # Odkrywanie nowych linków — dopisuje do końca frontieru
        for abs_u, txt in iter_links_fast(soup, final_c):
            cu = _canon(abs_u)
            if not cu or not allow_url(cu) or cu in dead_set:
                continue
            if cu in seen_in_frontier:
                continue

            if ENABLE_LINK_HITS and not is_download_url(cu):
                filename = urlparse(cu).path.split("/")[-1]
                ok_link, kw_link = keyword_match_in_blob(f"{txt} {filename}")
                if ok_link:
                    key = sha1(canonical_url(cu))
                    if content_seen.get(key) is None and cu not in state.reported_urls_this_run:
                        async with state.cache_lock:
                            content_seen[key] = {
                                "found_at": now_iso(), "last_checked": now_iso(),
                                "etag": "", "last_modified": "",
                                "gmina": gmina,
                                "title": (txt or filename)[:240],
                                "url": cu,
                                "keywords": [kw_link],
                                "att_sig": "", "status": "NOWE",
                            }
                        state.reported_urls_this_run.add(cu)
                        print_hit("🟢 NOWE (LINK)", gmina, kw_link, txt or filename)
                        found.append((gmina, kw_link, (txt or filename)[:240], cu, "NOWE"))
                        diag["counts"]["link_hits_new"] += 1

            seen_in_frontier.add(cu)
            q.append((cu, depth + 1))
            new_links_added += 1

    async with state.cache_lock:
        if q:
            state.gmina_frontiers[gkey] = [[u, d] for u, d in list(q)]
            print(
                f"  💾 Frontier zapisany [{gmina}]: "
                f"pozostało={len(q)} | nowe_linki={new_links_added} | ten_run={pages_ok}",
                flush=True
            )
        else:
            state.gmina_frontiers[gkey] = []
            mark_frontier_reset(gkey)
            print(
                f"  🏁 Frontier wyczerpany [{gmina}]: "
                f"sprawdzono={pages_ok} | pominięto_ttl={pages_skipped_ttl} | "
                f"znaleziono={len(found)} | PEŁNY CYKL ZAKOŃCZONY",
                flush=True
            )

    retry_final = len((state.gmina_retry or {}).get(gkey, []) or [])

    return found, {
        "status": "OK",
        "pages_ok": pages_ok,
        "pages_skipped_ttl": pages_skipped_ttl,
        "stop_reason": "SHUTDOWN" if state.shutdown_requested else "QUEUE_EMPTY",
        "frontier_len": len(q),
        "retry_len": retry_final,
        "new_links_added": new_links_added,
    }


# ============================================================
# WORKER — orkiestracja Phase1 + Phase2
# ============================================================

async def worker(
    name: str,
    queue: asyncio.Queue,
    session_default,
    session_ipv4,
    session_crawl,
    urls_seen: set,
    content_seen: dict,
    checkpoint_counter: dict,
):
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

            gkey_approx = gmina_cache_key(gmina, start_url)
            has_frontier = bool((state.gmina_frontiers or {}).get(gkey_approx))
            frontier_complete = is_frontier_complete(gkey_approx)

            p1meta = None
            found = []

            if has_frontier and frontier_complete:
                frontier_size = len((state.gmina_frontiers or {}).get(gkey_approx, []))
                print(
                    f"  ▶️  [{name}] {gmina}: kontynuacja Phase2 "
                    f"(frontier kompletny, {frontier_size} URL)",
                    flush=True
                )
                cached_seeds = state.gmina_seeds.get(gkey_approx, {})
                allowed_host = cached_seeds.get(
                    "allowed_host",
                    urlparse(normalize_url(start_url)).netloc.lower()
                )
                found, p2meta = await phase2_focus(
                    gmina=gmina,
                    session_crawl=session_crawl,
                    allowed_host=allowed_host,
                    content_seen=content_seen,
                    diag=diag,
                )
                p1meta = {"status": "SKIP", "seeds": 0, "phase1_complete": True}

            else:
                reason = "brak frontieru" if not has_frontier else "frontier niekompletny"
                print(f"  🆕 [{name}] {gmina}: Phase1 — {reason}", flush=True)

                all_urls, p1meta = await phase1_full_crawl(
                    gmina=gmina,
                    start_url=start_url,
                    session_default=session_default,
                    session_ipv4=session_ipv4,
                    session_crawl=session_crawl,
                    diag=diag,
                )

                if p1meta.get("status") != "OK":
                    print_start_fail_report(diag, gmina, start_url)
                    state.diag_rows.append({
                        "datetime": now_iso(), "gmina": gmina, "start_url": start_url,
                        "status": "START_FAIL",
                        "phase1_seeds": 0, "phase2_pages_ok": 0,
                        "notes": diag.get("notes", []),
                        "counts": dict(diag.get("counts", {})),
                    })
                    for e in diag.get("errors", []):
                        state.diag_errors.append(e)
                    print(f"  ❌ [{name}] {gmina}: START_FAIL — pomijam Phase2", flush=True)
                    continue

                allowed_host = p1meta["allowed_host"]
                gkey = gmina_cache_key(gmina, "https://" + allowed_host)
                phase1_complete = p1meta.get("phase1_complete", False)

                async with state.cache_lock:
                    state.gmina_frontiers[gkey] = [[u, 0] for u in all_urls]

                state.gmina_seeds[gkey_approx] = {
                    "allowed_host": allowed_host,
                    "start_final": p1meta.get("start_final", ""),
                    "seeds": len(all_urls),
                    "home_dynamic": p1meta.get("home_dynamic", False),
                    "home_dyn_score": p1meta.get("home_dyn_score", 0),
                    "ts": now_iso(),
                }

                if phase1_complete:
                    mark_frontier_complete(gkey, len(all_urls))
                    print(
                        f"  ✅ [{name}] {gmina}: Phase1 KOMPLETNA — "
                        f"frontier={len(all_urls)} URL | startuje Phase2",
                        flush=True
                    )
                else:
                    print(
                        f"  ⚠️  [{name}] {gmina}: Phase1 NIEKOMPLETNA — "
                        f"frontier={len(all_urls)} | Phase2 z tym co jest",
                        flush=True
                    )

                found, p2meta = await phase2_focus(
                    gmina=gmina,
                    session_crawl=session_crawl,
                    allowed_host=allowed_host,
                    content_seen=content_seen,
                    diag=diag,
                )

            stop_reason = (p2meta or {}).get("stop_reason") or ""
            frontier_len = int((p2meta or {}).get("frontier_len", 0) or 0)
            retry_len = int((p2meta or {}).get("retry_len", 0) or 0)
            pages_ok = int((p2meta or {}).get("pages_ok", 0) or 0)
            pages_skipped = int((p2meta or {}).get("pages_skipped_ttl", 0) or 0)
            new_links = int((p2meta or {}).get("new_links_added", 0) or 0)
            status_run = "OK" if (not stop_reason or stop_reason == "QUEUE_EMPTY") else "INCOMPLETE"

            state.diag_rows.append({
                "datetime": now_iso(), "gmina": gmina, "start_url": start_url,
                "status": status_run,
                "phase1_seeds": int((p1meta or {}).get("seeds", 0) or 0),
                "phase2_pages_ok": pages_ok,
                "notes": (diag.get("notes", []) or []) + [
                    f"stop_reason={stop_reason}",
                    f"frontier_len={frontier_len}",
                    f"retry_len={retry_len}",
                    f"pages_skipped_ttl={pages_skipped}",
                    f"new_links_added={new_links}",
                ],
                "counts": dict(diag.get("counts", {})),
            })
            for e in diag.get("errors", []):
                state.diag_errors.append(e)

            for (g, kw, t, u, st) in (found or []):
                mail_line = f"[{st}] {g} | {kw} | {t} | {u}"
                if mail_line not in state.mail_dedup:
                    state.mail_dedup.add(mail_line)
                    state.new_items_for_mail.append(mail_line)
                    log_new_item(g, t, u, kw)

            checkpoint_counter["done"] = int(checkpoint_counter.get("done", 0)) + 1
            if USE_CACHE and (checkpoint_counter["done"] % CACHE_CHECKPOINT_EVERY_N_GMINY == 0):
                try:
                    if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                        await save_shard_cache_and_commit(asyncio.get_event_loop())
                    else:
                        save_cache_v2(state.raw_cache, state.urls_seen, content_seen, state.gmina_seeds)
                        purge_old_cache(state.raw_cache, state.urls_seen, content_seen, state.gmina_seeds, state.dead_urls)
                except Exception as ex:
                    print(f"⚠️ checkpoint save failed: {ex}", flush=True)

            cycle_info = ""
            if frontier_len > 0:
                total_approx = frontier_len + pages_ok
                done_pct = round(pages_ok / max(total_approx, 1) * 100, 1)
                cycle_info = f" | cykl≈{done_pct}%"

            print(
                f"✅ [{name}] DONE: {gmina} | "
                f"znalezione={len(found or [])} | "
                f"phase2_strony={pages_ok} | "
                f"pominięte_ttl={pages_skipped} | "
                f"nowe_linki={new_links} | "
                f"frontier_pozostało={frontier_len} | "
                f"retry={retry_len}"
                f"{cycle_info}",
                flush=True
            )

        except asyncio.CancelledError:
            return
        except Exception as e:
            print(f"❌ [{name}] ERROR: {gmina} -> {e}", flush=True)
            import traceback
            traceback.print_exc()
            try:
                diag_add_error(diag, gmina or "", start_url or "", "worker", "exc", None, str(e))
                for er in diag.get("errors", []):
                    state.diag_errors.append(er)
                state.diag_rows.append({
                    "datetime": now_iso(), "gmina": gmina or "", "start_url": start_url or "",
                    "status": "WORKER_ERROR", "phase1_seeds": 0, "phase2_pages_ok": 0,
                    "notes": (diag.get("notes", []) or []) + [f"worker_exc={str(e)[:200]}"],
                    "counts": dict(diag.get("counts", {})),
                })
            except Exception:
                pass
        finally:
            if got_item:
                if USE_CACHE and os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                    await save_shard_cache_and_commit(asyncio.get_event_loop())
                queue.task_done()

# ===================== MAIN =====================
async def main():
    reset_val = os.getenv("RESET_CACHE", "0").strip().lower()
    if reset_val in ("1", "true", "yes"):
        print("🗑️  RESET_CACHE — czyszczę cache...")
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            print(f"   ✅ Usunięto: {CACHE_FILE}")
        for shard_file in BASE_DIR.glob("cache_shard_*.json"):
            shard_file.unlink()
            print(f"   ✅ Usunięto: {shard_file}")
        print("   ✅ Cache wyczyszczony.")

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

    conn_kwargs = dict(
        limit=CONCURRENT_REQUESTS,
        limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
        ssl=False
    )
    conn_default = aiohttp.TCPConnector(**conn_kwargs)
    conn_ipv4 = aiohttp.TCPConnector(family=socket.AF_INET, **conn_kwargs)
    conn_crawl = aiohttp.TCPConnector(**conn_kwargs)
    timeout_quick = aiohttp.ClientTimeout(total=None, sock_connect=12, sock_read=35)

    async with (
        aiohttp.ClientSession(connector=conn_default, timeout=timeout_quick) as s_default,
        aiohttp.ClientSession(connector=conn_ipv4, timeout=timeout_quick) as s_ipv4,
        aiohttp.ClientSession(connector=conn_crawl, timeout=timeout_quick) as s_crawl,
    ):
        queue: asyncio.Queue = asyncio.Queue()
        for gmina, start_url in rows:
            await queue.put((gmina, start_url))
        checkpoint_counter = {"done": 0}

        async def periodic_checkpoint():
            every = env_int("CHECKPOINT_EVERY_SEC", 300)
            while not state.shutdown_requested:
                await asyncio.sleep(every)
                if state.shutdown_requested:
                    break
                try:
                    if USE_CACHE:
                        if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                            await save_shard_cache_and_commit(asyncio.get_event_loop())
                        else:
                            save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
                    save_diag(state.diag_rows, state.diag_errors)
                    print(f"⏱️ Periodic checkpoint OK", flush=True)
                except Exception as ex:
                    print(f"⚠️ periodic checkpoint failed: {ex}", flush=True)

            print("🔚 Finalny checkpoint...", flush=True)
            try:
                if USE_CACHE:
                    if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                        await save_shard_cache_and_commit(asyncio.get_event_loop())
                    else:
                        save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
                save_diag(state.diag_rows, state.diag_errors)
                print("✅ Finalny checkpoint zapisany.", flush=True)
            except Exception as ex:
                print(f"⚠️ Finalny checkpoint failed: {ex}", flush=True)

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
