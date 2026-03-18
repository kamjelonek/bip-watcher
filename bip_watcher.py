# -*- coding: utf-8 -*-
"""
BIP WATCHER v2.41 - PRODUCTION
Zmiany v2.41 vs v2.40:

[FIX 1] normalize_url — whitelist parametrów URL zamiast blacklisty
    Problem: każdy nowy CMS wymyśla własne noise params (bsc=, bip=, acc_*, code=, sort=, rpg=...).
    Blacklista nigdy nie będzie kompletna → eksplozja frontieru dla Miłoradz, Ścinawa, Pępowo itp.
    Rozwiązanie: zachowaj TYLKO params które identyfikują dokument (KEEP_PARAMS).
    Wszystko inne wyrzucane automatycznie — nowy CMS z nowym noise param → działa bez interwencji.
    Bonus: id= stripowane gdy document_id= obecne w tym samym URL (id= to wtedy menu, nie dokument).

[FIX 2] make_allow_url_fn + _host_allowed — exact host match dla WSZYSTKICH
    Problem: same_base_domain("sp2.gostyn.pl", "biuletyn.gostyn.pl") = True → szkoły wpadają
    do frontieru. Strzegom: liceum, cmentarze, centrum kultury zamiast BIP-u.
    Rozwiązanie: zawsze exact host match (h == allowed_host lub www.allowed_host).
    Dotyczy wszystkich hostów — nie tylko shared providers i strict BIP.
    Universalne: działa dla każdej przyszłej gminy bez konfiguracji.

[FIX 3] canonical_url — breadcrumb normalizacja dla wszystkich hostów
    Problem: /a/b/c/930 i /x/y/z/930 to ten sam dokument (madkom/wokiss breadcrumb).
    Fix v2.39 działał tylko dla _is_strict_bip_host → wokiss.pl (Jarocin) wykluczony.
    Rozwiązanie: usuń warunek _is_strict_bip_host — aplikuj breadcrumb canonical dla WSZYSTKICH.
    Dodatkowa ochrona: segment kończący się ,LICZBA (madkom: m,5096 a,22784) → normalizuj.

[FIX 4] phase2_focus — NO_MATCH + keyword = NOWE (fix Wiązów)
    Problem: Playwright redirect m,5096→a,22784 → a,22784 był już w content_seen jako NO_MATCH
    → ok_any=True ale prev!=None → status_new=HIT → nie raportowane → znalezione=0.
    Rozwiązanie: gdy prev.status == "NO_MATCH" i ok_any=True → traktuj jak prev=None → NOWE.
    Logika: NO_MATCH = "sprawdzono, nie było keyword" — jeśli teraz jest → to jest nowe odkrycie.

[FIX 5] phase2_focus — czyszczenie frontieru przy starcie (fix Strzegom)
    Problem: stare URL-e z lo.strzegom.pl, cmentarze.strzegom.pl itd. siedzą w cache
    z poprzednich runów gdy same_base_domain było zbyt liberalne → 346k URL-i zamiast BIP-u.
    Fix 2 zapobiega dodawaniu nowych złych URL-i ale nie czyści starych.
    Rozwiązanie: przy ładowaniu frontieru filtruj każdy URL przez allow_url() — złe URL-e
    odrzucane jednorazowo przy starcie. Loguje ile URL-i odfiltrowano.

[FIX 6] phase2_focus — PW_PROCESSING w TTL check
    Problem: Fix v2.40 ustawiał placeholder status="PW_PROCESSING" ale TTL check go ignorował
    → URL nie był skipowany przy kolejnym wejściu → przetwarzany od nowa w pętli.
    Rozwiązanie: PW_PROCESSING traktowany jak NO_MATCH w TTL check.

Zmiany v2.23 vs v2.22:

    [ZMIANA 1] _fetch_links_playwright — pełny mini-BFS przez Playwright (glebokosc 1)
    [ZMIANA 2] phase1_full_crawl — automatyczny Playwright fallback per URL
    [ZMIANA 3] phase2_focus — rownolegly Playwright dla tresci stron
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
    pass  # git commit obsługiwany przez GitHub Actions YAML (if: always())

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
    out["new_items_for_mail"] = list(state.new_items_for_mail or [])  # [v2.36] backup
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
    # git commit/push obsługiwany przez GitHub Actions YAML — nie robimy tego z Pythona

# ===================== PATHS =====================
BASE_DIR = Path(__file__).resolve().parent / "data"
BASE_DIR.mkdir(parents=True, exist_ok=True)
CSV_FILE = BASE_DIR / "bipy1.csv"
CACHE_FILE = BASE_DIR / "cache.json"
LOG_FILE = BASE_DIR / "log.csv"
DIAG_GMINY_CSV = BASE_DIR / "diag_gminy.csv"
DIAG_ERRORS_CSV = BASE_DIR / "diag_errors.csv"
SUMMARY_FILE = BASE_DIR / "summary_report.txt"
HITS_BACKUP_FILE = BASE_DIR / "hits_backup.jsonl"  # [v2.36] backup ogłoszeń gdy email zawiedzie
ONEDRIVE_EXPORT_DIR = None  # OneDrive niedostępny w GitHub Actions

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

# ===================== NAV CONTEXT =====================
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
            m = re.search(rf"(?<!\w){re.escape(k)}(?!\w)", t)
            if m:
                return (True, kw)
        else:
            if k in t:
                return (True, kw)
    return (False, None)

# ===================== IGNORE =====================
IGNORE_URL_SUBSTR = [
    "kontakt", "mapa-strony", "mapa_strony", "wyszukiwarka", "statystyka",
    "cookies", "deklaracja-dostepnosci", "deklaracja_dostepnosci",
    "majatk", "majątk", "regulamin", "sygnalis",
    "login", "logowanie", "rejestracja", "newsletter",
    # Galerie, multimedia, zdjęcia — nigdy nie zawierają ogłoszeń planistycznych
    "galeria-zdjec", "galeria_zdjec", "galeria-fotografii", "galeria_fotografii",
    "galeria/", "/galeria", "photo", "photogallery", "zdjecia", "zdjęcia",
    "multimedia", "wideo", "video", "film", "filmy",
    # Szkoły, instytucje podrzędne — nie są BIP-em gminy
    "absolwenci", "uczniowie", "nauczyciele", "szkola", "szkoła",
    # Aktualności i newsy gminne (nie BIP) — nie zawierają aktów planistycznych
    "readmore=", "news.php", "aktualnosci.php", "artykul.php",
    # Akcje systemowe CMS — nigdy nie zwracają treści HTML do analizy
    # action=save, action=show, action=edit itp. to endpointy zapisu/podglądu raw
    # które zwracają pusty response (115B) lub JSON, nie stronę dokumentu
    "action=save", "action=show&", "action=edit", "action=delete",
    "action=export", "action=download", "action=print",
    # p=print, p=document — alternatywne widoki/akcje w bip.net.pl i podobnych
    "p=print", "p=document", "p=edit", "p=save",
    # Alternatywne formaty tej samej treści — nigdy nie są wartościowe
    "/xml/", "drukuj.asp", "core/drukuj", "core/pdf",
    "akcja=drukuj", "akcja=pdf", "format=pdf", "format=xml",
    "/print/", "/drukuj/",
]

IGNORE_URL_PATH_PATTERNS = [
    r"prognoza.pogody", r"prognoza_pogody",
    r"/wersja/\d+/?$", r"/wersja[_/]",
    # rodo jako osobny segment — nie uderza w srodowisk*, ochrona-srodowiska itp.
    r"[/=\-]rodo[/.\-_]", r"[/=\-]rodo$", r"/rodo/",
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
    ".shp", ".dbf", ".shx", ".prj", ".dwg", ".dxf",
    ".tif", ".tiff",
)

DOWNLOAD_URL_SEGMENTS = [
    "/pobierz/", "/download/", "/pobieranie/",
    "/file/", "/files/", "/attachment/", "/attachments/",
    "/getfile/", "/get-file/", "/dokumenty/pobierz/", "/media/", "/uploads/",
    "/file_add/", "/file_add/download/", "/filedownload/", "/file-download/",
    "/pobierz-plik/", "/get-file/",
    # [v2.40 Fix4] Sulechów CMS i podobne — /pliki/NUMER to pliki binarne (PDF/DOC)
    # serwowane przez CMS pod numerycznym ID. Nie są stronami HTML.
    "/pliki/",
]

DOWNLOAD_URL_PARAMS = ["file=", "pobierz=", "download=", "attachment=", "getfile="]

_DOWNLOAD_SUFFIX_RE = re.compile(
    r"(pdf|docx?|xlsx?|odt|rtf|zip|rar|7z|gml|xml|tiff?|dwg|dxf"
    # [v2.37] binaria i multimedia — Playwright nie powinien ich otwierać
    r"|exe|msi|dmg|deb|rpm|apk|bat|sh|cmd"
    r"|dav|avi|mp4|mkv|mov|wmv|flv|webm|mpg|mpeg|m4v"
    r"|mp3|wav|ogg|flac|aac|wma|m4a"
    r"|iso|img|bin|vhd|vmdk"
    r"|dat|bak|tmp"
    r")$", re.IGNORECASE
)

_PAGINATION_RE = re.compile(
    r"[?&](page|strona|p|offset|start|from|skip|pg)=\d+"
    r"|/page/\d+|/strona/\d+|[?&]p=\d+|/wersja/\d*(?:[/?_]|$)",
    re.IGNORECASE
)

def is_download_url(u: str) -> bool:
    low = (u or "").lower()
    for seg in DOWNLOAD_URL_SEGMENTS:
        if seg in low: return True
    for param in DOWNLOAD_URL_PARAMS:
        if param in low: return True
    path = urlparse(u).path
    if path and not path.endswith("/"):
        if _DOWNLOAD_SUFFIX_RE.search(path.split("/")[-1]):
            return True
    return False

# ===================== GENERIC TITLE FILTER =====================
_GENERIC_TITLE_PATTERNS = [
    "biuletyn informacji publicznej", "biuletyn informacji", "archiwum bip",
    "bip archiwum", "strona główna", "strona glowna", "aktualności", "aktualnosci",
    "redakcja", "rejestr zmian", "mapa strony", "mapa serwisu", "szukaj",
    "wyszukiwarka", "kontakt", "start", "home", "biznes", "informacje", "informacja",
    "dla mieszkańców", "dla mieszkancow", "urząd", "urzad", "gmina", "miasto",
    "powiat", "więcej", "wiecej", "czytaj więcej", "czytaj wiecej", "zobacz więcej",
    "wszystkie", "kategoria", "tagi", "archiwum", "newsletter", "galeria",
    "multimedia", "przetargi", "zamówienia", "zamowienia", "rada miasta",
    "zarząd", "zarzad", "burmistrz", "wójt", "wojt", "starosta",
    "najnowsze informacje", "najnowsze", "więcej informacji", "wiecej informacji",
    "lista zmian", "rejestr zmian strony", "historia zmian",
    "projekty unijne", "projekty europejskie", "dla mediów", "dla mediow",
]

def is_generic_page_title(title: str) -> bool:
    t = re.sub(r"\s+", " ", (title or "")).strip().lower()
    if not t or len(t) < 3: return True
    for pat in _GENERIC_TITLE_PATTERNS:
        if t == pat: return True
        if t.startswith(pat) and len(t) < len(pat) + 15: return True
    return False

_JUNK_LINK_TITLE_RE = re.compile(
    r"""
    ^\d+\.html?$ | ^[\d\s\.\-/\\]+$ | ^[a-z0-9_\-]+\.[a-z]{2,4}$
    | ^\d+$ | ^(19|20)\d{2}$
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
    if is_generic_page_title(t): return True
    if len(t) < 10: return True
    if _JUNK_LINK_TITLE_RE.match(t): return True
    if _DOWNLOAD_WORDS_RE.search(lt) and len(t) < 80:
        ok, _ = keyword_match_in_blob(lt)
        if not ok: return True
    if url and is_download_url(url): return True
    alnum = re.sub(r"[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF]", "", t)
    if len(alnum) < 6: return True
    return False

# ===================== PERFORMANCE =====================
CONCURRENT_GMINY = env_int("CONCURRENT_GMINY", 1)
CONCURRENT_REQUESTS = env_int("CONCURRENT_REQUESTS", 80)
LIMIT_PER_HOST = env_int("LIMIT_PER_HOST", 10)

PHASE1_MAX_DEPTH = env_int("PHASE1_MAX_DEPTH", 4)
PHASE1_MAX_URLS = env_int("PHASE1_MAX_URLS", 999999)

PHASE2_MAX_DEPTH = 4
PHASE2_MAX_PAGES = 999999

PLAYWRIGHT_MAX_DEPTH = env_int("PLAYWRIGHT_MAX_DEPTH", 4)
DYNAMIC_SCORE_THRESHOLD = env_int("DYNAMIC_SCORE_THRESHOLD", 5)
SPA_FALLBACK_MIN_LINKS = env_int("SPA_FALLBACK_MIN_LINKS", 20)

# [v2.23] Próg: jeśli aiohttp znalazł mniej linków — uruchamiamy Playwright
PHASE1_MIN_LINKS_FOR_PW = env_int("PHASE1_MIN_LINKS_FOR_PW", 8)

# [v2.23] Max stron odwiedzanych przez Playwright w mini-BFS per wywołanie
PLAYWRIGHT_MINI_BFS_MAX_PAGES = env_int("PLAYWRIGHT_MINI_BFS_MAX_PAGES", 20)

# [v2.29] Max wywołań Playwright do zbierania linków w Phase1 na gminę
# Po osiągnięciu limitu — reszta stron przez aiohttp (bez PW)
PHASE1_MAX_PW_FETCHES = env_int("PHASE1_MAX_PW_FETCHES", 50)

# [v2.30] Co ile stron Phase1 zapisuje częściowy frontier do state
# Zabezpiecza przed utratą pracy gdy job zostanie przerwany w trakcie Phase1
PHASE1_FRONTIER_CHECKPOINT_EVERY = env_int("PHASE1_FRONTIER_CHECKPOINT_EVERY", 500)

# [v2.23] Min długość tekstu (znaki) aby uznać stronę za HTML (nie JS)
PHASE2_MIN_TEXT_FOR_HTML = env_int("PHASE2_MIN_TEXT_FOR_HTML", 200)

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

# [v2.36] TTL — krytyczny fix. TTL=0 powoduje że program ignoruje cache
# i skanuje te same URL-e przy każdym runie, nigdy nie docierając do końca frontieru.
HIT_RECHECK_TTL_HOURS     = env_int("HIT_RECHECK_TTL_HOURS",     168)  # 7 dni
NO_MATCH_RECHECK_TTL_HOURS = env_int("NO_MATCH_RECHECK_TTL_HOURS", 168)  # 7 dni — identyczne z HIT
BLOCKED_RECHECK_TTL_MIN   = env_int("BLOCKED_RECHECK_TTL_MIN",    120)  # 2 godziny
FAILED_RECHECK_TTL_MIN    = env_int("FAILED_RECHECK_TTL_MIN",      60)  # 1 godzina

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
    min_delay=env_float("RATE_MIN_DELAY", 0.2),
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
    # panic_save wywoływana przez atexit (zdefiniowana niżej w kodzie)

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
    if not cu: return
    hu = sha1(cu)
    if hu in retry_seen: return
    retry_seen.add(hu)
    state.gmina_retry.setdefault(gkey, []).append(cu)

def dead_add(dead_key: str, dead_set: set, url: str):
    cu = _canon(url)
    if not cu or cu in dead_set: return
    dead_set.add(cu)
    state.dead_urls.setdefault(dead_key, []).append(cu)

def pick_rows_for_shard(rows, shard_index: int, shard_total: int):
    if shard_index < 0 or shard_total <= 0: return rows
    return rows[shard_index::shard_total]

def should_recheck_hit(prev: dict) -> bool:
    if (HIT_RECHECK_TTL_HOURS or 0) <= 0: return True
    if not prev or not isinstance(prev, dict): return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt: return True
    return (iso_now() - dt) >= timedelta(hours=HIT_RECHECK_TTL_HOURS)

def should_recheck_no_match(prev: dict) -> bool:
    if (NO_MATCH_RECHECK_TTL_HOURS or 0) <= 0: return True
    if not prev or not isinstance(prev, dict): return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt: return True
    return (iso_now() - dt) >= timedelta(hours=NO_MATCH_RECHECK_TTL_HOURS)

def should_recheck_block(prev: dict, ttl_min: int) -> bool:
    if int(ttl_min or 0) <= 0: return True
    if not prev or not isinstance(prev, dict): return True
    last = prev.get("last_checked") or prev.get("found_at") or ""
    dt = iso_parse(last)
    if not dt: return True
    return (iso_now() - dt) >= timedelta(minutes=int(ttl_min or 0))

def export_summary_to_onedrive():
    try:
        if not ONEDRIVE_EXPORT_DIR or str(ONEDRIVE_EXPORT_DIR).strip() == "": return
        if not ONEDRIVE_EXPORT_DIR.exists(): return
        if not SUMMARY_FILE.exists(): return
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
    "zbyt dużo jednoczesnych połączeń", "zbyt wiele jednoczesnych połączeń",
    "spróbuj za moment", "sprobuj za moment", "spróbuj ponownie później",
    "sprobuj ponownie pozniej", "twoja aktywność została uznana",
    "twoja aktywnosc zostala uznana", "too many requests", "request blocked",
    "403 forbidden", "access denied",
]

def is_block_page(text: str) -> bool:
    if not text: return False
    low = text.lower()
    for p in _BLOCK_PATTERNS_SURE:
        if p.lower() in low: return True
    return False

# ===================== DYNAMIC PAGE DETECTOR =====================
class DynamicPageDetector:
    _FRAMEWORK_MARKERS = [
        ("data-reactroot", 3), ("__next_data__", 3), ("_next/static", 3), ("react-dom", 2),
        ("__vue__", 3), ("data-v-", 2), ("__nuxt", 3), ("nuxt.js", 2),
        ("ng-version", 3), ("ng-app", 2), ("[ng-", 2), ("__svelte", 3),
        ("webpack", 1), ("vite", 1), ("chunk.js", 1), ("bundle.js", 1),
    ]

    _ROOT_PATTERNS = re.compile(
        r'(id=["\'])(root|app|__next|__nuxt|app-root|ng-app|vue-app)(["\'])',
        re.IGNORECASE
    )

    def score(self, html: str, url: str = "", kind: str = "html", status: int = None) -> tuple:
        total = 0
        reasons = []

        if not html:
            if kind == "html" and status == 200:
                total += 3
                reasons.append("empty_html_200")
            return total, reasons

        low = html.lower()
        html_size = len(html)

        fw_score = 0
        fw_hits = []
        for marker, weight in self._FRAMEWORK_MARKERS:
            if marker.lower() in low:
                fw_score = max(fw_score, weight)
                fw_hits.append(marker)
        if fw_score > 0:
            total += fw_score
            reasons.append(f"js_framework({','.join(fw_hits[:3])})")

        if self._ROOT_PATTERNS.search(html):
            total += 3
            reasons.append("spa_root_container")

        soup = None
        def _get_soup():
            nonlocal soup
            if soup is None:
                try:
                    soup = BeautifulSoup(html, "lxml")
                except Exception:
                    soup = None
            return soup

        try:
            s = _get_soup()
            if s:
                for tag in s(["script", "style", "noscript"]): tag.decompose()
                visible_text = re.sub(r"\s+", " ", s.get_text(" ", strip=True)).strip()
                text_len = len(visible_text)
                if html_size > 5000 and text_len < 200:
                    total += 3
                    reasons.append(f"near_empty_body(text={text_len},html={html_size})")
                elif html_size > 5000 and text_len < 300:
                    total += 2
                    reasons.append(f"sparse_text(text={text_len},html={html_size})")
                elif html_size > 50000 and text_len > 0:
                    # Stosunek tekstu do HTML < 2% przy dużym HTML — serwer zwrócił layout/menu
                    # zamiast treści dokumentu. Dotyczy każdego CMS który serwuje stronę główną
                    # niezależnie od parametrów (np. bip.lubelskie.pl z action=details).
                    ratio = text_len / html_size
                    if ratio < 0.02:
                        total += 3
                        reasons.append(f"low_text_ratio({ratio:.3f},text={text_len},html={html_size})")
        except Exception:
            pass

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

        try:
            s = _get_soup()
            if s:
                title_tag = s.find("title")
                title_text = (title_tag.get_text(strip=True) if title_tag else "")
                if not title_text or len(title_text) < 5:
                    total += 1
                    reasons.append("no_title")
        except Exception:
            pass

        if total >= 1:
            url_low = (url or "").lower()
            dynamic_url_hints = ["/#/", "/#!/", "/_next/", "/__nuxt/", "/static/js/"]
            if any(h in url_low for h in dynamic_url_hints):
                total += 2
                reasons.append("dynamic_url_pattern")

        return total, reasons

    def is_dynamic(self, html: str, url: str = "", kind: str = "html", status: int = None) -> tuple:
        score, reasons = self.score(html, url, kind, status)
        return score >= DYNAMIC_SCORE_THRESHOLD, score, reasons


dynamic_detector = DynamicPageDetector()


# ===================== PLAYWRIGHT — fetch z treścią =====================

async def fetch_with_playwright(url: str, interact: bool = False) -> tuple:
    """
    Pobiera pojedynczą stronę przez Playwright, zwraca wyrenderowany HTML.
    Zwraca 8-elementową krotkę: (html, final_url, kind, status, ctype, err, ms, {})
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None, url, "exc", None, "", "playwright_not_installed", 0, {}

    async with async_playwright() as p:
        browser = None
        page = None
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-setuid-sandbox",
                    "--ignore-certificate-errors",
                    "--disable-blink-features=AutomationControlled",
                ]
            )
            page = await browser.new_page()
            await page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })
            await page.route(
                "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,css}",
                lambda r: r.abort()
            )

            t0 = time.time()
            # [v2.25] load zamiast networkidle — BIP lubelskie.pl ma ciagle XHR/polling
            # ktore nigdy nie osiagaja networkidle, przez co goto timeout'uje lub zbiera
            # pusty DOM. Po load czekamy jawnie az DataTables wypelni tabele.
            try:
                await page.goto(url, wait_until="load", timeout=45000)
            except Exception:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            if interact:
                # Czekaj az tbody wypelni sie wierszami (DataTables/AJAX)
                try:
                    await page.wait_for_selector("tbody tr", timeout=8000)
                except Exception:
                    pass
                # Dodatkowe scrollowanie + czas na AJAX
                for _ in range(3):
                    await page.evaluate("window.scrollBy(0, document.body.scrollHeight)")
                    await asyncio.sleep(1.2)

            content = await page.content()
            final_url = page.url
            ms = round((time.time() - t0) * 1000)
            return content, final_url, "html", 200, "text/html", None, ms, {}

        except Exception as e:
            return None, url, "exc", None, "", str(e), 0, {}
        finally:
            if page:
                try: await page.close()
                except Exception: pass
            if browser:
                try: await browser.close()
                except Exception: pass


# ===================== [v2.23] _fetch_links_playwright — mini-BFS =====================

async def _fetch_links_playwright(url: str, allowed_host: str) -> set:
    """
    [v2.23] Zbiera linki przez Playwright używając mini-BFS (głębokość 1).

    Działa IDENTYCZNIE jak standardowy BFS dla HTML (iter_links_fast), ale
    zamiast aiohttp używa Playwright do renderowania stron JS.

    Algorytm:
    1. Załaduj stronę startową przez Playwright (networkidle)
    2. Przewiń stronę aby załadować lazy content
    3. Zbierz WSZYSTKIE <a href> z wyrenderowanego DOM + iframe + document_id z source
    4. Dla każdego nowego linka (allowed_host, not skip):
       - Odwiedź go Playwrightem (max PLAYWRIGHT_MINI_BFS_MAX_PAGES stron)
       - Zbierz kolejne <a href> z tej podstrony
    5. Zwróć kompletny zbiór canonicznych URL-i

    Brak klikania w losowe elementy — zamiast tego podążamy za linkami
    dokładnie jak standardowy crawler.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("    ⚠️ Playwright nie jest zainstalowany", flush=True)
        return set()

    found_links: set = set()
    # Kolejka do mini-BFS: (url, depth)
    bfs_queue: deque = deque()
    bfs_visited: set = set()

    cu_start = _canon(url)
    if cu_start:
        bfs_visited.add(cu_start)
    bfs_queue.append((url, 0))

    pages_crawled = 0

    async def _collect_links_from_playwright_page(pw_page, base_url: str) -> set:
        """
        Zbiera wszystkie dostępne linki z wyrenderowanej strony Playwright.
        Identyczna logika jak iter_links_fast, ale operuje na żywym DOM.
        Obejmuje: <a href>, atrybuty onclick/data-href, document_id, iframe.
        """
        collected = set()

        # --- 1. Standardowe <a href> z DOM ---
        try:
            hrefs = await pw_page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href || '').filter(h => h && !h.startsWith('javascript:') && !h.startsWith('mailto:') && !h.startsWith('tel:'))"
            )
            # [v2.25] Debug: ile linkow jest w DOM przed filtrowaniem
            if len(hrefs) == 0:
                raw_count = await pw_page.eval_on_selector_all("a", "els => els.length")
                raw_count = raw_count[0] if raw_count else 0
                tbody_rows = await pw_page.eval_on_selector_all("tbody tr", "els => els.length")
                tbody_rows = tbody_rows[0] if tbody_rows else 0
                # [v2.26] Dodatkowy debug: tytul i snippet body
                try:
                    _title = await pw_page.title()
                    _body_snip = await pw_page.evaluate("() => document.body ? document.body.innerText.slice(0,150).replace(/\n/g,' ') : 'NO_BODY'")
                    _page_url = pw_page.url
                except Exception:
                    _title, _body_snip, _page_url = "?", "?", base_url
                print(f"      [PW-DBG] a[href]=0 raw_a={raw_count} tbody_tr={tbody_rows}", flush=True)
                print(f"      [PW-DBG] title={_title!r} final_url={_page_url[:80]}", flush=True)
                print(f"      [PW-DBG] body={_body_snip!r}", flush=True)
            for href in hrefs:
                if not href: continue
                try:
                    abs_u = normalize_url(urljoin(base_url, href))
                    if not is_valid_url(abs_u): continue
                    if not _host_allowed(urlparse(abs_u).netloc, allowed_host): continue
                    if should_skip_href(abs_u): continue
                    cu = _canon(abs_u)
                    if cu: collected.add(cu)
                except Exception:
                    continue
        except Exception:
            pass

        # --- 2. document_id z całego source (dla systemów BIP z AJAX) ---
        try:
            page_source = await pw_page.content()
            doc_ids = set(re.findall(r'document_id[=\'":\s]+(\d+)', page_source, re.IGNORECASE))
            if doc_ids:
                parsed = urlparse(base_url)
                base_no_query = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
                base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
                for doc_id in doc_ids:
                    for base in (base_no_query, base_root):
                        detail_url = f"{base}?action=details&document_id={doc_id}"
                        cu = _canon(detail_url)
                        if cu and _host_allowed(urlparse(cu).netloc, allowed_host):
                            collected.add(cu)
        except Exception:
            pass

        # --- 3. onclick / data-href / data-url —linki w atrybutach JS ---
        try:
            js_attrs = await pw_page.eval_on_selector_all(
                "[onclick], [data-href], [data-url]",
                """els => els.map(e => ({
                    onclick: e.getAttribute('onclick') || '',
                    dataHref: e.getAttribute('data-href') || '',
                    dataUrl: e.getAttribute('data-url') || ''
                }))"""
            )
            for attrs in js_attrs:
                for val in (attrs.get("onclick",""), attrs.get("dataHref",""), attrs.get("dataUrl","")):
                    if not val: continue
                    # Wyciągnij URL-e z wartości atrybutu
                    for m in re.findall(r"['\"]([^'\"]*?(?:[?&][^'\"]*|/[^'\"]+))['\"]", val):
                        try:
                            abs_u = normalize_url(urljoin(base_url, m))
                            if not is_valid_url(abs_u): continue
                            if not _host_allowed(urlparse(abs_u).netloc, allowed_host): continue
                            if should_skip_href(abs_u): continue
                            cu = _canon(abs_u)
                            if cu: collected.add(cu)
                        except Exception:
                            continue
        except Exception:
            pass

        # --- 4. iframe — zbierz linki z zagnieżdżonych ramek ---
        try:
            frames = pw_page.frames
            for frame in frames:
                if frame == pw_page.main_frame: continue
                try:
                    frame_hrefs = await frame.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href || '').filter(h => h && !h.startsWith('javascript:'))"
                    )
                    for href in frame_hrefs:
                        try:
                            abs_u = normalize_url(urljoin(base_url, href))
                            if not is_valid_url(abs_u): continue
                            if not _host_allowed(urlparse(abs_u).netloc, allowed_host): continue
                            if should_skip_href(abs_u): continue
                            cu = _canon(abs_u)
                            if cu: collected.add(cu)
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

        return collected

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-setuid-sandbox",
                    "--ignore-certificate-errors",  # jak ssl=False w aiohttp
                    "--disable-blink-features=AutomationControlled",
                ]
            )

            while bfs_queue and pages_crawled < PLAYWRIGHT_MINI_BFS_MAX_PAGES:
                current_url, depth = bfs_queue.popleft()
                page = None

                try:
                    page = await browser.new_page()
                    await page.set_extra_http_headers({
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    })
                    await page.route(
                        "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,css}",
                        lambda r: r.abort()
                    )

                    # [v2.26] goto z logowaniem bledow — SSL ignore + bot bypass headers
                    _goto_ok = False
                    _goto_err = None
                    for _wait in ("load", "domcontentloaded"):
                        try:
                            await page.goto(current_url, wait_until=_wait, timeout=30000)
                            _goto_ok = True
                            break
                        except Exception as _ge:
                            _goto_err = _ge
                    if not _goto_ok:
                        print(f"      [PW-DBG] goto FAIL: {str(_goto_err)[:120]} url={current_url[:60]}", flush=True)
                        pages_crawled += 1
                        continue

                    # Czekaj az tbody wypelni sie wierszami (DataTables inicjalizacja)
                    try:
                        await page.wait_for_selector("tbody tr", timeout=8000)
                    except Exception:
                        pass

                    # Scrollowanie + czas na doladowanie lazy content
                    for _ in range(2):
                        try:
                            await page.evaluate("window.scrollBy(0, document.body.scrollHeight)")
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)

                    final_url = page.url
                    pages_crawled += 1

                    # Zbierz linki z tej strony
                    page_links = await _collect_links_from_playwright_page(page, final_url)
                    new_links = page_links - found_links
                    found_links.update(page_links)

                    print(
                        f"    🎭 PW mini-BFS p={pages_crawled} depth={depth} "
                        f"links_here={len(page_links)} new={len(new_links)} "
                        f"total={len(found_links)} url={current_url[:60]}",
                        flush=True
                    )

                    # Dodaj nowe linki do BFS (głębokość +1) — tylko jeśli to strony HTML
                    # (nie pliki, nie zbyt długie URL-e)
                    for cu in new_links:
                        if cu in bfs_visited: continue
                        if any(cu.lower().endswith(ext) for ext in ATT_EXT): continue
                        bfs_visited.add(cu)
                        # depth=0: odwiedzamy podstrony znalezione na stronie startowej
                        # depth=1: odwiedzamy linki z podstron (jeśli PLAYWRIGHT_MINI_BFS_MAX_PAGES pozwala)
                        if depth < 1:
                            bfs_queue.append((cu, depth + 1))

                except Exception as e:
                    print(f"    ⚠️ PW mini-BFS error @ {current_url[:60]}: {str(e)[:80]}", flush=True)
                finally:
                    if page:
                        try: await page.close()
                        except Exception: pass

        except Exception as e:
            print(f"    ❌ PW mini-BFS fatal: {e}", flush=True)
        finally:
            if browser:
                try: await browser.close()
                except Exception: pass

    print(
        f"    🎭 PW mini-BFS DONE: pages={pages_crawled} total_links={len(found_links)} "
        f"start={url[:60]}",
        flush=True
    )
    return found_links


# ===================== PLAYWRIGHT — pełny BFS (zachowany z v2.22) =====================

async def playwright_bfs(
    start_url: str,
    allowed_host: str,
    max_depth: int,
    diag: dict,
    existing_visited: set = None,
) -> set:
    """Pełny równoległy BFS przez Playwright (używany tylko jeśli Phase1 całkowicie fail)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        diag["notes"].append("PLAYWRIGHT_BFS_SKIP: playwright not installed")
        return set()

    if existing_visited is None:
        existing_visited = set()

    found_urls = set()
    visited = set(existing_visited)
    queue = deque()

    cu_start = _canon(start_url)
    if cu_start: visited.add(cu_start)
    queue.append((start_url, 0))

    pages_crawled = 0
    pages_failed = 0
    t0 = time.time()

    print(f"  🎭 Playwright BFS start: {start_url} (max_depth={max_depth})", flush=True)

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(headless=True)

            while queue and not state.shutdown_requested:
                url_bfs, depth = queue.popleft()
                if depth > max_depth:
                    cu = _canon(url_bfs)
                    if cu: found_urls.add(cu)
                    continue

                page = None
                try:
                    page = await browser.new_page()
                    await page.route(
                        "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot}",
                        lambda r: r.abort()
                    )
                    # [v2.25] load zamiast networkidle
                    try:
                        await page.goto(url_bfs, wait_until="load", timeout=45000)
                    except Exception:
                        await page.goto(url_bfs, wait_until="domcontentloaded", timeout=30000)
                    try:
                        await page.wait_for_selector("tbody tr", timeout=8000)
                    except Exception:
                        pass
                    try:
                        await page.wait_for_selector("a[href]", timeout=8000)
                    except Exception:
                        pass

                    final_url = page.url
                    pages_crawled += 1

                    raw_links = await page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => ({href: e.href, text: e.innerText || e.textContent || ''}))"
                    )

                    for link_obj in raw_links:
                        try:
                            href = (link_obj.get("href") or "").strip()
                            if not href or href.startswith(("mailto:", "tel:", "javascript:")): continue
                            abs_u = normalize_url(urljoin(final_url, href))
                            if not is_valid_url(abs_u): continue
                            if not _host_allowed(urlparse(abs_u).netloc, allowed_host): continue
                            if should_skip_href(abs_u): continue
                            cu = _canon(abs_u)
                            if not cu or cu in visited: continue
                            visited.add(cu)
                            found_urls.add(cu)
                            if depth + 1 <= max_depth:
                                queue.append((abs_u, depth + 1))
                        except Exception:
                            continue

                except Exception as e:
                    pages_failed += 1
                    if pages_failed <= 5:
                        print(f"  ⚠️  Playwright BFS error @ {url_bfs}: {str(e)[:80]}", flush=True)
                finally:
                    if page:
                        try: await page.close()
                        except Exception: pass

        except Exception as e:
            diag["notes"].append(f"PW_BFS_FATAL: {str(e)[:100]}")
        finally:
            if browser:
                try: await browser.close()
                except Exception: pass

    elapsed = round((time.time() - t0) / 60, 1)
    diag["notes"].append(f"PW_BFS pages={pages_crawled} failed={pages_failed} found={len(found_urls)} time={elapsed}min")
    diag["counts"]["pw_bfs_pages"] = pages_crawled
    diag["counts"]["pw_bfs_found"] = len(found_urls)
    return found_urls


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
    if last_exc: raise last_exc

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
            f"BIP WATCHER v2.41 SUMMARY @ {now_iso()}",
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


def append_hits_to_backup(items: list):
    """[v2.36] Dopisuje znalezione ogłoszenia do pliku JSONL — backup gdy email zawiedzie
    lub job zostanie przerwany. Plik rośnie między runami, można go przeglądać ręcznie."""
    if not items:
        return
    try:
        def _do():
            with open(HITS_BACKUP_FILE, "a", encoding="utf-8") as f:
                for item in items:
                    f.write(json.dumps({"ts": now_iso(), "item": item}, ensure_ascii=False) + "\n")
        retry_io(_do, tries=4, base_sleep=0.3)
        print(f"💾 Hits backup: +{len(items)} wpisów → {HITS_BACKUP_FILE}", flush=True)
    except Exception as ex:
        print(f"⚠️ hits backup failed: {ex}", flush=True)


def _try_send_email_sync():
    """[v2.36] Wysyła email synchronicznie — wywoływana z CancelledError, panic_save i main().
    Wysyła zawsze gdy są wyniki — NIE sprawdza shutdown_requested (to błąd z v2.35).
    Po udanym wysłaniu czyści listę żeby następny run nie wysyłał duplikatów."""
    if not ENABLE_EMAIL:
        return
    items = list(state.new_items_for_mail or [])
    if not items:
        print("📨 Email: brak wyników do wysłania.")
        return
    try:
        subject = (
            f"BIP WATCHER: {len(items)} nowych/zmienionych wpisów "
            f"({datetime.now().strftime('%Y-%m-%d %H:%M')})"
        )
        body = "\n\n".join(items[:1200])
        if len(items) > 1200:
            body += f"\n\n... truncated ({len(items)} total)"
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = EMAIL_TO
        msg["To"] = EMAIL_TO
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as srv:
            srv.send_message(msg)
        print(f"📨 Email: SENT ✅ ({len(items)} wpisów)")
        # [v2.36] Po wysłaniu czyść — żeby następny run nie wysyłał tych samych wyników
        state.new_items_for_mail.clear()
        state.mail_dedup.clear()
    except Exception as e:
        print(f"⚠️  Email failed: {e}")
        # Nie czyść listy — następny run spróbuje wysłać ponownie


def panic_save_checkpoint_sync(reason: str = "SIGTERM"):
    try:
        if not USE_CACHE: return
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
            out["new_items_for_mail"] = list(state.new_items_for_mail or [])  # [v2.36] backup
            filename = BASE_DIR / f"cache_shard_{shard}.json"
            tmp = str(filename) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
            os.replace(tmp, filename)
            print(f"🧯 PANIC SAVE (shard) OK [{reason}]: {filename}", flush=True)
        else:
            save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
            print(f"🧯 PANIC SAVE (cache.json) OK [{reason}]", flush=True)
        try:
            save_diag(state.diag_rows, state.diag_errors)
            print(f"🧯 PANIC SAVE (diag) OK [{reason}]", flush=True)
        except Exception as e:
            print(f"⚠️ PANIC diag save failed: {e}", flush=True)
        # [v2.36] Ostatnia deska ratunku — wyślij email z tym co zdążyliśmy zebrać
        try:
            write_summary(state.diag_rows, state.new_items_for_mail)
            _try_send_email_sync()
        except Exception as e:
            print(f"⚠️ PANIC email failed: {e}", flush=True)
    except Exception as e:
        print(f"⚠️ PANIC SAVE FAILED [{reason}]: {e}", flush=True)

import atexit
atexit.register(panic_save_checkpoint_sync, "atexit")


def normalize_url(url: str) -> str:
    try:
        # Dekoduj HTML entities i URL-encoded separatory przed parsowaniem.
        # Niektóre CMS-y generują: &amp;param=1 lub %26%3Bparam=1
        raw = url or ""
        raw = raw.replace("%26", "&").replace("%3B", ";")
        raw = raw.replace("&amp;", "&")
        p = urlparse(raw)
        # Zachowuj wszystkie parametry bez żadnej modyfikacji.
        # Filtrowanie hostów (exact match) zapewnia że nie wychodzimy poza BIP.
        # Jedyne co robimy to strip fragment (#...) który nie jest częścią URL dokumentu.
        return urlunparse(p._replace(fragment=""))
    except Exception:
        return url



def canonical_url(url: str) -> str:
    u = normalize_url((url or "").strip())
    try:
        p = urlparse(u)
        scheme = "https"
        netloc = (p.netloc or "").lower().strip()
        if netloc.startswith("www."): netloc = netloc[4:]
        path = p.path or "/"
        if path != "/" and path.endswith("/"): path = path[:-1]

        # [v2.39 Fix3] Pomiń wariant /xml — to samo co HTML (eksport XML Dmosin).
        segs = [s for s in path.split("/") if s]
        if segs and segs[-1].lower() == "xml":
            path = "/" + "/".join(segs[:-1]) if len(segs) > 1 else "/"

        # [v2.41 Fix3] Breadcrumb canonical dla WSZYSTKICH hostów.
        # Problem v2.39: warunek _is_strict_bip_host wykluczał wokiss.pl (Jarocin) i inne
        # shared providers → ten sam dokument pod N ścieżkami breadcrumba → eksplozja frontieru.
        # /a/b/c/930 i /x/y/c/930 → normalizuj do /c/930 dla każdego hosta.
        #
        # Zabezpieczenia przed fałszywą normalizacją dat w ścieżce:
        # 1. segs[-1] nie jest rokiem (1900-2099) — /archiwum/2024/3 → NIE normalizuj
        # 2. segs[-2] nie jest cyfrą — /2024/11 to data rok/miesiąc → NIE normalizuj
        segs = [s for s in path.split("/") if s]
        if len(segs) >= 3 and segs[-1].isdigit() and not segs[-2].isdigit():
            _n = int(segs[-1])
            if not (1900 <= _n <= 2099):  # nie jest rokiem
                path = "/" + segs[-2] + "/" + segs[-1]

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
        "page=", "strona=", "offset=", "limit=", "/rss", "/feed",
        "wyszuk", "szukaj", "search", "query=", "filter", "filtr",
        "ostatnio_dodane", "ostatnio_zaktualizowane",
        "/ogloszenia", "/obwieszczenia", "/planowanie", "/mpzp", "/studium",
        "/decyzje", "/uchwaly", "/prawo-miejscowe",
    ])

def is_phase1_listing(u: str) -> bool:
    return is_listing_url(u) or is_home_url(u)

def url_key(url: str) -> str:
    return sha1(canonical_url(url))

def migrate_content_seen_to_url_dedup(content_seen: dict):
    if not isinstance(content_seen, dict) or not content_seen: return
    added = 0
    for _k, meta in list(content_seen.items()):
        if not isinstance(meta, dict): continue
        url = meta.get("url")
        if not url: continue
        url_dedup = sha1(canonical_url(url))
        if url_dedup in content_seen: continue
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
    if not t or len(t) <= 2: return True
    return any(x in t for x in IGNORE_ANCHOR_TEXT)

def should_skip_href(abs_href: str) -> bool:
    u = (abs_href or "").lower()
    for pattern in IGNORE_URL_PATH_PATTERNS:
        if re.search(pattern, u): return True
    if url_is_ignored(u): return True
    if any(u.endswith(ext) for ext in BAD_EXT): return True
    if any(u.endswith(ext) for ext in ATT_EXT): return True
    return False

def base_domain(host: str) -> str:
    h = (host or "").lower().strip()
    if h.startswith("www."): h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2: return h
    if parts[-2] in {"com","net","org","gov","edu"} and parts[-1] in {"pl","uk"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def same_base_domain(host_a: str, host_b: str) -> bool:
    if not host_a or not host_b: return False
    a = host_a.lower().strip()
    b = host_b.lower().strip()
    if a.startswith("www."): a = a[4:]
    if b.startswith("www."): b = b[4:]
    if a == b: return True
    return base_domain(a) == base_domain(b)

def _host_allowed(netloc: str, allowed_host: str) -> bool:
    """
    [v2.41 Fix2] Exact host match dla WSZYSTKICH — bez wyjątków.
    Problem v2.40: same_base_domain("sp2.gostyn.pl", "biuletyn.gostyn.pl") = True
    → szkoły, cmentarze, licea wpadały do frontieru gdy BIP jest na subdomenie.
    Rozwiązanie: zawsze exact match. www. nadal akceptowane.
    Universalne: działa dla każdej gminy bez list wyjątków.
    """
    h = (netloc or "").lower().strip()
    ah = (allowed_host or "").lower().strip()
    if not h or not ah: return False
    return h == ah or h == "www." + ah or "www." + h == ah

# [v2.40] Shared BIP providers — każda gmina siedzi pod własną subdomeną providera.
# Crawler powinien być przypięty do konkretnej subdomeny gminy, nie do całej domeny bazowej.
# Np. ugobsza.bip.lubelskie.pl → akceptuj TYLKO ugobsza.bip.lubelskie.pl
#     gminabojanowo.biuletyn.net → akceptuj TYLKO gminabojanowo.biuletyn.net
_SHARED_BIP_PROVIDERS = {
    "biuletyn.net", "bip.net.pl", "bip.lubelskie.pl",
    "ssdip.bip.gov.pl", "finn.pl", "madkom.pl", "wokiss.pl",
    "bip.info.pl", "bip.gov.pl",
}

def _is_shared_bip_provider(host: str) -> bool:
    """Zwraca True jeśli host jest subdomieną known shared BIP providera."""
    h = (host or "").lower().strip()
    bd = base_domain(h)
    return any(h.endswith("." + p) or h == p or bd == p for p in _SHARED_BIP_PROVIDERS)

def _is_strict_bip_host(host: str) -> bool:
    """
    [v2.38] Zwraca True jeśli host to dedykowana subdomena BIP-u.
    Wtedy crawler NIE powinien wychodzić na główną domenę gminy.
    Przykłady True:  bip.miastonowydwor.pl, bip.gminaketrzyn.pl, bip3.wokiss.pl
    Przykłady False: gminaczarna.biuletyn.net, ugdolhobyczow.bip.lubelskie.pl,
                     www.granowo.pl, ssdip.bip.gov.pl
    Reguła: host zaczyna się od 'bip' (bip., bip2., bip3. itp.)
            ORAZ domena bazowa NIE jest zewnętrznym providerem BIP.
    """
    h = (host or "").lower().strip()
    bd = base_domain(h)
    if any(h.endswith(p) or bd == p for p in _SHARED_BIP_PROVIDERS):
        return False
    # subdomena zaczyna się od 'bip' (bip., bip2., bip3.)
    sub = h.split(".")[0] if "." in h else ""
    return bool(sub) and sub.startswith("bip")

def _is_bip_domain(host: str) -> bool:
    """
    [v2.39 Fix8] Zwraca True jeśli host wygląda jak BIP — uwzględnia różne warianty.
    Używane do filtrowania wyników emaila — zbieramy ogłoszenia TYLKO z BIP.

    Warianty BIP w Polsce:
      - bip.gmina.pl            (subdomena bip.*)
      - gmina.bip.gov.pl        (pod bip.gov.pl)
      - gmina.biuletyn.net      (biuletyn.net)
      - ugdolhobyczow.bip.lubelskie.pl
      - wokiss.pl, madkom.pl    (shared providers)
      - finn.pl                 (shared provider)
    """
    h = (host or "").lower().strip()
    if not h:
        return False
    # Subdomena zaczyna się od bip lub biuletyn
    sub = h.split(".")[0] if "." in h else h
    if sub.startswith("bip") or sub == "biuletyn":
        return True
    # Znane shared BIP providers
    _BIP_PROVIDERS = {
        "biuletyn.net", "bip.net.pl", "bip.lubelskie.pl",
        "ssdip.bip.gov.pl", "finn.pl", "madkom.pl", "wokiss.pl",
        "bip.info.pl", "bip.gov.pl",
    }
    bd = base_domain(h)
    if any(h.endswith(p) or bd == p for p in _BIP_PROVIDERS):
        return True
    # Fragment "bip" w pierwszym segmencie domeny (ebip.*, bipgmina.*, itp.)
    if "bip" in sub:
        return True
    return False


def make_allow_url_fn(allowed_host: str):
    """
    [v2.41 Fix2] Exact host match dla WSZYSTKICH — jeden mechanizm, zero list wyjątków.

    Problem v2.40: trzy tryby (strict/pinned/same_base_domain) — trzeci tryb używał
    same_base_domain → sp2.gostyn.pl, lo.strzegom.pl, cmentarze.strzegom.pl wpadały
    do frontieru bo dzieliły domenę bazową z BIP-em gminy.

    Rozwiązanie: zawsze exact match niezależnie od typu hosta.
    www. nadal akceptowane w obu kierunkach.
    Logowanie 🔒 dla wszystkich — crawler zawsze jest przypięty do jednego hosta.
    """
    ah = (allowed_host or "").lower().strip()

    def allow_url(u: str) -> bool:
        h = urlparse(u).netloc.lower()
        return h == ah or h == "www." + ah or "www." + h == ah

    return allow_url, True  # zawsze True — zawsze logujemy 🔒

def safe_soup(html: str):
    if not html: return None
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return None

def cache_mark_url(u: str):
    if not USE_CACHE: return
    if is_phase1_listing(u): return
    h = url_key(u)
    state.urls_seen.add(h)
    if isinstance(state.raw_cache, dict):
        d = state.raw_cache.setdefault("urls_seen", {})
        if isinstance(d, dict): d[h] = now_iso()

# ===================== SITEMAP + ROBOTS =====================
def detect_js_app(html: str) -> bool:
    if not html: return False
    is_dyn, _, _ = dynamic_detector.is_dynamic(html)
    return is_dyn

def extract_sitemaps_from_robots(robots_text: str) -> list:
    out = []
    if not robots_text: return out
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
    if not text: return False
    low = text.lstrip().lower()
    return ("<urlset" in low[:4000]) or ("<sitemapindex" in low[:4000]) or ('xmlns="http://www.sitemaps.org' in low[:4000])

def parse_sitemap_xml(xml_text: str, base_url: str = "") -> tuple:
    urls = []
    children = []
    if not xml_text: return urls, children
    try:
        soup = BeautifulSoup(xml_text, "xml")
        for sm in soup.find_all("sitemap"):
            loc = sm.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u): children.append(normalize_url(u))
        for uel in soup.find_all("url"):
            loc = uel.find("loc")
            if loc and loc.get_text(strip=True):
                u = loc.get_text(strip=True)
                if is_valid_url(u): urls.append(normalize_url(u))
    except Exception:
        try:
            for m in re.findall(r"<loc>\s*(https?://[^<\s]+)\s*</loc>", xml_text, flags=re.IGNORECASE):
                if is_valid_url(m): urls.append(normalize_url(m))
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
    if timeout is None: timeout = START_TIMEOUT_FAST
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
                try: text = data.decode("utf-8", errors="ignore")
                except Exception: text = data.decode("latin-1", errors="ignore")
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

# ===================== TEXT EXTRACTION =====================
def _strip_dynamic_noise(txt: str) -> str:
    if not txt: return ""
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
        if not soup: return ""
        for tag in soup(["script", "style", "noscript"]): tag.decompose()
        has_main_content = bool(
            soup.find("main") or
            soup.find(id=re.compile(r"(content|tresc|main|article)", re.I)) or
            soup.find(class_=re.compile(r"(content|tresc|main|article)", re.I))
        )
        if has_main_content:
            for tag in soup(["nav", "header", "footer", "aside"]): tag.decompose()
        txt = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        txt = _strip_dynamic_noise(txt)
        return txt[:max_chars]
    except Exception:
        return ""

def extract_title_h1_h2(soup: BeautifulSoup):
    if not soup: return "", "", "", ""

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
# [v2.35] Tylko te rozszerzenia liczą się jako "zmiana załączników" w raporcie.
# Szeroka lista ATT_EXT pozostaje dla crawlingu (skip href, frontier).
ATT_SIG_EXT = (".pdf", ".gml", ".zip", ".doc", ".docx")

def attachments_signature(soup: BeautifulSoup, base_url: str) -> set:
    if not soup: return set()
    result = set()
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href: continue
        abs_u = normalize_url(urljoin(base_url, href))
        low = abs_u.lower()
        if not any(low.endswith(ext) for ext in ATT_SIG_EXT): continue
        p = urlparse(abs_u)
        netloc = p.netloc.lower()
        if netloc.startswith("www."): netloc = netloc[4:]
        clean_url = urlunparse(("https", netloc, p.path, "", "", ""))
        result.add(clean_url)
    return result

def att_sig_serialize(att_set: set) -> str:
    return json.dumps(sorted(att_set), ensure_ascii=False)

def att_sig_deserialize(stored) -> set:
    if not stored: return set()
    if isinstance(stored, set): return stored
    if isinstance(stored, list): return set(stored)
    if isinstance(stored, str):
        try:
            data = json.loads(stored)
            if isinstance(data, list): return set(data)
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
    if not n: return []
    if n.startswith("www."): return [n, n[4:]]
    return [n, "www." + n]

def candidate_start_urls(start_url: str):
    u0 = (start_url or "").strip()
    if not u0: return
    if not re.match(r"^[a-zA-Z]+://", u0): u0 = "https://" + u0
    u0 = normalize_url(u0)
    p0 = urlparse(u0)
    schemes = [p0.scheme] if p0.scheme else ["https", "http"]
    if "https" not in schemes: schemes.append("https")
    if "http" not in schemes: schemes.append("http")
    hosts = _www_variants(p0.netloc.lower() if p0.netloc else "")
    base_paths = [
        p0.path or "/", "/", "/bip/", "/BIP/", "/start", "/start.html",
        "/index.php", "/index.html", "/asp/start", "/asp/index.php",
        "/strona-glowna", "/strona_glowna", "/gmina", "/gmina.html",
        "/projekty-mpzp", "/projekty_mpzp", "/planowanie", "/planowanie-przestrzenne",
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
CACHE_SCHEMA = 18  # v2.28

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
        return _empty_cache(), set(), {}, {}, {}, {}, {}

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
            print(f"🔄 Migrating cache schema {c.get('schema')} -> {CACHE_SCHEMA}")
            c["schema"] = CACHE_SCHEMA
            c.setdefault("urls_seen", {})
            c.setdefault("content_seen", {})
            c.setdefault("gmina_seeds", {})
            c.setdefault("gmina_frontiers", {})
            c.setdefault("gmina_retry", {})
            c.setdefault("dead_urls", {})
            c.pop("page_fprints", None)

        def _ensure_dict(key):
            if not isinstance(c.get(key), dict): c[key] = {}
            return c[key]

        urls = _ensure_dict("urls_seen")
        content = _ensure_dict("content_seen")
        gseeds = _ensure_dict("gmina_seeds")
        gf = _ensure_dict("gmina_frontiers")
        gr = _ensure_dict("gmina_retry")
        dead = _ensure_dict("dead_urls")

        print(f"📦 Cache loaded: {len(urls)} URLs, {len(content)} content, {len(gseeds)} seeds, {len(gf)} frontiers")
        return c, set(urls.keys()), content, gseeds, gf, gr, dead

    except Exception as e:
        print(f"⚠️  Cache load error: {e}")
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}

def save_cache_v2(raw_cache, urls_seen_set, content_seen, gmina_seeds):
    out = {"schema": CACHE_SCHEMA}
    old_urls = (raw_cache or {}).get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    print(f"💾 save_cache_v2: urls={len(urls_seen_set)} content={len(content_seen or {})} seeds={len(gmina_seeds or {})}")
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
    print(f"💾 Cache saved: {len(urls_seen_set)} URLs, {len(out['content_seen'])} content")

def purge_old_cache(raw_cache: dict, urls_seen_set: set, content_seen: dict, gmina_seeds: dict, dead_urls: dict):
    cutoff = datetime.now() - timedelta(days=SCANNED_TTL_DAYS)
    urls_dict = raw_cache.get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    to_del = [h for h, ts in list(urls_dict.items()) if _ts_older_than(ts, cutoff)]
    for h in to_del:
        urls_seen_set.discard(h)
        urls_dict.pop(h, None)
    seed_cutoff = datetime.now() - timedelta(days=SEED_CACHE_TTL_DAYS)
    to_del_seeds = [k for k, meta in list((gmina_seeds or {}).items())
                    if _ts_older_than((meta or {}).get("ts", ""), seed_cutoff)]
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
                if not re.match(r"^[a-zA-Z]+://", url): url = "https://" + url
                rows.append((name, url))
    return rows

# ===================== DIAG =====================
def diag_new():
    return {
        "start_attempts": [], "start_matrix": [], "errors": [],
        "counts": defaultdict(int), "notes": [],
        "trace": {"phase": "", "last_url": "", "last_kind": "", "last_status": None, "last_ms": None},
    }

def diag_add_error(diag, gmina, url, stage, kind, status, err):
    diag["counts"][f"err_{kind}"] += 1
    if status: diag["counts"][f"status_{status}"] += 1
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
    print(f"   trace: phase={tr.get('phase')} kind={tr.get('last_kind')} status={tr.get('last_status')}")
    if diag.get("notes"):
        print(f"   notes: {' | '.join(diag['notes'])[:900]}")
    sa = diag.get("start_attempts", [])
    for i, x in enumerate(sa[:8], 1):
        print(f"   {i:02d}) kind={x.get('kind')} status={x.get('status')} url={x.get('try_url')[:100]}")

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
                try: text = data.decode("utf-8", errors="ignore")
                except Exception: text = data.decode("latin-1", errors="ignore")
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
                diag["start_matrix"].append({"ok": ok, "strategy": strategy_name, "url": url, "status": status})
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
    r"application/octet|application/zip|application/x-|image/|audio/|video/)",
    re.IGNORECASE
)

_BINARY_URL_SUFFIX_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|odt|rtf|zip|rar|7z|gml|tiff?|dwg|dxf|jpg|jpeg|png|gif|mp4|mp3)$"
    r"|pdf$|docx?$|xlsx?$",
    re.IGNORECASE
)

def _is_binary_response(ctype: str, data: bytes, url: str) -> bool:
    if _BINARY_CTYPE_RE.search(ctype or ""): return True
    if data and len(data) >= 4:
        header = data[:8]
        for magic in _BINARY_MAGIC:
            if header.startswith(magic): return True
    path = urlparse(url or "").path
    if path and _BINARY_URL_SUFFIX_RE.search(path.split("/")[-1]): return True
    return False

async def fetch_conditional(session: aiohttp.ClientSession, url: str, extra_headers: dict = None):
    """
    Fetch z obsługą conditional HTTP (etag, last-modified, 304).
    Zwraca 8-elementową krotkę: (html, final, kind, status, ctype, err, ms, resp_meta).
    """
    url = normalize_url(url)
    domain = urlparse(url).netloc
    parsed = urlparse(url)
    referer = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))

    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers(referer=referer)
            if extra_headers: headers.update(extra_headers)
            t0 = time.time()
            async with session.get(url, timeout=REQUEST_TIMEOUT, ssl=ssl_mode,
                                   allow_redirects=True, headers=headers) as resp:
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
                try: text = data.decode("utf-8", errors="ignore")
                except Exception: text = data.decode("latin-1", errors="ignore")
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
    if not meta: return None
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
        "allowed_host": allowed_host, "start_final": start_final,
        "seeds": seeds, "ts": now_iso()
    }

# ===================== LINK EXTRACTION =====================
def iter_links_fast(soup: BeautifulSoup, base_url: str):
    """Standardowa ekstrakcja linków z HTML (aiohttp path)."""
    yielded = set()
    try: all_links = soup.find_all("a", href=True)
    except Exception: all_links = []
    for a in all_links:
        try:
            href = (a.get("href") or "").strip()
            if not href: continue
            abs_u = normalize_url(urljoin(base_url, href))
            if not is_valid_url(abs_u): continue
            txt = a.get_text(" ", strip=True)
            is_attachment = any(abs_u.lower().endswith(ext) for ext in ATT_EXT)
            if should_skip_href(abs_u) and not is_attachment: continue
            if abs_u in yielded: continue
            yielded.add(abs_u)
            yield abs_u, txt
        except Exception:
            continue

# ===================== POMOCNICZE — stan cyklu gminy =====================

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
# PHASE 1 — Adaptacyjny BFS z automatycznym Playwright fallback (v2.23)
# ============================================================

def _extract_links_from_html(html: str, base_url: str, allowed_host: str) -> set:
    """Wyciąga wewnętrzne linki z surowego HTML przez aiohttp. Zwraca zbiór canonicznych URL."""
    links = set()
    soup = safe_soup(html)
    if not soup: return links
    for abs_u, txt in iter_links_fast(soup, base_url):
        if not _host_allowed(urlparse(abs_u).netloc, allowed_host): continue
        cu = _canon(abs_u)
        if cu: links.add(cu)
    return links


def _html_visible_text_len(html: str) -> int:
    """Szybkie przybliżenie długości widocznego tekstu w HTML."""
    soup = safe_soup(html)
    if not soup: return 0
    for tag in soup(["script", "style", "noscript"]): tag.decompose()
    return len(re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip())


def _needs_playwright_for_links(html: str, url: str, aiohttp_links_count: int) -> tuple[bool, str]:
    """
    [v2.23] Automatyczna decyzja: czy ta strona potrzebuje Playwright do zbierania linków?
    
    Kryteria (każde wystarczy):
    1. DynamicPageDetector wykrył JS (score >= threshold)
    2. Za mało linków z aiohttp (< PHASE1_MIN_LINKS_FOR_PW)
    3. HTML jest duży ale widocznego tekstu mało (SPA pattern)
    
    NIE używamy hardcodowanych list URL hints — decyzja opiera się wyłącznie
    na analizie pobranego HTML, co jest bardziej niezawodne.
    """
    if not html:
        return True, "no_html"

    # Kryterium 1: DynamicPageDetector
    is_dyn, dyn_score, dyn_reasons = dynamic_detector.is_dynamic(html=html, url=url)
    if is_dyn:
        return True, f"js_detected(score={dyn_score},reasons={dyn_reasons[:2]})"

    # Kryterium 2: Za mało linków — strona może renderować listę przez JS
    if aiohttp_links_count < PHASE1_MIN_LINKS_FOR_PW:
        return True, f"few_links({aiohttp_links_count}<{PHASE1_MIN_LINKS_FOR_PW})"

    # Kryterium 3: Duży HTML, mało tekstu — wzorzec SPA/lazy rendering
    if len(html) > 8000:
        text_len = _html_visible_text_len(html)
        if text_len < 300:
            return True, f"spa_pattern(html={len(html)},text={text_len})"

    # [v2.24] Kryterium 4: pusta tabela AJAX
    # bip.lubelskie.pl - tabela ogloszen ladowana przez DataTables/XHR.
    try:
        soup_check = safe_soup(html)
        if soup_check:
            for table in soup_check.find_all("table"):
                tbody = table.find("tbody")
                if tbody is not None:
                    rows = tbody.find_all("tr")
                    tbody_txt = re.sub(r"\s+", " ", tbody.get_text(" ", strip=True)).strip()
                    if len(rows) == 0 or len(tbody_txt) < 20:
                        return True, f"empty_ajax_table(rows={len(rows)},text={len(tbody_txt)})"
    except Exception:
        pass

    # [v2.24] Kryterium 5: sygnaly AJAX bez document_id w source
    _html_lk5 = html.lower()
    _ajax_sigs_k5 = ["datatables", "datatable", "ajax.reload", "ajax: {", "ajax:{",
                     "datatables.net", "table.ajax", "loadingoverlay", "$.ajax("]
    _has_ajax_k5 = any(sig in _html_lk5 for sig in _ajax_sigs_k5)
    _has_docid_k5 = "document_id=" in html or "document_id:" in html
    if _has_ajax_k5 and not _has_docid_k5:
        return True, "ajax_signals_no_docid"

    return False, "html_ok"


async def phase1_full_crawl(
    gmina: str,
    start_url: str,
    session_default,
    session_ipv4,
    session_crawl,
    diag,
) -> tuple:
    """
    Phase1 v2.23 — adaptacyjny BFS z automatycznym Playwright fallback.
    
    Dla każdej strony w BFS:
    1. Pobierz przez aiohttp
    2. Uruchom _needs_playwright_for_links() na wyniku
    3. Jeśli tak → uruchom _fetch_links_playwright() (mini-BFS przez Playwright)
    4. Połącz linki z obu źródeł → frontier Phase2
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

    for su in candidate_start_urls(start_url):
        if (time.time() - start_time) > START_TOTAL_TIMEOUT_SEC:
            diag["notes"].append(f"START_TIMEOUT after {int(time.time()-start_time)}s")
            break
        if state.shutdown_requested: break
        tried += 1
        if tried > START_MAX_TRIES: break

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

    # [v2.38] strict mode dla dedykowanych subdomen bip.*
    allow_url, _strict_bip = make_allow_url_fn(allowed_host)
    if _strict_bip:
        _mode = "strict BIP" if _is_strict_bip_host(allowed_host) else "pinned shared BIP"
        print(f"  🔒 [Phase1] {_mode} [{gmina}]: tylko {allowed_host}", flush=True)

    seeds = {}
    visited = set()
    q = deque()

    # Sitemap
    try:
        sitemap_urls = await collect_sitemap_urls(session_crawl, base_site, diag, max_urls=5000)
        sitemap_added = 0
        for u in sitemap_urls:
            if allow_url(u) and not should_skip_href(u):
                cu = _canon(u)
                if cu:
                    score = 20 if any(h in u.lower() for h in LISTING_URL_HINTS) else 10
                    seeds[cu] = max(seeds.get(cu, 0), score)
                    if cu not in visited: visited.add(cu)
                    sitemap_added += 1
        diag["notes"].append(f"SITEMAP_SEEDS={sitemap_added}")
        print(f"  🗺️  Sitemap [{gmina}]: {sitemap_added} URL", flush=True)
    except Exception as ex:
        diag["notes"].append(f"SITEMAP_FAILED: {str(ex)[:80]}")

    cu0 = _canon(final0)
    if cu0 not in visited: visited.add(cu0)
    q.appendleft((final0, 0))
    seeds[cu0] = seeds.get(cu0, 5)

    pages_crawled = 0
    pw_fetches = 0
    pw_extra_links = 0
    home_links: set = set()
    home_text_for_phase2: str = ""

    print(
        f"  🕷️  BFS [{gmina}] @ {allowed_host} "
        f"sitemap_seeds={len(seeds)} max_depth={PHASE1_MAX_DEPTH}",
        flush=True
    )

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

        result = await fetch_conditional(session_crawl, url)
        html, final, kind, status, ctype, err, ms, resp_meta = result

        if kind != "html" or not html:
            cu = _canon(url)
            if cu and not any(url.lower().endswith(ext) for ext in ATT_EXT):
                seeds[cu] = seeds.get(cu, 1)
            diag_add_error(diag, gmina, url, "phase1_bfs", kind, status, err)
            continue

        pages_crawled += 1

        # --- Linki przez aiohttp ---
        aiohttp_links = _extract_links_from_html(html, final, allowed_host)

        # --- Zbierz home data (depth=0) ---
        if depth == 0 and not home_links:
            home_links = set(aiohttp_links)
            try:
                _sh = safe_soup(html)
                if _sh:
                    for _t in _sh(["script", "style", "noscript"]): _t.decompose()
                    home_text_for_phase2 = re.sub(r"\s+", " ", _sh.get_text(" ", strip=True)).strip()
            except Exception:
                home_text_for_phase2 = ""
            print(f"  🏠 [{gmina}] home_links={len(home_links)} home_text={len(home_text_for_phase2)}ch", flush=True)

        # --- [v2.23] Automatyczna decyzja czy użyć Playwright ---
        use_pw, pw_reason = _needs_playwright_for_links(html, final, len(aiohttp_links))

        # Debug dla pierwszych 30 stron
        if pages_crawled <= 30:
            try:
                _lnk_dbg = len(safe_soup(html).find_all("a", href=True)) if safe_soup(html) else 0
                _txt_dbg = _html_visible_text_len(html)
            except Exception:
                _lnk_dbg = 0
                _txt_dbg = 0
            print(
                f"  📄 [{gmina}] p={pages_crawled} depth={depth} "
                f"html={len(html)}B text={_txt_dbg}ch aiohttp_links={len(aiohttp_links)} "
                f"use_pw={use_pw} pw_reason={pw_reason} url={url[:70]}",
                flush=True
            )

        # --- [v2.28] Playwright dla linkow — pobierz TYLKO te strone, bez mini-BFS ---
        # Glowny BFS sam odwiedzi kazdy znaleziony link (przez aiohttp lub PW).
        # Nie potrzebujemy osobnego sub-crawlera — to bylo zrodlem petli i eksplozji.
        pw_links = set()
        if use_pw:
            if pw_fetches >= PHASE1_MAX_PW_FETCHES:
                use_pw = False
                pw_reason = f"limit_reached({pw_fetches}>={PHASE1_MAX_PW_FETCHES})"
        if use_pw:
            pw_fetches += 1
            print(
                f"  🎭 [{gmina}] PW fetch-for-links @ depth={depth} "
                f"reason={pw_reason} url={url[:70]}",
                flush=True
            )
            try:
                pw_html, pw_final, pw_kind, _, _, pw_err, pw_ms, _ = await fetch_with_playwright(
                    final or url, interact=True
                )
                if pw_html:
                    pw_links = _extract_links_from_html(pw_html, pw_final or final or url, allowed_host)
                    new_from_pw = len(pw_links - aiohttp_links)
                    pw_extra_links += new_from_pw
                    print(
                        f"  🎭 PW links: {len(pw_links)} ({new_from_pw} nowych) "
                        f"html={len(pw_html)}B ms={pw_ms} @ {url[:60]}",
                        flush=True
                    )
                    diag["counts"]["pw_mini_bfs_calls"] = int(diag["counts"].get("pw_mini_bfs_calls", 0)) + 1
                    diag["counts"]["pw_mini_bfs_extra_links"] = int(diag["counts"].get("pw_mini_bfs_extra_links", 0)) + new_from_pw
                else:
                    print(f"  🎭 PW fetch-for-links: brak HTML ({pw_err}) @ {url[:60]}", flush=True)
            except Exception as ex:
                diag["notes"].append(f"PW_ERR {url[:50]}: {str(ex)[:60]}")
                print(f"    ⚠️ PW fetch-for-links error: {ex}", flush=True)

        # --- Połącz linki z obu źródeł ---
        all_links = aiohttp_links | pw_links

        for cu in all_links:
            if not cu or not allow_url(cu): continue
            if any(cu.lower().endswith(ext) for ext in ATT_EXT): continue
            ul = cu.lower()
            score = 15 if any(h in ul for h in LISTING_URL_HINTS) else 1
            seeds[cu] = max(seeds.get(cu, 0), score)
            if cu not in visited:
                visited.add(cu)
                q.append((cu, depth + 1))

        if pages_crawled % 100 == 0:
            elapsed = round((time.time() - start_time) / 60, 1)
            print(
                f"  🕷️  BFS [{gmina}] pages={pages_crawled} seeds={len(seeds)} "
                f"q={len(q)} depth={depth} pw_fetches={pw_fetches} time={elapsed}min",
                flush=True
            )

        # [v2.31] Frontier checkpoint co 500 stron Phase1 — zabezpieczenie przed
        # przerwaniem joba przez GitHub Actions timeout (325min).
        # save_shard_cache_and_commit zapisuje na dysk; YAML (if: always()) pushuje do git.
        if pages_crawled % PHASE1_FRONTIER_CHECKPOINT_EVERY == 0 and pages_crawled > 0 and allowed_host:
            _p1_gkey = gmina_cache_key(gmina, "https://" + allowed_host)
            _partial_urls = sorted(seeds.keys(), key=lambda u: -seeds.get(u, 0))
            async with state.cache_lock:
                state.gmina_frontiers[_p1_gkey] = [[u, 0] for u in _partial_urls]
            await save_shard_cache_and_commit()
            print(
                f"  💾 Phase1 checkpoint [{gmina}]: seeds={len(_partial_urls)} p={pages_crawled}",
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
        "home_links_list": list(home_links),
        "home_text": home_text_for_phase2,
    }


# ============================================================
# PHASE 2 — content check + Playwright fallback dla treści (v2.23)
# ============================================================

def _extract_content_text(soup_orig, url: str, home_text: str = "") -> tuple:
    """
    Wyciąga tekst TYLKO z treści strony, z pominięciem menu nawigacyjnego.
    Zachowana bez zmian z v2.22 (FIX 2 już zawarty).
    """
    import copy

    _ul = (url or "").lower()
    _is_detail = "action=details" in _ul or "document_id=" in _ul

    all_headings = " ".join(
        re.sub(r"\s+", " ", t.get_text(" ", strip=True))
        for t in soup_orig.find_all(["h1", "h2", "h3", "h4", "h5"])
    )

    full_text_raw = re.sub(r"\s+", " ", soup_orig.get_text(" ", strip=True)).strip()

    # Strategia 1: Strony DETAIL — szukaj sekcji "Szczegóły dokumentu"
    if _is_detail:
        anchor = None
        for tag in soup_orig.find_all(["h1", "h2", "h3", "h4"]):
            txt = (tag.get_text(" ", strip=True) or "").lower()
            if "szczeg" in txt and "dokument" in txt:
                anchor = tag
                break
        if anchor:
            parts = [anchor.get_text(" ", strip=True)]
            for sib in anchor.find_next_siblings():
                parts.append(sib.get_text(" ", strip=True))
            content = re.sub(r"\s+", " ", " ".join(parts)).strip()
            if len(content) > 50:
                return f"{all_headings} {content}", len(full_text_raw) - len(content), "detail_section"

    # Strategia 2: Główny kontener treści
    for sel in [
        "#content", "#tresc", "#main-content", ".content", ".tresc",
        "main", "article", "[role='main']", "#page-content",
        ".article-content", ".entry-content", ".post-content",
        "#s3_content", "#s3content", "#content-div", ".document-content",
        ".field-items", ".field--name-body",
        "#print-content", ".print-content",
        ".bip-content", "#bip-content",
        "#middle-column", "#right-column", "#left-column",
        ".main-content", ".page-content", ".entry-content",
        ".post-body", ".article-body", ".node-content",
        ".view-content", ".views-field",
        "#dokument", "#dokumenty", ".dokument",
        "td.content", "div.content",
    ]:
        try:
            node = soup_orig.select_one(sel)
            if node:
                node_text = re.sub(r"\s+", " ", node.get_text(" ", strip=True)).strip()
                if len(node_text) > 200:
                    removed = len(full_text_raw) - len(node_text)
                    return f"{all_headings} {node_text}", removed, f"sel:{sel}"
        except Exception:
            continue

    # Strategia 3: Usuń nav/header/footer/aside
    soup2 = copy.copy(soup_orig)
    removed_tags = 0
    for tag in soup2.find_all(["nav", "header", "footer", "aside"]):
        tag.decompose()
        removed_tags += 1
    if removed_tags > 0:
        stripped = re.sub(r"\s+", " ", soup2.get_text(" ", strip=True)).strip()
        removed = len(full_text_raw) - len(stripped)
        if removed > 500:
            return f"{all_headings} {stripped}", removed, "strip_nav"

    # Strategia 4: Sliding window z home_text
    if home_text and len(home_text) > 200:
        clean = full_text_raw
        cl = clean.lower()
        for i in range(0, max(0, len(home_text) - 70), 25):
            phrase = home_text[i:i + 70].strip()
            if len(phrase) < 50: continue
            pl = phrase.lower()
            pos = cl.find(pl)
            while pos >= 0:
                clean = clean[:pos] + " " + clean[pos + len(phrase):]
                cl = clean.lower()
                pos = cl.find(pl)
        clean_text = re.sub(r"\s+", " ", clean).strip()
        removed = len(full_text_raw) - len(clean_text)
        if removed > 500:
            return f"{all_headings} {clean_text}", removed, "sliding_window"

    return f"{all_headings} {full_text_raw}", 0, "full_text"


async def phase2_focus(
    gmina: str,
    session_crawl,
    allowed_host: str,
    content_seen: dict,
    diag,
    home_links: set = None,
    home_text: str = "",
    home_url: str = "",
) -> tuple:
    """
    Phase2 v2.23 — sprawdzanie treści + równoległy Playwright fallback.
    
    Dla każdej strony:
    1. Pobierz przez aiohttp
    2. Sprawdź jakość HTML (widoczny tekst, dynamic detector)
    3. Jeśli HTML wygląda jak JS shell → pobierz przez Playwright (wyrenderowana treść)
    4. Keyword match na treści z obu źródeł
    5. Linki znalezione przez Playwright też trafiają do kolejki (jak iter_links_fast)
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
        print(f"  ⚠️  Phase2 [{gmina}]: brak frontieru — pomijam", flush=True)
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

    # [v2.38] strict mode dla dedykowanych subdomen bip.*
    allow_url, _strict_bip = make_allow_url_fn(allowed_host)
    if _strict_bip:
        _mode = "strict BIP" if _is_strict_bip_host(allowed_host) else "pinned shared BIP"
        print(f"  🔒 [Phase2] {_mode} [{gmina}]: tylko {allowed_host}", flush=True)

    # [v2.41 Fix5] Odfiltruj śmieciowe URL-e ze starego frontieru.
    # Problem: stare runy z same_base_domain wpuszczały lo.strzegom.pl, cmentarze.strzegom.pl
    # itp. do frontieru. Fix2 zapobiega dodawaniu nowych złych URL-i ale nie czyści starych.
    # Rozwiązanie: przy każdym starcie Phase2 filtruj frontier przez allow_url().
    # Jednorazowe — po pierwszym runie złe URL-e znikają z cache na zawsze.
    filtered_out = 0
    filtered_q = deque()
    for cu, fd in q:
        if allow_url(cu):
            filtered_q.append((cu, fd))
        else:
            filtered_out += 1
    if filtered_out > 0:
        print(
            f"  🧹 [v2.41] Odfiltrowano {filtered_out} URL-i spoza {allowed_host} "
            f"(stary frontier) [{gmina}]",
            flush=True
        )
    q = filtered_q
    pages_ok = 0
    pages_skipped_ttl = 0
    new_links_added = 0
    pw_content_fetches = 0
    # [v2.32] Deduplikacja po hash treści — ten sam blob = ten sam dokument
    # pod innym URL → nie reportujemy drugi raz w tym samym runie
    blob_hashes_this_run: set = set()
    # [v2.35] Deduplikacja po hash kontekstu keyword-a — ten sam fragment wokół
    # keyword-a na 2+ stronach → widget boczny → nie reportujemy kolejnych trafień
    context_hashes_this_run: dict = {}  # hash → count

    while q and not state.shutdown_requested:
        if RUN_DEADLINE_MIN > 0:
            elapsed_min = (time.time() - GLOBAL_T0) / 60
            # [v2.39 Fix7] Graceful shutdown 20 min przed twardym limitem GitHub Actions
            # Mamy 6h na run, kończymy ok. 5h20min → zostaje ~40min zapasu.
            # 20 minut daje pewność że frontier i cache zapisze się w całości.
            _soft_limit = RUN_DEADLINE_MIN - 20
            if elapsed_min > _soft_limit and not state.shutdown_requested:
                print(
                    f"⏰ PRE-TIMEOUT graceful shutdown [{gmina}]: "
                    f"{elapsed_min:.1f}min >= {_soft_limit}min (limit={RUN_DEADLINE_MIN}min)",
                    flush=True
                )
                state.request_shutdown()
                break
            # Twardy limit jako fallback
            if elapsed_min > RUN_DEADLINE_MIN:
                state.request_shutdown()
                break

        url, depth = q.popleft()

        if pages_ok > 0 and pages_ok % FRONTIER_CHECKPOINT_EVERY == 0:
            async with state.cache_lock:
                state.gmina_frontiers[gkey] = [[u, d] for u, d in q]
            print(
                f"  📊 [{gmina}] pages_ok={pages_ok} skipped={pages_skipped_ttl} "
                f"nowe_linki={new_links_added} pozostało={len(q)}",
                flush=True
            )

        url = _canon(url)
        if not url: continue

        url_dedup = sha1(canonical_url(url))
        prev_pre = content_seen.get(url_dedup)
        is_listing = is_listing_url(url) or is_home_url(url)

        if USE_CACHE and prev_pre:
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
            elif status_prev == "PW_PROCESSING":
                # [v2.41 Fix6] PW_PROCESSING = placeholder ustawiony gdy Playwright
                # był w trakcie przetwarzania. Traktuj jak NO_MATCH — sprawdź ponownie
                # po standardowym TTL. Bez tego URL wracał do pętli w nieskończoność.
                if not should_recheck_no_match(prev_pre):
                    diag["counts"]["pw_processing_ttl_skip"] += 1
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

        # --- 1. Pobierz przez aiohttp ---
        html, final, kind, status, ctype, err, ms, resp_meta = await fetch_conditional(
            session_crawl, url, extra_headers
        )

        # --- 2. [v2.23] Zdecyduj czy potrzebny Playwright do treści ---
        #    Playwright pobiera treść gdy aiohttp fail LUB gdy strona wygląda na JS
        need_pw_for_content = False
        pw_content_reason = ""

        # [v2.40 Fix3] is_download_url jako PIERWSZY warunek — zanim cokolwiek innego.
        # Problem Czarne: .dav plik → js_detected(score=6) → Playwright → "Download is starting"
        # → crash całego joba. Binaria nigdy nie powinny trafiać do Playwright.
        if is_download_url(url):
            # Traktuj jak PDF — skip bez Playwright
            if kind not in ("pdf", "not_modified", "blocked"):
                kind = "pdf"  # przekieruj do ścieżki skip

        if kind in ("pdf", "not_modified", "blocked"):
            pass
        elif kind != "html" or not html:
            need_pw_for_content = True
            pw_content_reason = f"aiohttp_failed(kind={kind})"
        else:
            text_len = _html_visible_text_len(html)
            if text_len < PHASE2_MIN_TEXT_FOR_HTML:
                need_pw_for_content = True
                pw_content_reason = f"too_little_text({text_len}<{PHASE2_MIN_TEXT_FOR_HTML})"

            if not need_pw_for_content:
                is_dyn, dyn_score, dyn_reasons = dynamic_detector.is_dynamic(html=html, url=final or url)
                if is_dyn:
                    need_pw_for_content = True
                    pw_content_reason = f"js_detected(score={dyn_score})"

            # [v2.32] empty_ajax_table usunięte z Phase2 — było źródłem fałszywych
            # Playwright triggers dla stron detail które nigdy nie mają tabel listingów.
            # Kryterium pozostaje tylko w Phase1 (_needs_playwright_for_links).

            if not need_pw_for_content:
                # [v2.24] Sprawdzenie 4: strona detail z za mala trescia
                # action=details&document_id=... powinna miec >600 znakow
                _url_l = (url or "").lower()
                if ("action=details" in _url_l or "document_id=" in _url_l) and text_len < 600:
                    need_pw_for_content = True
                    pw_content_reason = f"detail_too_short(text={text_len}<600)"

            if not need_pw_for_content:
                # [v2.24] Sprawdzenie 5: sygnaly AJAX bez danych
                _html_l = html.lower()
                _ajax_sigs = ["datatables", "ajax.reload", "ajax: {", "ajax:{",
                              "loadingoverlay", "spinner-border", "$.ajax("]
                _has_ajax = any(s in _html_l for s in _ajax_sigs)
                _has_data = "document_id=" in html or "document_id:" in html
                if _has_ajax and not _has_data:
                    need_pw_for_content = True
                    pw_content_reason = "ajax_signals_no_data"

        # --- 3. [v2.23] Playwright dla treści (jeśli potrzebny) ---
        pw_extra_links_for_phase2: set = set()

        # [v2.39 Fix5] Nie odpalaj Playwright jeśli zostało <5 min do deadline.
        # Playwright blokuje pętlę na 30s/call — przy małym oknie lepiej zapisać frontier.
        if need_pw_for_content and RUN_DEADLINE_MIN > 0:
            _remaining = RUN_DEADLINE_MIN - (time.time() - GLOBAL_T0) / 60
            if _remaining < 5:
                need_pw_for_content = False
                pw_content_reason = f"skipped_near_deadline(remaining={_remaining:.1f}min)"
        if need_pw_for_content and kind not in ("pdf", "not_modified", "blocked"):
            pw_content_fetches += 1
            print(
                f"  🎭 Phase2 Playwright content @ {url[:70]} reason={pw_content_reason}",
                flush=True
            )
            pw_html, pw_final, pw_kind, pw_status, pw_ctype, pw_err, pw_ms, _pw_meta = \
                await fetch_with_playwright(url, interact=True)

            if pw_kind == "html" and pw_html:
                # [v2.41] Gdy Playwright dał redirect na stronę główną BIP —
                # oryginalny URL jest martwym linkiem (endpoint systemowy, API, eksport).
                # Universalne: działa dla każdego CMS który redirectuje nieistniejące endpointy
                # na home (np. /auction/628/getAuctionExport/auction → strona główna Oleszyce).
                _pw_final_canon = _canon(pw_final or url)
                _home_canon = _canon(home_url) if home_url else ""
                if _home_canon and _pw_final_canon == _home_canon and _pw_final_canon != _canon(url):
                    dead_add(dead_key, dead_set, _canon(url))
                    diag["counts"]["home_redirect_dead"] = int(diag["counts"].get("home_redirect_dead", 0)) + 1
                    print(f"  💀 home_redirect_dead: {url[:70]}", flush=True)
                    continue

                # Playwright dał wyrenderowany HTML — użyj go zamiast/obok aiohttp
                print(
                    f"  🎭 Phase2 Playwright OK: {len(pw_html)}B @ {url[:60]}",
                    flush=True
                )
                # Aktualizuj zmienne robocze — soup i att_set będą przeliczone z pw_html
                # na linii pages_ok += 1 → soup = safe_soup(html) gdzie html = pw_html
                html, final, kind, status, ctype = pw_html, pw_final, pw_kind, pw_status, pw_ctype

                # [v2.40 Fix2] Zapisz placeholder pod ORYGINALNYM url_dedup już teraz.
                # Problem Jarocin: aiohttp http_err → Playwright OK → final_url inny niż url
                # → status zapisywany tylko pod final_url → oryginalny URL nie dostaje statusu
                # → pw_extra_links_for_phase2 dodaje go z powrotem → 860x ten sam URL w pętli.
                # Rozwiązanie: od razu oznacz oryginalny URL żeby seen_in_frontier go nie wpuściło.
                async with state.cache_lock:
                    if url_dedup not in content_seen:
                        content_seen[url_dedup] = {
                            "found_at": now_iso(), "last_checked": now_iso(),
                            "etag": "", "last_modified": "",
                            "gmina": gmina, "title": "", "url": url,
                            "keywords": [], "att_sig": "", "status": "PW_PROCESSING",
                        }

                # [v2.41] Gdy Playwright dał redirect (final_url != url), dodaj final_c
                # do seen_in_frontier natychmiast — bez tego final_c może wrócić do kolejki
                # przez pw_extra_links lub następny Phase1, powodując nieskończoną pętlę.
                # Problem Kamieniec/wokiss: /rada-gmi → redirect → /organy-wladzy-publiczne
                # → Playwright zbiera linki → /organy-wladzy-publiczne dodany do frontieru
                # → przy następnym wejściu znowu aiohttp_failed → znowu Playwright → pętla.
                _pw_final_c = _canon(pw_final or url)
                if _pw_final_c and _pw_final_c != _canon(url):
                    seen_in_frontier.add(_pw_final_c)
                    # Też zapisz placeholder w content_seen żeby TTL działał
                    _pw_final_dedup = sha1(canonical_url(_pw_final_c))
                    async with state.cache_lock:
                        if _pw_final_dedup not in content_seen:
                            content_seen[_pw_final_dedup] = {
                                "found_at": now_iso(), "last_checked": now_iso(),
                                "etag": "", "last_modified": "",
                                "gmina": gmina, "title": "", "url": _pw_final_c,
                                "keywords": [], "att_sig": "", "status": "PW_PROCESSING",
                            }

                # [v2.23] Zbierz też linki z wyrenderowanej strony — mogą być nowe
                # [v2.41] Dodaj tylko URL-e których nie ma jeszcze w content_seen —
                # linki nawigacyjne już odwiedzone nie powinny trafiać z powrotem do frontieru.
                pw_soup_links = safe_soup(pw_html)
                if pw_soup_links:
                    for abs_u, _txt in iter_links_fast(pw_soup_links, pw_final or url):
                        cu_pw = _canon(abs_u)
                        if not cu_pw or not allow_url(cu_pw): continue
                        if cu_pw in seen_in_frontier: continue
                        if any(cu_pw.lower().endswith(ext) for ext in ATT_EXT): continue
                        # Nie dodawaj URL-i które były już przetworzone (mają status w content_seen)
                        _cu_pw_dedup = sha1(canonical_url(cu_pw))
                        if _cu_pw_dedup in content_seen: continue
                        pw_extra_links_for_phase2.add(cu_pw)

                diag["counts"]["pw_content_ok"] = int(diag["counts"].get("pw_content_ok", 0)) + 1
            else:
                print(
                    f"  🎭 Phase2 Playwright FAIL: {pw_err or '?'} @ {url[:60]}",
                    flush=True
                )
                diag["counts"]["pw_content_fail"] = int(diag["counts"].get("pw_content_fail", 0)) + 1

        final_c = _canon(final or url)
        url_dedup_final = sha1(canonical_url(final_c))
        prev = content_seen.get(url_dedup_final) or prev_pre

        if final_c != url:
            diag["counts"]["redirected"] += 1

        # --- Obsługa stanów specjalnych ---
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
                    "last_checked": now_iso(), "etag": "", "last_modified": "",
                    "gmina": gmina, "title": (prevb.get("title") if prevb else ""),
                    "url": final_c, "keywords": (prevb.get("keywords") if prevb else []),
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
                        "last_checked": now_iso(), "etag": "", "last_modified": "",
                        "gmina": gmina, "title": (prevf.get("title") if prevf else ""),
                        "url": final_c, "keywords": (prevf.get("keywords") if prevf else []),
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
        if not soup: continue

        title, h1, h2, meta_blob = extract_title_h1_h2(soup)
        att_set = attachments_signature(soup, final_c)

        for tag in soup(["script", "style", "noscript"]): tag.decompose()

        blob, _removed_chars, _blob_method = _extract_content_text(
            soup, url=url, home_text=home_text
        )

        # [v2.41] Post-blob Playwright retry — gdy blob jest za mały przy dużym HTML
        # i Playwright nie był jeszcze użyty. Dotyczy serwerów które zwracają duży layout
        # nawigacyjny (bip.lubelskie.pl: 214kB HTML, 312ch blob po ekstrakcji nawigacji).
        # text_len był wystarczający żeby nie triggerować Playwright przed ekstrakcją,
        # ale po ekstrakcji okazuje się że treść dokumentu to tylko kilkaset znaków.
        # Universalne: działa dla każdego serwera z takim zachowaniem.
        if (not need_pw_for_content and len(blob) < 400 and len(html) > 50000):
            _remaining = (RUN_DEADLINE_MIN - (time.time() - GLOBAL_T0) / 60) if RUN_DEADLINE_MIN > 0 else 999
            if _remaining >= 5:
                pw_content_fetches += 1
                print(
                    f"  🎭 Phase2 Playwright retry (small_blob={len(blob)},html={len(html)}) @ {url[:60]}",
                    flush=True
                )
                _rpw_html, _rpw_final, _rpw_kind, _rpw_status, _rpw_ctype, _rpw_err, _rpw_ms, _ = \
                    await fetch_with_playwright(url, interact=True)
                if _rpw_kind == "html" and _rpw_html and len(_rpw_html) > len(html):
                    html = _rpw_html
                    final = _rpw_final or final
                    _rpw_soup = safe_soup(_rpw_html)
                    if _rpw_soup:
                        soup = _rpw_soup
                        att_set = attachments_signature(soup, _canon(_rpw_final or url))
                        for tag in soup(["script", "style", "noscript"]): tag.decompose()
                        blob, _removed_chars, _blob_method = _extract_content_text(
                            soup, url=url, home_text=home_text
                        )
                        print(
                            f"  🎭 Phase2 Playwright retry OK: blob={len(blob)} @ {url[:60]}",
                            flush=True
                        )
                    diag["counts"]["pw_small_blob_retry"] = int(diag["counts"].get("pw_small_blob_retry", 0)) + 1

        # Oblicz hash blob-a już tutaj — potrzebny do deduplikacji i raportowania
        _blob_hash = sha1(blob[:5000])
        _blob_is_duplicate = _blob_hash in blob_hashes_this_run

        # [v2.41] Gdy blob jest duplikatem i URL redirectował (final_c != url_c) →
        # oryginalny URL jest martwym linkiem (strona błędu, catch-all, nieistniejący endpoint).
        # Oznacz jako dead żeby nie wracał co 168h na zawsze.
        # Warunek redirect (final_c != url) eliminuje false positive dla stron z przypadkowo
        # identyczną treścią bez redirectu.
        if _blob_is_duplicate and final_c != _canon(url):
            dead_add(dead_key, dead_set, _canon(url))
            diag["counts"]["blob_dedup_dead"] = int(diag["counts"].get("blob_dedup_dead", 0)) + 1

        # [v2.32] Deduplikacja po hash blob-a — ten sam hash = ta sama treść
        # pod innym URL (np. /110/240/ vs /50/240/) → pomijamy raport
        if not _blob_is_duplicate and len(blob) > 100:
            blob_hashes_this_run.add(_blob_hash)

        ok_any, kw_any = keyword_match_in_blob(blob)

        # [v2.35] Deduplikacja po hash kontekstu keyword-a
        # Ten sam fragment (~150 znaków) wokół keyword-a na 2+ stronach → widget boczny
        _context_is_duplicate = False
        if ok_any and kw_any:
            _kw_pos = blob.lower().find(kw_any.lower())
            if _kw_pos >= 0:
                _ctx_fragment = blob[max(0, _kw_pos - 60): _kw_pos + 90].lower()
                _ctx_hash = sha1(_ctx_fragment)
                context_hashes_this_run[_ctx_hash] = context_hashes_this_run.get(_ctx_hash, 0) + 1
                if context_hashes_this_run[_ctx_hash] >= 2:
                    _context_is_duplicate = True

        # Diagnostyka
        _ul = (url or "").lower()
        _is_detail = "action=details" in _ul or "document_id=" in _ul
        if ok_any or _is_detail:
            kw_pos = blob.lower().find((kw_any or "").lower()) if kw_any else -1
            kw_ctx = blob[max(0, kw_pos-60):kw_pos+100].replace("\n", " ") if kw_pos >= 0 else ""
            print(
                f"  🔎 [{gmina}] {'DETAIL ' if _is_detail else ''}match={ok_any} kw={kw_any!r} "
                f"removed={_removed_chars}ch blob={len(blob)}ch html={len(html)}B"
                f"\n     ctx: ...{kw_ctx!r}..."
                f"\n     url={url[:80]}",
                flush=True
            )

        page_title = ""
        for tag in soup.find_all(["h1", "h2", "h3"]):
            txt = re.sub(r"\s+", " ", (tag.get_text(" ", strip=True) or "")).strip()
            if txt and not is_generic_page_title(txt) and len(txt) > 10:
                page_title = txt[:300]
                break
        if not page_title:
            page_title = final_c

        if prev is None:
            status_new = "NOWE" if ok_any else "NO_MATCH"
        else:
            if ok_any:
                # [v2.41 Fix4] prev.status == NO_MATCH + keyword znaleziony = NOWE odkrycie.
                # Problem Wiązów: Playwright redirect m,5096→a,22784 → a,22784 był już
                # w content_seen jako NO_MATCH (poprzedni etap tego runu, brak keyword) →
                # prev!=None → status_new=HIT → nie raportowane → znalezione=0.
                # NO_MATCH znaczy "sprawdzono, nie było keyword" — jeśli teraz jest → NOWE.
                # Dotyczy też aliasowania URL-i przez różne redirecty Playwright.
                if prev.get("status") == "NO_MATCH":
                    status_new = "NOWE"
                else:
                    prev_att_set = att_sig_deserialize(prev.get("att_sig") or "")
                    added_files = att_set - prev_att_set
                    status_new = "ZMIANA" if added_files else "HIT"
                    if added_files: diag["counts"]["att_added"] += len(added_files)
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
            if final_c not in state.reported_urls_this_run and not _blob_is_duplicate and not _context_is_duplicate:
                state.reported_urls_this_run.add(final_c)
                print_hit(f"🟢 {status_new}", gmina, kw_any, page_title)
                found.append((gmina, kw_any, page_title, final_c, status_new))
            else:
                if _blob_is_duplicate:
                    diag["counts"]["blob_dedup_skipped"] += 1
                    print(f"  🔁 blob_dedup [{gmina}]: pominięto duplikat treści @ {url[:60]}", flush=True)
                elif _context_is_duplicate:
                    diag["counts"]["context_dedup_skipped"] += 1
                    print(f"  🔁 ctx_dedup [{gmina}]: pominięto duplikat kontekstu kw={kw_any!r} @ {url[:60]}", flush=True)
                else:
                    diag["counts"]["dedup_skipped"] += 1

        # --- [v2.23] Linki z HTML (aiohttp) → kolejka ---
        # [v2.41] Gdy blob jest duplikatem → ta strona zwraca tę samą treść co poprzednia
        # (strona błędu, catch-all, nawigacja bez treści). Jej linki nawigacyjne są identyczne
        # z linkami już zebranymi — nie dodawaj ich do kolejki bo frontier będzie rósł.
        # LINK_HITS działa ZAWSZE — keyword w anchor text raportujemy niezależnie od duplikatu.
        for abs_u, txt in iter_links_fast(soup, final_c):
            cu = _canon(abs_u)
            if not cu or not allow_url(cu) or cu in dead_set: continue

            # LINK_HITS: zawsze sprawdzaj anchor text, nawet na stronie błędu
            if ENABLE_LINK_HITS and not is_download_url(cu) and cu not in seen_in_frontier:
                filename = urlparse(cu).path.split("/")[-1]
                ok_link, kw_link = keyword_match_in_blob(f"{txt} {filename}")
                if ok_link:
                    key = sha1(canonical_url(cu))
                    if content_seen.get(key) is None and cu not in state.reported_urls_this_run:
                        async with state.cache_lock:
                            content_seen[key] = {
                                "found_at": now_iso(), "last_checked": now_iso(),
                                "etag": "", "last_modified": "",
                                "gmina": gmina, "title": (txt or filename)[:240],
                                "url": cu, "keywords": [kw_link],
                                "att_sig": "", "status": "NOWE",
                            }
                        state.reported_urls_this_run.add(cu)
                        print_hit("🟢 NOWE (LINK)", gmina, kw_link, txt or filename)
                        found.append((gmina, kw_link, (txt or filename)[:240], cu, "NOWE"))
                        diag["counts"]["link_hits_new"] += 1

            # Dodaj do kolejki tylko gdy blob nie jest duplikatem
            # Strona błędu/catch-all ma identyczny blob — jej linki nawigacyjne
            # są tymi samymi linkami co już w frontierze → nie dodawaj ponownie
            if _blob_is_duplicate: continue
            if cu in seen_in_frontier: continue
            seen_in_frontier.add(cu)
            q.append((cu, depth + 1))
            new_links_added += 1

        # --- [v2.23] Linki z Playwright → też do kolejki ---
        # Gdy blob duplikat → nie dodawaj linków z Playwright (ta sama logika)
        if not _blob_is_duplicate:
            for cu in pw_extra_links_for_phase2:
                if cu in dead_set or cu in seen_in_frontier: continue
                seen_in_frontier.add(cu)
                q.append((cu, depth + 1))
                new_links_added += 1
                diag["counts"]["pw_extra_links_phase2"] = int(diag["counts"].get("pw_extra_links_phase2", 0)) + 1

    async with state.cache_lock:
        if q:
            state.gmina_frontiers[gkey] = [[u, d] for u, d in list(q)]
            print(
                f"  💾 Frontier zapisany [{gmina}]: "
                f"pozostało={len(q)} | nowe_linki={new_links_added} | ten_run={pages_ok} | "
                f"pw_content_fetches={pw_content_fetches}",
                flush=True
            )
        else:
            state.gmina_frontiers[gkey] = []
            mark_frontier_reset(gkey)
            print(
                f"  🏁 Frontier wyczerpany [{gmina}]: "
                f"sprawdzono={pages_ok} | pominięto_ttl={pages_skipped_ttl} | "
                f"znaleziono={len(found)} | pw_content_fetches={pw_content_fetches} | "
                f"PEŁNY CYKL ZAKOŃCZONY",
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
        "pw_content_fetches": pw_content_fetches,
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

            if RUN_DEADLINE_MIN > 0:
                _elapsed_min = (time.time() - GLOBAL_T0) / 60
                _soft = RUN_DEADLINE_MIN - 20
                if _elapsed_min > _soft and not state.shutdown_requested:
                    print(f"⏰ PRE-TIMEOUT worker shutdown: {_elapsed_min:.1f}min >= {_soft}min", flush=True)
                    state.request_shutdown()
                elif _elapsed_min > RUN_DEADLINE_MIN:
                    state.request_shutdown()

            if state.shutdown_requested:
                try: await queue.put((gmina, start_url))
                except Exception: pass
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
                print(f"  ▶️  [{name}] {gmina}: kontynuacja Phase2 (frontier={frontier_size})", flush=True)
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
                    home_links=set(state.gmina_seeds.get(gkey_approx, {}).get("home_links_list", [])),
                    home_text=state.gmina_seeds.get(gkey_approx, {}).get("home_text", ""),
                    home_url=state.gmina_seeds.get(gkey_approx, {}).get("start_final", ""),
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
                        "status": "START_FAIL", "phase1_seeds": 0, "phase2_pages_ok": 0,
                        "notes": diag.get("notes", []), "counts": dict(diag.get("counts", {})),
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
                    "home_links_list": p1meta.get("home_links_list", []),
                    "home_text": p1meta.get("home_text", ""),
                    "ts": now_iso(),
                }

                if phase1_complete:
                    mark_frontier_complete(gkey, len(all_urls))
                    print(f"  ✅ [{name}] {gmina}: Phase1 KOMPLETNA — frontier={len(all_urls)} | startuje Phase2", flush=True)
                else:
                    print(f"  ⚠️  [{name}] {gmina}: Phase1 NIEKOMPLETNA — frontier={len(all_urls)}", flush=True)

                found, p2meta = await phase2_focus(
                    gmina=gmina,
                    session_crawl=session_crawl,
                    allowed_host=allowed_host,
                    content_seen=content_seen,
                    diag=diag,
                    home_links=set(p1meta.get("home_links_list", [])),
                    home_text=p1meta.get("home_text", ""),
                    home_url=p1meta.get("start_final", ""),
                )

            stop_reason = (p2meta or {}).get("stop_reason") or ""
            frontier_len = int((p2meta or {}).get("frontier_len", 0) or 0)
            retry_len = int((p2meta or {}).get("retry_len", 0) or 0)
            pages_ok = int((p2meta or {}).get("pages_ok", 0) or 0)
            pages_skipped = int((p2meta or {}).get("pages_skipped_ttl", 0) or 0)
            new_links = int((p2meta or {}).get("new_links_added", 0) or 0)
            pw_content = int((p2meta or {}).get("pw_content_fetches", 0) or 0)
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
                    f"pw_content_fetches={pw_content}",
                ],
                "counts": dict(diag.get("counts", {})),
            })
            for e in diag.get("errors", []):
                state.diag_errors.append(e)

            for (g, kw, t, u, st) in (found or []):
                # [v2.39 Fix4] Pomijaj PDF/DOC w mailu — chcemy tylko strony HTML
                _u_low = (u or "").lower()
                _MAIL_SKIP_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".rtf",
                                  ".zip", ".rar", ".7z", ".gml", ".xml")
                if any(_u_low.endswith(ext) for ext in _MAIL_SKIP_EXT):
                    continue
                # [v2.39 Fix8] Tylko URL-e zawierające "bip" w domenie
                # Zbieramy ogłoszenia wyłącznie z BIP — nie z głównych stron gminy
                _u_host = urlparse(u).netloc.lower() if u else ""
                if not _is_bip_domain(_u_host):
                    continue
                mail_line = f"[{st}] {g} | {kw} | {t} | {u}"
                if mail_line not in state.mail_dedup:
                    state.mail_dedup.add(mail_line)
                    state.new_items_for_mail.append(mail_line)
                    append_hits_to_backup([mail_line])  # [v2.36] backup natychmiast
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
                f"znalezione={len(found or [])} | phase2_strony={pages_ok} | "
                f"pominięte_ttl={pages_skipped} | nowe_linki={new_links} | "
                f"pw_content={pw_content} | frontier_pozostało={frontier_len} | "
                f"retry={retry_len}{cycle_info}",
                flush=True
            )

        except asyncio.CancelledError:
            # [v2.36] Zamiast po prostu return — zapisz co zdążyliśmy zebrać.
            # GitHub Actions cancel powoduje CancelledError — bez tego tracimy
            # wszystkie wyniki z danego runu bezpowrotnie.
            print(f"⚠️  [{name}] CancelledError — zapisuję wyniki przed wyjściem...", flush=True)
            try:
                if USE_CACHE and os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                    await save_shard_cache_and_commit(asyncio.get_event_loop())
                save_diag(state.diag_rows, state.diag_errors)
                write_summary(state.diag_rows, state.new_items_for_mail)
                _try_send_email_sync()
                print(f"✅ [{name}] Dane zapisane po CancelledError", flush=True)
            except Exception as _ce:
                print(f"⚠️  [{name}] Zapis po CancelledError failed: {_ce}", flush=True)
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
        for shard_file in BASE_DIR.glob("cache_shard_*.json"):
            shard_file.unlink()
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
        print("❌ CSV pusty.")
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
        limit=CONCURRENT_REQUESTS, limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=600, enable_cleanup_closed=True, ssl=False
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
                if state.shutdown_requested: break
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
            for t in workers: t.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    try:
        if USE_CACHE:
            if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                await save_shard_cache_and_commit(asyncio.get_event_loop())
            else:
                save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
        save_diag(state.diag_rows, state.diag_errors)
        write_summary(state.diag_rows, state.new_items_for_mail)
        # export_summary_to_onedrive() — niedostępne w GitHub Actions
    except Exception as e:
        print(f"⚠️  Final save failed: {e}")

    # [v2.36] Email — zawsze próbuj wysłać (usunięto błędny warunek not shutdown_requested).
    # Używamy _try_send_email_sync() która po wysłaniu czyści listę (no-resend w nast. runie).
    _try_send_email_sync()

    # [v2.36] Po wysłaniu emaila — zapisz shard jeszcze raz żeby nowa_items=[],
    # tak żeby następny run nie wysyłał tych samych wyników ponownie.
    try:
        if USE_CACHE:
            if os.getenv("GITHUB_ACTIONS") and get_shard_index() >= 0:
                await save_shard_cache_and_commit(asyncio.get_event_loop())
            else:
                save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds)
    except Exception as e:
        print(f"⚠️  Post-email cache save failed: {e}")

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
