# config.py
# All constants, paths, switches, keywords, user agents, timeouts, etc.

import os
from pathlib import Path
import aiohttp

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

# ===================== PATHS (VS CODE / WINDOWS) =====================
BASE_DIR = Path(__file__).resolve().parent / "data"
BASE_DIR.mkdir(parents=True, exist_ok=True)
CSV_FILE = BASE_DIR / "bipy1.csv"
CACHE_FILE = BASE_DIR / "cache.json"
LOG_FILE = BASE_DIR / "log.csv"
DIAG_GMINY_CSV = BASE_DIR / "diag_gminy.csv"
DIAG_ERRORS_CSV = BASE_DIR / "diag_errors.csv"
SUMMARY_FILE = BASE_DIR / "summary_report.txt"
# ======= ONE DRIVE EXPORT (Power Automate trigger) =======
ONEDRIVE_EXPORT_DIR = Path(r"P:\WORKSPACE\PP_ALL")

# ===================== USER SWITCHES =====================
UNLIMITED_SCAN = True
USE_CACHE = True
ONLY_GMINA = None  # np. "Gmina X"
CRAWL_ALL_INTERNAL_LINKS = True
BOOTSTRAP_MODE = False
FORCE_PHASE1_REDISCOVERY = True

# ===================== EMAIL =====================
EMAIL_TO = "planowanie@wpd-polska.pl"
ENABLE_EMAIL = False

# ===================== KEYWORDS (NAGŁÓWKI-ONLY / MINIMAL) =====================
KEYWORDS = [
    "mpzp", "miejscowy plan", "plan miejscowy", "miejscowego",
    "miejscowy plan zagospodarowania przestrzennego",
    "projekt mpzp", "miejscowego planu zagospodarowania przestrzennego",
    "plan ogólny", "plan ogolny", "planu ogólnego",
    "studium uwarunkowań", "studium uwarunkowan",
    "warunki zabudowy", "decyzja o warunkach zabudowy", "decyzje o warunkach zabudowy",
    "decyzja środowiskowa", "decyzje środowiskowe",
    "decyzja o środowiskowych uwarunkowaniach", "środowiskowych uwarunkowaniach",
    "raport o oddziaływaniu na środowisko",
    "oze",
    "elektrownia wiatrowa", "farma wiatrowa", "wiatr", "wiatrow", "turbina",
    "fotowolta", "farma fotowoltaiczna", "magazyn energii",
]

STRICT_ONLY = {"wz", "mpzp", "oze"}

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

PHASE1_MAX_PAGES = 5000
PHASE1_MAX_SEEDS = 100000
PHASE2_MAX_DEPTH = 4
PHASE2_MAX_PAGES = 1000000
ABSOLUTE_MAX_SEC_PER_GMINA = 10**9
MAX_SEC_PER_GMINA = 10**9

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=None, sock_connect=12, sock_read=35)

START_TIMEOUT_FAST = aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=18)
START_TIMEOUT_LONG = aiohttp.ClientTimeout(total=None, sock_connect=18, sock_read=45)
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
FAST_TEXT_MAX_CHARS = 3500
HIT_RECHECK_TTL_HOURS = 168
NO_MATCH_RECHECK_TTL_HOURS = 168
BLOCKED_RECHECK_TTL_MIN = env_int("BLOCKED_RECHECK_TTL_MIN", 180)
FAILED_RECHECK_TTL_MIN  = env_int("FAILED_RECHECK_TTL_MIN", 120)
FAST_FPRINT_MAX_CHARS = 6000

# ===================== USER AGENTS ROTATION =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

def get_random_headers():
    import random
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
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

# ===================== ATTACHMENTS =====================
ATT_EXT = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".rtf",
    ".gml", ".xml", ".gpx", ".kml", ".kmz", ".geojson", ".json",
    ".shp", ".dbf", ".shx", ".prj",
    ".dwg", ".dxf",
    ".tif", ".tiff",
)

# ===================== LISTING URL BONUS (SITEMAP) =====================
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
    # DODANE:
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
    # DODANE:
    "/sitemap.xml.gz", "/sitemap_index.xml.gz", "/sitemap.php",
    "/sitemap.xml?page=1", "/sitemap.xml?page=2",
    "/ogloszenia.xml", "/ogloszenia.rss",
    "/kategorie.xml", "/kategorie.rss",
    "/bip-sitemap.xml", "/bip-sitemap_index.xml",
]

