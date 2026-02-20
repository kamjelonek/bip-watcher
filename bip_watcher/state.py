# state.py
import asyncio, signal, time
from bip_watcher.utils import now_iso
from bip_watcher.cache import load_cache_v2
from bip_watcher.config import RUN_DEADLINE_MIN, env_int

class GlobalState:
    def __init__(self):
        self.shutdown_requested = False
        self.new_items_for_mail = []
        self.raw_cache = {}
        self.urls_seen = set()
        self.content_seen = {}
        self.gmina_seeds = {}
        self.page_fprints = {}
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

def signal_handler(signum, frame):
    state.request_shutdown()

try:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
except Exception:
    pass
