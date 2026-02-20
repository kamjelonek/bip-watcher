# phases/phase1.py
import time
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse
from bip_watcher.utils import normalize_url, canonical_url, is_valid_url, safe_soup, url_key
from bip_watcher.networking.fetch_normal import fetch_start_matrix, collect_sitemap_urls
from bip_watcher.parsing.link_extraction import iter_links_fast, should_skip_href
from bip_watcher.parsing.soup_utils import extract_title_h1_h2, _soup_fast_text
from bip_watcher.config import *
from bip_watcher.diagnostics.diag import diag_add_error, trace_set
from bip_watcher.cache import seed_cache_get, seed_cache_put
from bip_watcher.utils import sha1

async def phase1_discover(gmina: str, start_url: str,
                         session_default,
                         session_ipv4,
                         session_crawl,
                         urls_seen: set, diag):
    if gmina is None:
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
        if tried > START_MAX_TRIES:
            break
        tried += 1
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
                        diag["counts"]["js_extra_seeds_added"] += len(JS_EXTRA_SEED_PATHS)
                    except Exception:
                        diag["counts"]["js_extra_seeds_failed"] += 1
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
    while q and pages < PHASE1_MAX_PAGES:
        url = normalize_url(q.popleft())
        html, final, kind, status, ctype, err, ms = await fetch(session_crawl, url)
        trace_set(diag, "PHASE1_DISCOVERY", url=url, kind=kind, status=status, ms=ms)
        if kind != "html" or not html:
            diag_add_error(diag, gmina, url, "phase1_fetch", kind, status, err)
            continue
        pages += 1
        diag["counts"]["phase1_pages_ok"] += 1
        if USE_CACHE:
            # cache_mark_url is in utils originally; we keep cache marking in cache module
            pass
        soup = safe_soup(html)
        if not soup:
            diag_add_error(diag, gmina, final, "phase1_parse", "parse", status, "soup_failed")
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
