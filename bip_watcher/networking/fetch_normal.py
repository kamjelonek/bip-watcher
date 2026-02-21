# networking/fetch_normal.py

import asyncio
import time
import random
import re
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from bip_watcher.utils import (
    normalize_url,
    canonical_url,
    sha1,
    safe_soup,
    now_iso,
    is_valid_url,
    is_home_url,
    is_listing_url,
)

from bip_watcher.config import (
    START_TIMEOUT_FAST,
    START_TIMEOUT_LONG,
    REQUEST_TIMEOUT,
    START_MAX_TRIES,
    START_AUX_HINTS,
    START_TOTAL_TIMEOUT_SEC,
    ATT_EXT,
    JS_EXTRA_SEED_PATHS,
    LISTING_URL_HINTS,
    get_random_headers,
)

from bip_watcher.networking.rate_limiter import DomainRateLimiter
from bip_watcher.networking.sitemap import parse_sitemap_xml, _looks_like_xml_sitemap

# ------------------------------------------------------------
# GLOBAL RATE LIMITER
# ------------------------------------------------------------

rate_limiter = DomainRateLimiter(min_delay=0.5, max_delay=1.5)

# ------------------------------------------------------------
# URL HELPERS
# ------------------------------------------------------------

def looks_like_search_url(u: str) -> bool:
    low = (u or "").lower()
    if any(x in low for x in ["wyszuk", "szukaj", "search", "query", "filter", "filtr"]):
        return True
    if any(x in low for x in ["?q=", "&q=", "?search=", "&search=", "?szukaj=", "&szukaj=", "?query=", "&query="]):
        return True
    return False


def build_search_fuzz_urls(base_url: str) -> list:
    base_url = normalize_url(base_url)
    parsed = urlparse(base_url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))

    param_candidates = ["q", "search", "szukaj", "query"]
    queries = ["mpzp", "oze", "wiatr", "fotowolta", "plan ogólny", "plan miejscowy"]

    out = []
    for param in param_candidates:
        for q in queries:
            qs2 = dict(qs)
            qs2[param] = q
            new_q = urlencode(list(qs2.items()), doseq=True)
            u2 = urlunparse(parsed._replace(query=new_q, fragment=""))
            out.append(normalize_url(u2))

    uniq = []
    seen = set()
    for u in out:
        cu = canonical_url(u)
        if cu in seen:
            continue
        seen.add(cu)
        uniq.append(u)
        if len(uniq) >= 12:
            break

    return uniq

# ------------------------------------------------------------
# FETCH HELPERS
# ------------------------------------------------------------

async def fetch_text_best_effort(session, url: str, timeout=None):
    if timeout is None:
        timeout = START_TIMEOUT_FAST

    url = normalize_url(url)
    domain = urlparse(url).netloc

    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            t0 = time.time()

            async with session.get(
                url,
                timeout=timeout,
                ssl=ssl_mode,
                allow_redirects=True,
                headers=headers
            ) as resp:

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


async def fetch_with_retry(session, url: str, timeout, ssl_mode, max_retries=3, method="GET"):
    url = normalize_url(url)
    domain = urlparse(url).netloc

    for attempt in range(max_retries):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            t0 = time.time()

            async with session.request(
                method,
                url,
                timeout=timeout,
                ssl=ssl_mode,
                allow_redirects=True,
                headers=headers
            ) as resp:

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
                    await asyncio.sleep((2 ** attempt) * random.uniform(1.0, 2.0))
                    continue

                if status >= 500 and attempt < max_retries - 1:
                    await asyncio.sleep((2 ** attempt) * random.uniform(0.5, 1.5))
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


async def _aio_fetch_raw(session, url: str, timeout, ssl_mode, method="GET"):
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

# ------------------------------------------------------------
# START MATRIX
# ------------------------------------------------------------

async def fetch_start_matrix(session_default, session_ipv4, url: str, diag):
    url = normalize_url(url)

    def looks_html(ctype: str, text: str) -> bool:
        low = (text or "").lower()
        return (
            "html" in (ctype or "").lower()
            or "<html" in low[:2000]
            or "<!doctype" in low[:2000]
            or "<body" in low[:2000]
        )

    STRATEGIES = []

    # FAST
    for timeout, tname in ((START_TIMEOUT_FAST, "FAST"),):
        STRATEGIES.append(("aio_default", tname, "ssl=off", "GET", timeout, False))
        STRATEGIES.append(("aio_ipv4", tname, "ssl=off", "GET", timeout, False))

    # FAST + LONG
    for timeout, tname in ((START_TIMEOUT_FAST, "FAST"), (START_TIMEOUT_LONG, "LONG")):
        for ssl_mode, sname in ((None, "ssl=verify"), (False, "ssl=off")):
            for method in ("GET", "HEAD"):
                STRATEGIES.append(("aio_default", tname, sname, method, timeout, ssl_mode))
                STRATEGIES.append(("aio_ipv4", tname, sname, method, timeout, ssl_mode))

    # requests fallback
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
                    final, status, ctype, text, ms = res

            else:
                continue

            # robots / sitemap
            lu = url.lower()
            if any(ax in lu for ax in ("/robots.txt", "sitemap")):
                ok = (status is not None) and (200 <= int(status) < 400) and bool(text)
                diag["start_matrix"].append({
                    "ok": ok,
                    "strategy": strategy_name,
                    "url": url,
                    "status": status,
                    "kind": ("aux_ok" if ok else "aux_fail"),
                })
                continue

            # HTTP error
            if status is None or int(status) != 200:
                diag["start_matrix"].append({
                    "ok": False,
                    "strategy": strategy_name,
                    "url": url,
                    "status": status,
                    "kind": "http_err",
                })
                last_fail = (None, final, "http_err", status, ctype, f"HTTP {status}", ms)
                continue

            # HTML OK
            if looks_html(ctype, text) and text:
                diag["start_matrix"].append({
                    "ok": True,
                    "strategy": strategy_name,
                    "url": url,
                    "status": status,
                    "kind": "html",
                })
                return text, final, "html", status, ctype, None, ms

            # non-HTML
            diag["start_matrix"].append({
                "ok": False,
                "strategy": strategy_name,
                "url": url,
                "status": status,
                "kind": "non_html",
            })
            last_fail = (None, final, "non_html", status, ctype, "start_non_html", ms)

        except Exception as e:
            msg = str(e)
            kind = "exc"
            if "ssl" in msg.lower() or "certificate" in msg.lower():
                kind = "ssl"

            diag["start_matrix"].append({
                "ok": False,
                "strategy": strategy_name,
                "url": url,
                "status": None,
                "kind": kind,
            })

            last_fail = (None, url, kind, None, "", msg, None)

    return last_fail if last_fail else (None, url, "fail", None, "", "no_strategy_worked", None)

# ------------------------------------------------------------
# FETCH (HTML / PDF / BLOCK PAGE)
# ------------------------------------------------------------

def is_block_page(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(x in low for x in ["access denied", "forbidden", "blocked", "captcha"])

async def fetch(session, url: str, extra_headers: dict = None):
    url = normalize_url(url)
    domain = urlparse(url).netloc

    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            if extra_headers:
                headers.update(extra_headers)

            t0 = time.time()

            async with session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                ssl=ssl_mode,
                allow_redirects=True,
                headers=headers
            ) as resp:

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

# ------------------------------------------------------------
# CONDITIONAL FETCH (ETAG / LAST-MODIFIED)
# ------------------------------------------------------------

async def fetch_conditional(session, url: str, extra_headers: dict = None):
    url = normalize_url(url)
    domain = urlparse(url).netloc

    for ssl_mode in (False, None):
        try:
            await rate_limiter.wait(domain)
            headers = get_random_headers()
            if extra_headers:
                headers.update(extra_headers)

            t0 = time.time()

            async with session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                ssl=ssl_mode,
                allow_redirects=True,
                headers=headers
            ) as resp:

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
