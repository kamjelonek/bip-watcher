# phases/phase2.py
from collections import deque
from bip_watcher.utils import normalize_url, url_key, sha1, canonical_url, now_iso
from bip_watcher.parsing.soup_utils import extract_title_h1_h2, _soup_fast_text, page_fingerprint, attachments_signature
from bip_watcher.parsing.link_extraction import iter_links_fast, anchor_is_ignored
from bip_watcher.parsing.keyword_match import keyword_match_in_blob
from bip_watcher.networking.fetch_normal import fetch_conditional
from bip_watcher.config import *
from bip_watcher.diagnostics.diag import diag_add_error, trace_set

async def phase2_focus(gmina: str, seed_urls, session_crawl, allowed_host: str,
                      urls_seen: set, content_seen: dict, diag):

    if gmina is None:
        return [], {"status": "SHUTDOWN"}

    found = []
    visited = set()
    q = deque()

    gkey = sha1(f"{gmina.strip().lower()}|{allowed_host}")
    dead_key = f"dead_{gkey}"
    dead_set = set((content_seen.get("dead_urls", {}) or {}).get(dead_key, []) or [])

    retry_list = (content_seen.get("gmina_retry", {}) or {}).get(gkey, []) or []
    for u in retry_list[:3000]:
        u = normalize_url(u)
        if u and u not in visited and u not in dead_set:
            visited.add(u)
            q.appendleft((u, 0))

    for su in seed_urls:
        su = normalize_url(su)
        if su not in visited and su not in dead_set:
            visited.add(su)
            q.append((su, 0))

    def allow_url(u: str) -> bool:
        return same_base_domain(urlparse(u).netloc.lower(), allowed_host)

    pages_ok = 0

    while q:
        url, depth = q.popleft()
        if depth > PHASE2_MAX_DEPTH:
            continue

        url = normalize_url(url)
        url_hash = url_key(url)
        is_listing = is_listing_url(url) or is_home_url(url)

        url_dedup = sha1(canonical_url(url))
        prev = content_seen.get(url_dedup)

        # TTL logic
        if USE_CACHE and prev and not is_listing:
            status_prev = prev.get("status")
            if status_prev in {"NOWE", "ZMIANA", "HIT"}:
                if not should_recheck_hit(prev):
                    diag["counts"]["hit_ttl_skip"] += 1
                    continue
            elif status_prev == "NO_MATCH":
                if not should_recheck_no_match(prev):
                    diag["counts"]["no_match_ttl_skip"] += 1
                    continue
            elif status_prev == "BLOCKED":
                if not should_recheck_block(prev, BLOCKED_RECHECK_TTL_MIN):
                    diag["counts"]["blocked_ttl_skip"] += 1
                    continue
            elif status_prev == "FAILED":
                if not should_recheck_block(prev, FAILED_RECHECK_TTL_MIN):
                    diag["counts"]["failed_ttl_skip"] += 1
                    continue

        extra_headers = {}
        if prev and prev.get("etag"):
            extra_headers["If-None-Match"] = prev.get("etag")
        if prev and prev.get("last_modified"):
            extra_headers["If-Modified-Since"] = prev.get("last_modified")

        html, final, kind, status, ctype, err, ms, resp_meta = await fetch_conditional(
            session_crawl, url, extra_headers
        )

        url_dedup_final = sha1(canonical_url(final or url))

        if kind == "not_modified":
            content_seen[url_dedup_final]["last_checked"] = now_iso()
            content_seen[url_dedup_final]["status"] = "HIT"
            continue

        if kind == "blocked":
            diag["counts"]["blocked_13"] += 1
            prevb = content_seen.get(url_dedup_final)
            content_seen[url_dedup_final] = {
                "found_at": (prevb.get("found_at") if prevb else now_iso()),
                "last_checked": now_iso(),
                "etag": "",
                "last_modified": "",
                "gmina": gmina,
                "title": (prevb.get("title") if prevb else ""),
                "url": final or url,
                "keywords": (prevb.get("keywords") if prevb else []),
                "att_sig": (prevb.get("att_sig") if prevb else ""),
                "status": "BLOCKED",
            }
            content_seen.setdefault("gmina_retry", {}).setdefault(gkey, []).append(url)
            urls_seen.discard(url_hash)
            continue

        if kind != "html" or not html:
            if status in (404, 410):
                content_seen.setdefault("dead_urls", {}).setdefault(dead_key, []).append(url)
                continue
            if status in (403, 429) or kind in {"timeout", "exc"} or (status and int(status) >= 500):
                prevf = content_seen.get(url_dedup_final)
                content_seen[url_dedup_final] = {
                    "found_at": (prevf.get("found_at") if prevf else now_iso()),
                    "last_checked": now_iso(),
                    "etag": "",
                    "last_modified": "",
                    "gmina": gmina,
                    "title": (prevf.get("title") if prevf else ""),
                    "url": final or url,
                    "keywords": (prevf.get("keywords") if prevf else []),
                    "att_sig": (prevf.get("att_sig") if prevf else ""),
                    "status": "FAILED",
                }
                content_seen.setdefault("gmina_retry", {}).setdefault(gkey, []).append(url)
                urls_seen.discard(url_hash)
            continue

        pages_ok += 1
        soup = safe_soup(html)
        if not soup:
            continue

        title, h1, h2, meta_blob = extract_title_h1_h2(soup)
        fast_text = _soup_fast_text(soup)
        blob = f"{title} {h1} {h2} {fast_text}"

        ok_any, kw_any = keyword_match_in_blob(blob)
        fp = page_fingerprint(title, h1, fast_text)
        att_sig = attachments_signature(soup, final)

        status_new = "NO_MATCH"
        if ok_any:
            status_new = "NOWE"
        if prev and (prev.get("fp") != fp or prev.get("att_sig") != att_sig):
            if ok_any:
                status_new = "ZMIANA"

        page_title = (h1 or h2 or title or "").strip()
        if not page_title:
            page_title = final

        content_seen[url_dedup_final] = {
            "found_at": (prev.get("found_at") if prev else now_iso()),
            "last_checked": now_iso(),
            "etag": (resp_meta.get("etag") if resp_meta else ""),
            "last_modified": (resp_meta.get("last_modified") if resp_meta else ""),
            "gmina": gmina,
            "title": page_title[:240],
            "url": final,
            "keywords": [kw_any] if ok_any else [],
            "fp": fp,
            "att_sig": att_sig,
            "status": status_new,
        }

        if status_new in {"NOWE", "ZMIANA"}:
            print_hit(f"🟢 {status_new}", gmina, kw_any, page_title)
            found.append((gmina, kw_any, page_title, final, status_new))

        for abs_u, txt in iter_links_fast(soup, final):
            if not allow_url(abs_u):
                continue
            filename = urlparse(abs_u).path.split("/")[-1]
            blob_link = f"{txt} {filename}"
            ok_link, kw_link = keyword_match_in_blob(blob_link)
            if ok_link:
                key = sha1(canonical_url(abs_u))
                if key not in content_seen:
                    link_title = (txt or "").strip()
                    if not link_title:
                        link_title = filename or abs_u
                    content_seen[key] = {
                        "found_at": now_iso(),
                        "last_checked": now_iso(),
                        "etag": "",
                        "last_modified": "",
                        "gmina": gmina,
                        "title": link_title[:240],
                        "url": abs_u,
                        "keywords": [kw_link],
                        "att_sig": "",
                        "status": "NOWE",
                    }
                    print_hit("🟢 NOWE (LINK)", gmina, kw_link, link_title)
                    found.append((gmina, kw_link, link_title, abs_u, "NOWE"))

            if abs_u not in visited:
                visited.add(abs_u)
                q.append((abs_u, depth + 1))

    return found, {
        "status": "OK",
        "pages_ok": pages_ok,
        "stop_reason": "QUEUE_EMPTY",
        "frontier_len": 0,
        "retry_len": len(content_seen.get("gmina_retry", {}).get(gkey, [])),
    }
