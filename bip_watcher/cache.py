# cache.py

import json
import os
from datetime import datetime, timedelta

from bip_watcher.config import (
    USE_CACHE,
    CACHE_FILE,
    SCANNED_TTL_DAYS,
    SEED_CACHE_TTL_DAYS,
)

from bip_watcher.utils import now_iso, sha1, retry_io
from bip_watcher.state import state


CACHE_SCHEMA = 10


def _empty_cache():
    return {
        "schema": CACHE_SCHEMA,
        "urls_seen": {},
        "content_seen": {},
        "gmina_seeds": {},
        "page_fprints": {},
        "gmina_frontiers": {},
        "gmina_retry": {},
        "dead_urls": {},
    }


def load_cache_v2():
    if not USE_CACHE:
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}, {}

    if not CACHE_FILE.exists():
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}, {}

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            c = json.load(f) or {}

        # Legacy migration
        if "schema" not in c and "found_items" in c:
            print("🔄 Legacy cache detected (found_items). Upgrading to schema 9.")
            c = _empty_cache()

        if not isinstance(c.get("schema"), int):
            c["schema"] = CACHE_SCHEMA

        # Schema upgrade
        if c.get("schema", 0) < CACHE_SCHEMA:
            print(f"🔄 Migrating cache schema {c.get('schema')} -> {CACHE_SCHEMA} (keeping data).")
            c["schema"] = CACHE_SCHEMA
            c.setdefault("urls_seen", {})
            c.setdefault("content_seen", {})
            c.setdefault("gmina_seeds", {})
            c.setdefault("page_fprints", {})
            c.setdefault("gmina_frontiers", {})
            c.setdefault("gmina_retry", {})
            c.setdefault("dead_urls", {})

        # Validate structures
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

        pf = c.get("page_fprints", {})
        if not isinstance(pf, dict):
            pf = {}
            c["page_fprints"] = pf

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

        print(
            f"📦 Cache loaded: {len(urls)} URLs, {len(content)} content, "
            f"{len(gseeds)} gmina seeds, {len(pf)} page_fprints, {len(dead)} dead"
        )

        return c, set(urls.keys()), content, gseeds, pf, gf, gr, dead

    except Exception as e:
        print(f"⚠️ Cache load error: {e}")
        c = _empty_cache()
        return c, set(), {}, {}, {}, {}, {}, {}


def save_cache_v2(raw_cache, urls_seen_set, content_seen, gmina_seeds, page_fprints):
    out = {"schema": CACHE_SCHEMA}

    # URLs seen
    out["urls_seen"] = {}
    old_urls = (raw_cache or {}).get("urls_seen", {}) if isinstance(raw_cache, dict) else {}
    for h in urls_seen_set:
        out["urls_seen"][h] = old_urls.get(h, now_iso())

    # Direct copies
    out["content_seen"] = content_seen or {}
    out["gmina_seeds"] = gmina_seeds or {}
    out["page_fprints"] = page_fprints or {}

    # Use passed-in values, not global state
    out["gmina_frontiers"] = state.gmina_frontiers or {}
    out["gmina_retry"] = state.gmina_retry or {}

    # Dead URLs
    out["dead_urls"] = state.dead_urls or {}

    tmp = str(CACHE_FILE) + ".tmp"

    def _do_save():
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CACHE_FILE)

    retry_io(_do_save, tries=6, base_sleep=0.7)

    print(
        f"💾 Cache saved: {len(urls_seen_set)} URLs, {len(out['content_seen'])} content, "
        f"{len(out['gmina_seeds'])} seeds, {len(out['page_fprints'])} fprints, "
        f"{len(out['dead_urls'])} dead"
    )


def purge_old_cache(raw_cache: dict, urls_seen_set: set, content_seen: dict,
                    gmina_seeds: dict, page_fprints: dict, dead_urls: dict):

    cutoff = datetime.now() - timedelta(days=SCANNED_TTL_DAYS)

    # URLs TTL
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

    # Seed TTL
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

    # Fingerprint TTL
    to_del_pf = []
    for k, meta in list((page_fprints or {}).items()):
        try:
            ts = (meta or {}).get("ts", "")
            if ts and datetime.fromisoformat(ts) < cutoff:
                to_del_pf.append(k)
        except Exception:
            to_del_pf.append(k)

    for k in to_del_pf:
        page_fprints.pop(k, None)

    # Dead URLs TTL intentionally left unchanged
