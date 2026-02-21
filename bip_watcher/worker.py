# worker.py

import asyncio
import time

from bip_watcher.phases.phase1 import phase1_discover
from bip_watcher.phases.phase2 import phase2_focus

from bip_watcher.diagnostics.diag import (
    diag_add_error,
    diag_new,
    trace_set,
    print_start_fail_report,
)

from bip_watcher.cache import save_cache_v2, purge_old_cache
from bip_watcher.state import state
from bip_watcher.config import *
from bip_watcher.utils import now_iso

from bip_watcher.runner import GLOBAL_T0   # <-- brakujący import


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

            # Deadline
            if RUN_DEADLINE_MIN > 0 and (time.time() - GLOBAL_T0) > (RUN_DEADLINE_MIN * 60):
                state.request_shutdown()

            if state.shutdown_requested:
                try:
                    await queue.put((gmina, start_url))
                except Exception:
                    pass
                return

            # ONLY_GMINA filter
            if ONLY_GMINA and ONLY_GMINA.strip().lower() != (gmina or "").strip().lower():
                queue.task_done()
                continue

            print(f"\n🔎 [{name}] START: {gmina} -> {start_url}", flush=True)

            # PHASE 1
            seed_urls, p1meta = await phase1_discover(
                gmina=gmina,
                start_url=start_url,
                session_default=session_default,
                session_ipv4=session_ipv4,
                session_crawl=session_crawl,
                urls_seen=urls_seen,
                diag=diag,
            )

            if (p1meta or {}).get("status") != "OK":
                print_start_fail_report(diag, gmina, start_url)

                state.diag_rows.append({
                    "datetime": now_iso(),
                    "gmina": gmina,
                    "start_url": start_url,
                    "status": "START_FAIL",
                    "phase1_seeds": int((p1meta or {}).get("seeds", 0) or 0),
                    "phase2_pages_ok": 0,
                    "notes": diag.get("notes", []),
                    "counts": dict(diag.get("counts", {})),
                })

                for e in diag.get("errors", []):
                    state.diag_errors.append(e)

                print(f"✅ [{name}] DONE: {gmina} (found 0)", flush=True)
                continue

            allowed_host = (p1meta or {}).get("allowed_host", "")

            # PHASE 2
            found, p2meta = await phase2_focus(
                gmina=gmina,
                seed_urls=seed_urls,
                session_crawl=session_crawl,
                allowed_host=allowed_host,
                urls_seen=urls_seen,
                content_seen=content_seen,
                diag=diag,
            )

            # Add found items to mail queue
            if found:
                state.new_items_for_mail.extend(found)

            stop_reason = (p2meta or {}).get("stop_reason") or ""
            frontier_len = int((p2meta or {}).get("frontier_len", 0) or 0)
            retry_len = int((p2meta or {}).get("retry_len", 0) or 0)

            status = "OK"
            if stop_reason and stop_reason != "QUEUE_EMPTY":
                status = "INCOMPLETE"

            state.diag_rows.append({
                "datetime": now_iso(),
                "gmina": gmina,
                "start_url": start_url,
                "status": status,
                "phase1_seeds": int((p1meta or {}).get("seeds", 0) or 0),
                "phase2_pages_ok": int((p2meta or {}).get("pages_ok", 0) or 0),
                "notes": diag.get("notes", []) + [
                    f"stop_reason={stop_reason}",
                    f"frontier_len={frontier_len}",
                    f"retry_len={retry_len}",
                ],
                "counts": dict(diag.get("counts", {})),
            })

            for e in diag.get("errors", []):
                state.diag_errors.append(e)

            checkpoint_counter["done"] = checkpoint_counter.get("done", 0) + 1

            # Periodic cache save
            if USE_CACHE and (checkpoint_counter["done"] % CACHE_CHECKPOINT_EVERY_N_GMINY == 0):
                try:
                    save_cache_v2(
                        state.raw_cache,
                        state.urls_seen,
                        state.content_seen,
                        state.gmina_seeds,
                        state.page_fprints,
                    )
                    purge_old_cache(
                        state.raw_cache,
                        state.urls_seen,
                        state.content_seen,
                        state.gmina_seeds,
                        state.page_fprints,
                        state.dead_urls,
                    )
                except Exception as ex:
                    print(f"⚠️ checkpoint save failed: {ex}", flush=True)

            print(
                f"✅ [{name}] DONE: {gmina} (found {len(found)}, frontier={frontier_len}, retry={retry_len})",
                flush=True,
            )

            if frontier_len == 0 and retry_len == 0:
                print(f"   ✅ Gmina {gmina} – pełne przeskanowanie (frontier i retry puste)")

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
                    "datetime": now_iso(),
                    "gmina": gmina or "",
                    "start_url": start_url or "",
                    "status": "WORKER_ERROR",
                    "phase1_seeds": 0,
                    "phase2_pages_ok": 0,
                    "notes": diag.get("notes", []) + [f"worker_exc={str(e)[:160]}"],
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
                queue.task_done()
