# runner.py
import asyncio, socket
from bip_watcher.worker import worker
from bip_watcher.state import state
from bip_watcher.cache import load_cache_v2, save_cache_v2, purge_old_cache
from bip_watcher.diagnostics.summary import save_diag, write_summary, export_summary_to_onedrive
from bip_watcher.config import *
from bip_watcher.utils import now_iso
from bip_watcher.worker import worker as worker_func
from bip_watcher.utils import retry_io
from bip_watcher.diagnostics.diag import diag_new
from bip_watcher.worker import worker
from bip_watcher.cache import save_cache_v2
from bip_watcher.diagnostics.summary import save_diag, write_summary, export_summary_to_onedrive
from bip_watcher.state import state

GLOBAL_T0 = time.time()

async def main():
    state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.page_fprints, state.gmina_frontiers, state.gmina_retry, state.dead_urls = load_cache_v2()
    # migrate_content_seen_to_url_dedup omitted (kept in cache module if needed)
    purge_old_cache(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.page_fprints, state.dead_urls)

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

    conn_default = aiohttp.TCPConnector(
        limit=CONCURRENT_REQUESTS,
        limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
        ssl=False
    )
    conn_ipv4 = aiohttp.TCPConnector(
        family=socket.AF_INET,
        limit=CONCURRENT_REQUESTS,
        limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
        ssl=False
    )
    conn_crawl = aiohttp.TCPConnector(
        limit=CONCURRENT_REQUESTS,
        limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
        ssl=False
    )
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
                        save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.page_fprints)
                    save_diag(state.diag_rows, state.diag_errors)
                except Exception as ex:
                    print(f"⚠️ periodic checkpoint failed: {ex}", flush=True)

        workers = [
            asyncio.create_task(
                worker(
                    name=f"W{i+1}",
                    queue=queue,
                    session_default=s_default,
                    session_ipv4=s_ipv4,
                    session_crawl=s_crawl,
                    urls_seen=state.urls_seen,
                    content_seen=state.content_seen,
                    checkpoint_counter=checkpoint_counter
                )
            )
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
            save_cache_v2(state.raw_cache, state.urls_seen, state.content_seen, state.gmina_seeds, state.page_fprints)
        save_diag(state.diag_rows, state.diag_errors)
        write_summary(state.diag_rows, state.new_items_for_mail)
        export_summary_to_onedrive()
    except Exception as e:
        print(f"⚠️  Final save failed: {e}")

    print("✅ SKAN ZAKOŃCZONY")

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
