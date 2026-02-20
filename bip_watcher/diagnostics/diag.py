# diagnostics/diag.py
from collections import defaultdict
from bip_watcher.config import DIAG_GMINY_CSV, DIAG_ERRORS_CSV
import csv, json
from bip_watcher.utils import now_iso, retry_io

def diag_new():
    return {
        "start_attempts": [],
        "start_matrix": [],
        "errors": [],
        "counts": defaultdict(int),
        "notes": [],
        "trace": {"phase":"", "last_url":"", "last_kind":"", "last_status":None, "last_ms":None},
    }

def diag_add_error(diag, gmina, url, stage, kind, status, err):
    diag["counts"][f"err_{kind}"] += 1
    if status:
        diag["counts"][f"status_{status}"] += 1
    if len(diag["errors"]) < 60:
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
