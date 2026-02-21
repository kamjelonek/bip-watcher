# diagnostics/diag.py

from collections import defaultdict
import csv
import json

from bip_watcher.utils import now_iso, retry_io


def diag_new():
    return {
        "start_attempts": [],
        "start_matrix": [],
        "errors": [],
        "counts": defaultdict(int),
        "notes": [],
        "trace": {
            "phase": "",
            "last_url": "",
            "last_kind": "",
            "last_status": None,
            "last_ms": None,
        },
    }


def diag_add_error(diag, gmina, url, stage, kind, status, err):
    diag["counts"][f"err_{kind}"] += 1
    if status:
        diag["counts"][f"status_{status}"] += 1

    # limit errors to 60 per gmina
    if len(diag["errors"]) < 60:
        diag["errors"].append({
            "gmina": gmina,
            "url": url,
            "stage": stage,
            "kind": kind,
            "status": status,
            "err": (err or "")[:260],
        })


def trace_set(diag, phase, url="", kind="", status=None, ms=None):
    tr = diag["trace"]
    tr["phase"] = phase or tr["phase"]
    if url:
        tr["last_url"] = url
    if kind:
        tr["last_kind"] = kind
    if status is not None:
        tr["last_status"] = status
    if ms is not None:
        tr["last_ms"] = ms


def print_start_fail_report(diag, gmina: str, start_url: str):
    print(f"\n🧩 START_FAIL REPORT: {gmina}")

    tr = diag.get("trace", {})
    print(
        f"   trace: phase={tr.get('phase')} "
        f"kind={tr.get('last_kind')} "
        f"status={tr.get('last_status')} "
        f"ms={tr.get('last_ms')}"
    )

    notes = diag.get("notes")
    if notes:
        print(f"   notes: {' | '.join(notes)[:900]}")

    sa = diag.get("start_attempts", [])
    print(f"   start_attempts={len(sa)} (TOP 8)")

    for i, x in enumerate(sa[:8], 1):
        print(
            f"   {i:02d}) kind={x.get('kind')} "
            f"status={x.get('status')} "
            f"ms={x.get('ms')} "
            f"url={x.get('try_url')[:100]}"
        )
