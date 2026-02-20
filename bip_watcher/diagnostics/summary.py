# diagnostics/summary.py
from bip_watcher.config import SUMMARY_FILE, ONEDRIVE_EXPORT_DIR, DIAG_GMINY_CSV, DIAG_ERRORS_CSV
from bip_watcher.utils import retry_io, now_iso
import json, re

def save_diag(diag_rows, diag_errors):
    try:
        def _do():
            new_file = not DIAG_GMINY_CSV.exists()
            with open(DIAG_GMINY_CSV, "a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                if new_file:
                    w.writerow([
                        "datetime", "gmina", "start_url", "status",
                        "phase1_seeds", "phase2_pages_ok",
                        "notes", "counts_json"
                    ])
                for r in (diag_rows or []):
                    w.writerow([
                        r.get("datetime"),
                        r.get("gmina"),
                        r.get("start_url"),
                        r.get("status"),
                        r.get("phase1_seeds"),
                        r.get("phase2_pages_ok"),
                        " | ".join(r.get("notes", []) or [])[:900],
                        json.dumps(r.get("counts", {}), ensure_ascii=False)[:5000],
                    ])
            new_file2 = not DIAG_ERRORS_CSV.exists()
            with open(DIAG_ERRORS_CSV, "a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                if new_file2:
                    w.writerow(["datetime", "gmina", "stage", "kind", "status", "url", "err"])
                for e in (diag_errors or []):
                    w.writerow([
                        now_iso(),
                        e.get("gmina"),
                        e.get("stage"),
                        e.get("kind"),
                        e.get("status"),
                        (e.get("url") or "")[:400],
                        (e.get("err") or "")[:300],
                    ])
        retry_io(_do, tries=6, base_sleep=0.7)
    except Exception as ex:
        print(f"⚠️ save_diag failed: {ex}")

def write_summary(diag_rows, new_items_for_mail):
    try:
        total = len(diag_rows or [])
        ok = sum(1 for r in (diag_rows or []) if r.get("status") == "OK")
        start_fail = sum(1 for r in (diag_rows or []) if r.get("status") == "START_FAIL")
        hits_new = 0
        hits_change = 0
        for r in (diag_rows or []):
            c = r.get("counts", {}) or {}
            hits_new += int(c.get("hit_new", 0) or 0)
            hits_change += int(c.get("hit_change", 0) or 0)
        lines = []
        lines.append(f"BIP WATCHER SUMMARY @ {now_iso()}")
        lines.append(f"gminy_total={total} ok={ok} start_fail={start_fail}")
        lines.append(f"hits_new={hits_new} hits_change={hits_change}")
        lines.append(f"mail_items={len(new_items_for_mail or [])}")
        lines.append("")
        lines.append("TOP 50 mail items:")
        for x in (new_items_for_mail or [])[:500]:
            lines.append("- " + re.sub(r"\s+", " ", x).strip())
        def _do():
            with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        retry_io(_do, tries=6, base_sleep=0.7)
        print(f"🧾 Summary saved: {SUMMARY_FILE}")
    except Exception as ex:
        print(f"⚠️ write_summary failed: {ex}")

def export_summary_to_onedrive():
    try:
        if not ONEDRIVE_EXPORT_DIR or str(ONEDRIVE_EXPORT_DIR).strip() == "":
            print("ℹ️ OneDrive export: pominięty (BIP_EXPORT_DIR nie ustawione).")
            return
        if not ONEDRIVE_EXPORT_DIR.exists():
            print(f"ℹ️ OneDrive export: folder nie istnieje: {ONEDRIVE_EXPORT_DIR}")
            return
        if not SUMMARY_FILE.exists():
            print(f"ℹ️ OneDrive export: brak pliku summary: {SUMMARY_FILE}")
            return
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        out_file = ONEDRIVE_EXPORT_DIR / f"summary_{ts}.txt"
        def _do():
            data = SUMMARY_FILE.read_text(encoding="utf-8", errors="ignore")
            out_file.write_text(data, encoding="utf-8")
        retry_io(_do, tries=5, base_sleep=0.4)
        print(f"✅ OneDrive export: {out_file}")
    except Exception as e:
        print(f"⚠️ OneDrive export failed: {e}")
