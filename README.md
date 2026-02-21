---

# Opis modułów

## main.py
Minimalny punkt startowy.  
Uruchamia funkcję `run_main_vscode_style()` z `runner.py`.  
Dzięki temu cały projekt można uruchomić poleceniem:


---

## runner.py
Centralny koordynator działania programu:

- ładuje cache,
- tworzy sesje `aiohttp`,
- buduje kolejkę zadań (gmin),
- uruchamia wiele workerów równolegle,
- uruchamia okresowe checkpointy,
- zapisuje wyniki i generuje podsumowanie.

To główna logika sterująca całym procesem.

---

## worker.py
Każdy worker:

- pobiera z kolejki `(gmina, start_url)`,
- wykonuje **Phase 1** (odkrywanie stron),
- wykonuje **Phase 2** (skanowanie treści),
- zapisuje wyniki do struktur globalnych,
- dodaje wpisy diagnostyczne,
- wywołuje checkpointy cache.

To „robot” wykonujący pracę dla jednej gminy.

---

## state.py
Zawiera globalny obiekt `state`, który przechowuje:

- cache w pamięci,
- listę nowych znalezisk,
- retry listy,
- dead URLs,
- diagnostykę,
- flagę `shutdown_requested`.

Obsługuje także sygnały systemowe (Ctrl+C) do bezpiecznego zatrzymania.

---

## cache.py
Odpowiada za:

- ładowanie cache (`load_cache_v2`),
- zapisywanie cache (`save_cache_v2`),
- czyszczenie starych wpisów (`purge_old_cache`),
- obsługę cache seedów (Phase 1),
- kompatybilność ze strukturą shardów używaną w GitHub Actions.

To fundament trwałości danych między uruchomieniami.

---

## config.py
Zawiera wszystkie ustawienia:

- ścieżki plików,
- limity wydajności,
- timeouty,
- listy słów kluczowych,
- listy ignorowanych linków,
- user-agenty,
- parametry środowiskowe,
- stałe używane w Phase 1 i Phase 2.

To jedyne miejsce, gdzie zmienia się konfigurację działania skanera.

---

## utils.py
Zbiór funkcji pomocniczych:

- normalizacja URL,
- canonicalizacja URL,
- skróty SHA1,
- funkcje czasu,
- `retry_io`,
- bezpieczne tworzenie BeautifulSoup,
- drobne narzędzia używane w wielu modułach.

---

# networking/

## rate_limiter.py
Asynchroniczny limiter domen:

- pilnuje opóźnień między requestami,
- stosuje backoff przy 403/429,
- zapobiega blokadom i przeciążeniu serwerów BIP.

---

## fetch_normal.py
Główna logika HTTP:

- `fetch_start_matrix` — inteligentne próby startowe (różne strategie),
- `fetch` — standardowy fetch HTML,
- `fetch_conditional` — fetch z ETag/Last-Modified,
- `fetch_with_retry` — retry z backoffem,
- `_probe_with_requests` — fallback synchroniczny,
- wykrywanie PDF, blokad, błędów.

To serce komunikacji sieciowej.

---

## fetch_start.py
Warstwa kompatybilności — re-eksportuje funkcje startowe, aby moduły mogły importować z jednego miejsca.

---

## sitemap.py
Obsługa sitemap:

- wykrywanie sitemap,
- parsowanie XML,
- ekstrakcja URL-i,
- deduplikacja.

Używane w Phase 1 do generowania seedów.

---

# parsing/

## soup_utils.py
Zaawansowane przetwarzanie HTML:

- ekstrakcja tytułów, nagłówków, meta,
- czyszczenie szumu,
- wyciąganie głównego tekstu,
- fingerprint treści,
- fingerprint załączników.

---

## link_extraction.py
Szybkie i filtrowane wyciąganie linków:

- ignorowanie śmieciowych linków,
- wykrywanie załączników,
- heurystyki priorytetów,
- filtrowanie anchorów.

---

## keyword_match.py
Silnik dopasowywania słów kluczowych:

- dopasowania ścisłe i luźne,
- obsługa `STRICT_ONLY`,
- wykrywanie słów w blobach i anchorach.

---

# phases/

## phase1.py — Discovery
Odpowiada za:

- próby startowe,
- wykrywanie hosta głównego,
- pobieranie sitemap,
- heurystyki JS-heavy,
- BFS po stronie,
- generowanie seedów do Phase 2.

---

## phase2.py — Focused Scan
Odpowiada za:

- pobieranie stron z seedów,
- TTL dla HIT/NO_MATCH/BLOCKED/FAILED,
- fingerprinting treści,
- wykrywanie zmian,
- wykrywanie słów kluczowych,
- wykrywanie linków z dopasowaniem,
- retry i dead URLs.

To właściwy skaner treści.

---

# diagnostics/

## diag.py
Zawiera:

- struktury diagnostyczne,
- zapisy błędów,
- śledzenie ostatniego URL,
- raport start-fail.

---

## summary.py
Generuje:

- `diag_gminy.csv`,
- `diag_errors.csv`,
- `summary_report.txt`,
- opcjonalny eksport do OneDrive.

# BIP Watcher — Kluczowe metody (LITE MODE)

Ten dokument opisuje najważniejsze funkcje w projekcie BIP Watcher, ich rolę oraz powiązania z innymi modułami.

---

# main.py

### run_main_vscode_style()
Uruchamia główną pętlę programu (`runner.main()`), dbając o kompatybilność z VS Code / środowiskami interaktywnymi.  
**Wywołuje:** `runner.main()`.

---

# runner.py

### main()
Centralna funkcja programu:
- ładuje cache (`load_cache_v2`),
- tworzy sesje aiohttp,
- buduje kolejkę gmin,
- uruchamia workerów (`worker()`),
- uruchamia checkpointy (`save_cache_v2`, `save_diag`),
- zapisuje podsumowanie (`write_summary`).

**Wywołuje:**  
`load_cache_v2`, `purge_old_cache`, `worker`, `save_cache_v2`, `save_diag`, `write_summary`, `export_summary_to_onedrive`.

---

# worker.py

### worker()
Główna pętla robocza dla jednej gminy:
- pobiera zadanie z kolejki,
- wykonuje Phase 1 (`phase1_discover`),
- wykonuje Phase 2 (`phase2_focus`),
- zapisuje diagnostykę,
- wywołuje checkpointy cache.

**Wywołuje:**  
`phase1_discover`, `phase2_focus`, `save_cache_v2`, `diag_add_error`.

---

# state.py

### GlobalState
Obiekt przechowujący:
- cache,
- retry listy,
- dead URLs,
- diagnostykę,
- flagę `shutdown_requested`.

### request_shutdown()
Ustawia flagę zatrzymania, używane przy Ctrl+C.

---

# cache.py

### load_cache_v2()
Ładuje cache z pliku `cache.json`, migruje schemat, waliduje strukturę.  
**Wywołuje:** `retry_io`.

### save_cache_v2()
Zapisuje cache na dysk, tworzy plik tymczasowy, atomowo podmienia.  
**Wywołuje:** `retry_io`.

### purge_old_cache()
Usuwa stare wpisy wg TTL (URL, fingerprinty, seedy, dead URLs).

### seed_cache_get() / seed_cache_put()
Obsługa cache seedów Phase 1.

---

# config.py

### env_int(), env_float(), get_shard_index()
Pomocnicze funkcje do pobierania zmiennych środowiskowych.

---

# utils.py

### normalize_url(), canonical_url()
Normalizacja i kanonizacja URL — kluczowe dla deduplikacji.  
**Używane przez:** Phase 1, Phase 2, link extraction, fetch.

### sha1()
Hashowanie fingerprintów i URL dedup.

### retry_io()
Bezpieczne zapisywanie plików z retry.

### safe_soup()
Tworzy BeautifulSoup z ochroną przed błędami.

---

# networking/

## rate_limiter.py

### DomainRateLimiter.wait()
Wymusza opóźnienie między requestami do tej samej domeny.

### report_403()
Zwiększa penalizację domeny po 403/429.

---

## fetch_normal.py

### fetch_start_matrix()
Próbuje różne strategie pobrania strony startowej:
- różne timeouty,
- różne tryby SSL,
- GET/HEAD,
- fallback przez `requests`.

**Wywołuje:** `_aio_fetch_raw`, `_probe_with_requests`.

### fetch()
Standardowy fetch HTML:
- obsługa SSL fallback,
- wykrywanie PDF,
- wykrywanie blokad,
- zwraca (html, final_url, kind, status).

### fetch_conditional()
Fetch z obsługą ETag / Last-Modified.  
**Używane w Phase 2.**

### fetch_text_best_effort()
Szybki fetch używany w startowych próbach.

---

## sitemap.py

### parse_sitemap_xml()
Parsuje sitemap XML, zwraca listę URL-i i listę sitemap podrzędnych.

### _looks_like_xml_sitemap()
Heurystyka wykrywania sitemap.

---

# parsing/

## soup_utils.py

### extract_title_h1_h2()
Wyciąga tytuł, H1, H2, meta description.  
**Używane w Phase 2.**

### _soup_fast_text()
Czyści HTML i wyciąga główny tekst strony.  
**Używane do fingerprintów.**

### page_fingerprint()
Tworzy fingerprint treści (title + h1 + tekst).  
**Używane do wykrywania zmian.**

### attachments_signature()
Tworzy fingerprint załączników (PDF, DOC, GML itd.).  
**Używane do wykrywania zmian.**

---

## link_extraction.py

### iter_links_fast()
Szybkie wyciąganie linków z priorytetami i filtrami.  
**Używane w Phase 1 i Phase 2.**

### should_skip_href()
Filtruje linki nieistotne / śmieciowe.

### anchor_is_ignored()
Filtruje linki na podstawie tekstu anchorów.

---

## keyword_match.py

### keyword_match_in_blob()
Sprawdza, czy w tekście występują słowa kluczowe (MPZP, WZ, OZE itd.).  
**Używane w Phase 2 i przy linkach.**

---

# phases/

## phase1.py

### phase1_discover()
Główna logika odkrywania:
- próby startowe (`fetch_start_matrix`),
- wykrywanie hosta,
- pobieranie sitemap (`collect_sitemap_urls`),
- BFS po stronie (`fetch`),
- generowanie seedów.

**Wywołuje:**  
`fetch_start_matrix`, `collect_sitemap_urls`, `fetch`, `iter_links_fast`.

---

## phase2.py

### phase2_focus()
Główna logika skanowania treści:
- conditional fetch (`fetch_conditional`),
- TTL dla poprzednich wyników,
- fingerprint treści (`page_fingerprint`),
- fingerprint załączników (`attachments_signature`),
- wykrywanie słów kluczowych (`keyword_match_in_blob`),
- wykrywanie linków (`iter_links_fast`),
- obsługa retry i dead URLs.

**Wywołuje:**  
`fetch_conditional`, `extract_title_h1_h2`, `_soup_fast_text`, `page_fingerprint`, `attachments_signature`, `keyword_match_in_blob`, `iter_links_fast`.

---

# diagnostics/

## diag.py

### diag_new()
Tworzy pustą strukturę diagnostyczną.

### diag_add_error()
Dodaje wpis błędu do diagnostyki.

### trace_set()
Aktualizuje ostatni stan (phase, url, status).

---

## summary.py

### save_diag()
Zapisuje `diag_gminy.csv` i `diag_errors.csv`.

### write_summary()
Tworzy `summary_report.txt`.

### export_summary_to_onedrive()
Kopiuje summary do folderu OneDrive (jeśli skonfigurowane).

---