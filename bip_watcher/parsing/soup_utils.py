# parsing/soup_utils.py
import re
from bs4 import BeautifulSoup
from bip_watcher.config import FAST_TEXT_MAX_CHARS, ATT_EXT
from bip_watcher.utils import safe_soup, now_iso, sha1

_KILL_UI_RE = re.compile(
    r"(menu|nav|navbar|sidebar|panel|left|right|breadcrumbs|okruszk|stopka|footer|header|"
    r"cookie|rodo|deklaracja|dostepn|dostępn|wyszuk|search|login|logowan|"
    r"share|udostepn|udostępn|drukuj|print|rss|"
    r"skroty|skróty|szybkie|quick|shortcut|przydatne|polecane|na-skróty|na-skroty|links|linki)",
    re.IGNORECASE
)

def extract_title_h1_h2(soup: BeautifulSoup):
    if not soup:
        return "", "", "", ""

    def _clean(s: str) -> str:
        s = re.sub(r"\s+", " ", (s or "")).strip()
        return s

    title = _clean(soup.title.get_text(" ", strip=True) if soup.title else "")

    h1 = soup.find("h1")
    h2 = soup.find("h2")
    h3 = soup.find("h3")

    h1t = _clean(h1.get_text(" ", strip=True) if h1 else "")
    h2t = _clean(h2.get_text(" ", strip=True) if h2 else "")
    h3t = _clean(h3.get_text(" ", strip=True) if h3 else "")

    if not (h1t or h2t or h3t):
        fallback_selectors = [
            "#page-title", "#pagetitle", "#content-title", "#title",
            ".page-title", ".entry-title", ".post-title", ".article-title",
            ".tytul", ".tytuł", ".naglowek", ".nagłowek", ".naglowekStrony",
            ".title", "header .title", "header .page-title",
        ]
        for sel in fallback_selectors:
            try:
                node = soup.select_one(sel)
                if node:
                    txt = _clean(node.get_text(" ", strip=True))
                    if txt and len(txt) >= 6:
                        h1t = txt
                        break
            except Exception:
                continue

    meta_desc = ""
    try:
        meta = soup.find("meta", attrs={"name": "description"})
        if meta and meta.get("content"):
            meta_desc = _clean(meta.get("content", ""))
    except Exception:
        meta_desc = ""

    blob = _clean(f"{title} {h1t} {h2t} {h3t} {meta_desc}")
    return title, h1t, h2t, blob

def _strip_dynamic_noise(txt: str) -> str:
    if not txt:
        return ""
    txt = re.sub(
        r"wygenerowano:\s*\d{1,2}\s+[a-ząćęłńóśźż]+\s+\d{4}\s*r?\.?\s*\d{1,2}:\d{2}:\d{2}",
        "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(
        r"wygenerowano:\s*\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\s+\d{1,2}:\d{2}:\d{2}",
        "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(r"(wyświetleń|wyswietlen|odsłon|odslon|pobrań|pobran)\s*:\s*\d+", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"odsłony:\s*\d+", "", txt, flags=re.IGNORECASE)
    txt = re.sub(
        r"data\s+(publikacji|modyfikacji|utworzenia|aktualizacji)\s*:\s*[\d\-\.:/ ]{6,}",
        "", txt, flags=re.IGNORECASE
    )
    txt = re.sub(
        r"rejestr\s+zmian.*?(?=(załączniki|zalaczniki|dokumenty|pliki|$))",
        "", txt, flags=re.IGNORECASE | re.DOTALL
    )
    txt = re.sub(r"nowe zasady dotyczące cookies.*?(?=$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"polityka prywatności.*?(?=$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"deklaracja dostępności.*?(?=$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(udostępniający|udostepniajacy)\s*:\s*.*?(?=\s{2,}|$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(wytworzył|wytworzyl|wytworzone\s+przez)\s*:\s*.*?(?=\s{2,}|$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(odpowiedzialny|odpowiedzialna)\s*:\s*.*?(?=\s{2,}|$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(data\s+wytworzenia|data\s+utworzenia|data\s+publikacji)\s*:\s*.*?(?=\s{2,}|$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(data\s+zmiany|data\s+modyfikacji|ostatnia\s+modyfikacja)\s*:\s*.*?(?=\s{2,}|$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"(rejestr\s+zmian|historia\s+zmian)\s*:\s*.*?(?=$)", "", txt, flags=re.IGNORECASE)
    txt = re.sub(r"\s+", " ", txt).strip()
    return txt

def _pick_main_container(soup: BeautifulSoup):
    selectors = [
        "main", "article",
        "#content", "#main", "#page", "#primary",
        ".content", ".main", ".page-content", ".entry-content",
        ".article", ".post", ".news", ".text", ".tresc", ".treść",
        ".bip-content", ".content-area"
    ]
    for sel in selectors:
        try:
            node = soup.select_one(sel)
            if node:
                t = node.get_text(" ", strip=True)
                if t and len(t) > 80:
                    return node
        except Exception:
            pass
    return soup

def _soup_fast_text(soup: BeautifulSoup, max_chars: int = FAST_TEXT_MAX_CHARS) -> str:
    try:
        if not soup:
            return ""
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        for tag in soup.find_all(["nav", "footer", "header", "aside"]):
            tag.decompose()
        for el in list(soup.find_all(True, attrs={"class": True})):
            try:
                cls = " ".join(el.get("class") or [])
                if cls and _KILL_UI_RE.search(cls):
                    el.decompose()
            except Exception:
                continue
        for el in list(soup.find_all(True, attrs={"id": True})):
            try:
                _id = (el.get("id") or "")
                if _id and _KILL_UI_RE.search(_id):
                    el.decompose()
            except Exception:
                continue
        for hdr in soup.find_all(["h2", "h3", "h4"]):
            try:
                t = (hdr.get_text(" ", strip=True) or "").lower()
                if any(x in t for x in ["metryka", "rejestr zmian", "historia zmian",
                                        "skróty", "skroty", "na skróty", "na skroty",
                                        "przydatne linki", "szybkie linki", "polecane"]):
                    parent = hdr.find_parent(["section", "div", "article", "table"]) or hdr.parent
                    if parent:
                        parent.decompose()
            except Exception:
                pass
        main = _pick_main_container(soup)
        txt = main.get_text(" ", strip=True)
        txt = re.sub(r"\s+", " ", (txt or "")).strip()
        txt = _strip_dynamic_noise(txt)
        if len(txt) > max_chars:
            txt = txt[:max_chars]
        return txt
    except Exception:
        return ""

def page_fingerprint(title: str, h1: str, fast_text: str) -> str:
    base = f"{(title or '')[:180]}|{(h1 or '')[:180]}|{(fast_text or '')}"
    return sha1(base)

def attachments_signature(soup: BeautifulSoup, base_url: str) -> str:
    if not soup:
        return ""
    items = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        abs_u = normalize_url(urljoin(base_url, href))
        low = abs_u.lower()
        if not any(low.endswith(ext) for ext in ATT_EXT):
            continue
        p = urlparse(abs_u)
        clean_url = urlunparse((
            "https",
            p.netloc.lower().lstrip("www."),
            p.path,
            "",
            "",
            ""
        ))
        txt = a.get_text(" ", strip=True) or ""
        size = ""
        m = re.search(
            r"(\d+(?:[.,]\d+)?)\s*(kb|mb|gb)",
            txt,
            flags=re.IGNORECASE
        )
        if m:
            size = m.group(1).replace(",", ".") + m.group(2).lower()
        items.append((clean_url, size))
    if not items:
        return ""
    items.sort()
    blob = "||".join([f"{u}::{s}" for u, s in items])
    return sha1(blob)
