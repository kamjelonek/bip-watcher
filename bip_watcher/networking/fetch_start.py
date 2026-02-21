# networking/fetch_start.py
"""
Compatibility wrapper for fetch/start helpers.

This module re-exports the start/fetch helpers so other modules can import:
    from bip_watcher.networking.fetch_start import (
        fetch_start_matrix,
        fetch_text_best_effort,
        fetch_with_retry,
        _aio_fetch_raw,
        parse_sitemap_xml,
        _looks_like_xml_sitemap,
    )

The original monolithic script grouped these helpers together. After refactor
they live in fetch_normal.py and sitemap.py. This wrapper keeps the public API
stable and avoids cyclic imports.
"""

# Import ONLY safe, top-level functions (no cyclic imports)
from bip_watcher.networking.fetch_normal import (
    fetch_start_matrix,
    fetch_text_best_effort,
    fetch_with_retry,
    _aio_fetch_raw,
)

from bip_watcher.networking.sitemap import (
    parse_sitemap_xml,
    _looks_like_xml_sitemap,
)

__all__ = [
    "fetch_start_matrix",
    "fetch_text_best_effort",
    "fetch_with_retry",
    "_aio_fetch_raw",
    "parse_sitemap_xml",
    "_looks_like_xml_sitemap",
]
