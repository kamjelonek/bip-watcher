# networking/fetch_start.py
"""
Compatibility wrapper for fetch/start helpers.

This module re-exports the start/fetch helpers so other modules can import
from bip_watcher.networking.fetch_start import fetch_start_matrix, fetch_text_best_effort, _probe_with_requests

The original monolithic script had these helpers grouped together; during
refactor they were implemented in fetch_normal.py and sitemap.py. To keep
the public API stable (and to satisfy imports from other modules), this
file simply imports and re-exports the relevant functions.
"""

from bip_watcher.networking.fetch_normal import (
    fetch_start_matrix,
    fetch_text_best_effort,
    _probe_with_requests,
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
    "_probe_with_requests",
    "fetch_with_retry",
    "_aio_fetch_raw",
    "parse_sitemap_xml",
    "_looks_like_xml_sitemap",
]
