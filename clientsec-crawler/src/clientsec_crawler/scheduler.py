"""Crawl queue, de-duplication and depth/page limits (no I/O)."""

from __future__ import annotations

import asyncio

from .config import CrawlConfig

QUEUED = "queued"
ALREADY_SEEN = "already_seen"
SKIPPED_DEPTH = "skipped_depth_limit"
SKIPPED_PAGES = "skipped_page_limit"


class CrawlScheduler:
    """FIFO (breadth-first) work queue with a visited set.

    ``try_enqueue`` is synchronous, so check-and-insert is atomic with respect to the
    event loop: two workers can never schedule the same URL twice.
    """

    def __init__(self, config: CrawlConfig) -> None:
        self._config = config
        self.queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._seen: set[str] = set()
        self._scheduled = 0
        self.limits_reached: set[str] = set()

    @property
    def pages_scheduled(self) -> int:
        return self._scheduled

    def mark_seen(self, url: str) -> None:
        """Record a URL (e.g. a redirect destination) so it is never scheduled later."""
        self._seen.add(url)

    def try_enqueue(self, url: str, depth: int) -> str:
        if url in self._seen:
            return ALREADY_SEEN
        if depth > self._config.max_depth:
            self.limits_reached.add("max_depth")
            return SKIPPED_DEPTH
        if self._scheduled >= self._config.max_pages:
            self.limits_reached.add("max_pages")
            return SKIPPED_PAGES
        self._seen.add(url)
        self._scheduled += 1
        self.queue.put_nowait((url, depth))
        return QUEUED
