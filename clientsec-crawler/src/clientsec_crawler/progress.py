"""Progress events and cooperative, thread-safe cancellation for the crawl engine."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

# kinds: started, page_started, page_fetched, page_failed, asset_fetched, asset_failed,
#        asset_skipped, cancelling, finished
PROGRESS_KINDS = (
    "started",
    "page_started",
    "page_fetched",
    "page_failed",
    "asset_fetched",
    "asset_failed",
    "asset_skipped",
    "cancelling",
    "finished",
)


@dataclass(frozen=True)
class ProgressEvent:
    """One progress notification. ``stats`` is a snapshot of live counters."""

    kind: str
    url: str | None = None
    message: str = ""
    stats: dict = field(default_factory=dict)
    #: Extra details. page_started: depth. page_fetched: depth, title, children (queued URLs),
    #: js, css, inline counts; or duplicate_of for redirect duplicates.
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


ProgressCallback = Callable[[ProgressEvent], None]


class CancellationToken:
    """Request cancellation of a crawl from any thread.

    Pass the same token to ``crawl(..., cancellation_token=token)`` and call ``token.cancel()``
    (e.g. from a GUI thread). The crawl stops scheduling work, cancels in-flight requests, and
    returns the partial result with ``crawl_status == "cancelled"``.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[], None]] = []

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        with self._lock:
            self._event.set()
            callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks:
            try:
                callback()
            except Exception:  # a dead event loop must not break cancel()
                pass

    def _register(self, callback: Callable[[], None]) -> None:
        with self._lock:
            if not self._event.is_set():
                self._callbacks.append(callback)
                return
        callback()

    def _unregister(self, callback: Callable[[], None]) -> None:
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
