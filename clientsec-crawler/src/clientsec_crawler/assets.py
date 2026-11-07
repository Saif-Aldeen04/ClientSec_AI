"""Asset registry and downloading (JavaScript and CSS referenced by pages)."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from .config import CrawlConfig
from .errors import FetchError
from .fetcher import CSS_TYPES, JS_TYPES, Fetcher, decode_body
from .scope import ScopePolicy

JAVASCRIPT = "javascript"
CSS = "css"

ErrorSink = Callable[..., None]


@dataclass
class AssetRecord:
    url: str
    type: str
    asset_id: str
    fetch_status: str = "pending"  # fetched | error | skipped | pending
    skip_reason: str | None = None
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    content_sha256: str | None = None
    content: str | None = None
    referenced_by: list[str] = field(default_factory=list)
    error: dict | None = None

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "url": self.url,
            "type": self.type,
            "fetch_status": self.fetch_status,
            "skip_reason": self.skip_reason,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "content": self.content,
            "referenced_by": list(self.referenced_by),
            "error": self.error,
        }


def asset_id_for(url: str) -> str:
    """Stable identifier derived from the normalised URL (not from the content)."""
    return "a_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


class AssetCollector:
    """Tracks every referenced asset once and downloads the permitted ones."""

    def __init__(
        self,
        config: CrawlConfig,
        scope: ScopePolicy,
        fetcher: Fetcher,
        on_error: ErrorSink,
        on_event: Callable[[str, str], None] | None = None,
    ) -> None:
        self._on_event = on_event or (lambda kind, url: None)
        self._config = config
        self._scope = scope
        self._fetcher = fetcher
        self._on_error = on_error
        self._records: dict[str, AssetRecord] = {}
        self._scheduled_fetches = 0
        self.limits_reached: set[str] = set()

    def register(self, url: str, asset_type: str, referrer: str) -> bool:
        """Record a reference. Returns True if the asset is new and must be downloaded."""
        record = self._records.get(url)
        if record is not None:
            if referrer not in record.referenced_by:
                record.referenced_by.append(referrer)
            return False
        record = AssetRecord(url=url, type=asset_type, asset_id=asset_id_for(url))
        record.referenced_by.append(referrer)
        self._records[url] = record
        if (asset_type == JAVASCRIPT and not self._config.fetch_js) or (
            asset_type == CSS and not self._config.fetch_css
        ):
            record.fetch_status, record.skip_reason = "skipped", "asset_type_disabled"
            self._on_event("asset_skipped", url)
            return False
        if not self._config.fetch_assets:
            record.fetch_status, record.skip_reason = "skipped", "asset_fetching_disabled"
            self._on_event("asset_skipped", url)
            return False
        decision = self._scope.check_asset_url(url)
        if not decision.allowed:
            record.fetch_status, record.skip_reason = "skipped", decision.reason
            self._on_event("asset_skipped", url)
            return False
        if self._scheduled_fetches >= self._config.max_assets:
            self.limits_reached.add("max_assets")
            record.fetch_status, record.skip_reason = "skipped", "asset_limit_reached"
            self._on_event("asset_skipped", url)
            return False
        self._scheduled_fetches += 1
        return True

    async def fetch(self, url: str) -> None:
        record = self._records[url]
        accepted = JS_TYPES if record.type == JAVASCRIPT else CSS_TYPES
        try:
            result = await self._fetcher.fetch(
                url,
                kind="asset",
                accepted_types=accepted,
                max_bytes=self._config.max_asset_bytes,
            )
        except FetchError as exc:
            record.fetch_status = "error"
            record.final_url = exc.final_url or url
            record.status_code = exc.status_code
            record.content_type = exc.content_type
            record.error = {"code": exc.code, "message": exc.message}
            self._on_error(
                operation="fetch_asset",
                url=url,
                code=exc.code,
                message=exc.message,
                status_code=exc.status_code,
            )
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # defensive: one bad asset must not stop the crawl
            record.fetch_status = "error"
            record.error = {"code": "internal_error", "message": type(exc).__name__}
            self._on_error(
                operation="fetch_asset", url=url, code="internal_error", message=type(exc).__name__
            )
            return
        record.fetch_status = "fetched"
        record.final_url = result.final_url
        record.status_code = result.status_code
        record.content_type = result.content_type
        record.size_bytes = len(result.body)
        record.content_sha256 = hashlib.sha256(result.body).hexdigest()
        record.content = decode_body(result.body, result.content_type_header)
        self._on_event("asset_fetched", url)

    def records(self) -> list[AssetRecord]:
        return list(self._records.values())
