"""Crawl orchestration and the public API (``crawl`` / ``crawl_sync`` / ``Crawler``)."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .assets import CSS, JAVASCRIPT, AssetCollector
from .config import CrawlConfig
from .errors import FetchError, InvalidTargetError
from .fetcher import HTML_TYPES, Fetcher, Resolver, decode_body
from .models import LIMITATIONS, SCHEMA_VERSION, EndpointRecord
from .parser import InlineBlock, parse_html
from .progress import CancellationToken, ProgressCallback, ProgressEvent
from .scheduler import ALREADY_SEEN, QUEUED, SKIPPED_DEPTH, SKIPPED_PAGES, CrawlScheduler
from .scope import ScopePolicy, validate_target_url
from .url_utils import looks_like_non_html_resource, redact_url

log = logging.getLogger("clientsec_crawler")


class _DropHttpxInfoLogs(logging.Filter):
    """httpx logs every request URL (including query strings, which may hold tokens) at INFO."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


_httpx_filter = _DropHttpxInfoLogs()
_httpx_filter_users = 0


def _suppress_httpx_url_logs(enable: bool) -> None:
    """Reference-counted so concurrent crawls in one process do not remove it early."""
    global _httpx_filter_users
    loggers = [logging.getLogger(n) for n in ("httpx", "httpcore")]
    if enable:
        _httpx_filter_users += 1
        for lg in loggers:
            if _httpx_filter not in lg.filters:
                lg.addFilter(_httpx_filter)
    else:
        _httpx_filter_users -= 1
        if _httpx_filter_users <= 0:
            for lg in loggers:
                lg.removeFilter(_httpx_filter)


_ACTION_FOR = {
    QUEUED: "queued",
    ALREADY_SEEN: "already_seen",
    SKIPPED_DEPTH: "skipped_depth_limit",
    SKIPPED_PAGES: "skipped_page_limit",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _block_dict(block: InlineBlock) -> dict:
    return {
        "index": block.index,
        "content": block.content,
        "content_sha256": block.content_sha256,
        "attributes": dict(block.attrs),
    }


class Crawler:
    """One crawl run. Create a new instance per crawl.

    ``resolver`` and ``transport`` are advanced/testing hooks: a custom DNS resolver and an
    ``httpx`` transport. Security checks are applied regardless of what they return.
    """

    def __init__(
        self,
        config: CrawlConfig | None = None,
        *,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        progress_callback: ProgressCallback | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> None:
        self._progress = progress_callback
        self._token = cancellation_token
        self._config = config or CrawlConfig()
        self._include = [re.compile(p) for p in self._config.include_patterns]
        self._exclude = [re.compile(p) for p in self._config.exclude_patterns]
        self._resolver = resolver
        self._transport = transport
        self._endpoints: dict[str, EndpointRecord] = {}
        self._errors: list[dict] = []
        self._out_of_scope: dict[str, dict] = {}
        self._content_owner: dict[str, str] = {}
        self._used = False

    # ------------------------------------------------------------------ public

    async def run(self, target_url: str) -> dict:
        if self._used:
            raise RuntimeError("a Crawler instance can only run once; create a new one")
        self._used = True
        _suppress_httpx_url_logs(True)
        try:
            return await self._run(target_url)
        finally:
            _suppress_httpx_url_logs(False)

    async def _run(self, target_url: str) -> dict:
        started = _now()
        if self._config.unsafe_allow_private_networks:
            log.warning("unsafe_allow_private_networks is enabled: TEST USE ONLY")
        try:
            target = validate_target_url(target_url)
        except InvalidTargetError as exc:
            self._record_error(
                operation="validate_target",
                url=str(target_url)[:200],
                code=exc.code,
                message=exc.message,
            )
            return self._build_result(
                str(target_url)[:200], "failed", started, _now(), set(), None, None
            )

        scope = ScopePolicy(target, self._config)
        self._scope = scope
        self._sched = CrawlScheduler(self._config)
        self._fetcher = Fetcher(
            self._config, scope, resolver=self._resolver, transport=self._transport
        )
        self._collector = AssetCollector(
            self._config,
            scope,
            self._fetcher,
            self._record_error_kwargs,
            on_event=lambda kind, asset_url: self._emit(kind, asset_url),
        )
        limits: set[str] = set()
        cancelled = False
        workers: list[asyncio.Task] = []
        waiters: list[asyncio.Future] = []
        loop = asyncio.get_running_loop()
        cancel_event = asyncio.Event()

        def _on_cancel() -> None:
            try:
                loop.call_soon_threadsafe(cancel_event.set)
            except RuntimeError:  # loop already closed
                pass

        if self._token is not None:
            self._token._register(_on_cancel)
        try:
            self._schedule(target, 0)
            self._emit("started", target, "crawl started")
            workers = [
                asyncio.create_task(self._worker(), name=f"crawl-worker-{i}")
                for i in range(self._config.max_concurrency)
            ]
            join_task = asyncio.ensure_future(self._sched.queue.join())
            cancel_task = asyncio.ensure_future(cancel_event.wait())
            waiters = [join_task, cancel_task]
            done, _ = await asyncio.wait(
                waiters,
                timeout=self._config.max_crawl_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_task in done:
                cancelled = True
                self._emit("cancelling", None, "cancellation requested")
            elif join_task not in done:
                limits.add("max_crawl_seconds")
        finally:
            if self._token is not None:
                self._token._unregister(_on_cancel)
            for task in [*workers, *waiters]:
                task.cancel()
            await asyncio.gather(*workers, *waiters, return_exceptions=True)
            await self._fetcher.aclose()

        limits |= self._sched.limits_reached | self._collector.limits_reached
        for record in self._endpoints.values():
            if record.fetch_status == "pending":
                record.fetch_status = "not_fetched"
        first = self._endpoints.get(target)
        if cancelled:
            status = "cancelled"
        elif first is not None and first.fetch_status == "error":
            status = "failed"
        elif limits:
            status = "partial"
        else:
            status = "completed"
        self._emit("finished", target, f"crawl {status}")
        return self._build_result(
            target, status, started, _now(), limits, scope.target_origin, self._collector
        )

    def _stats(self) -> dict:
        endpoints = list(self._endpoints.values())
        collector = getattr(self, "_collector", None)
        assets = collector.records() if collector else []
        return {
            "pages_discovered": len(endpoints),
            "pages_fetched": sum(1 for e in endpoints if e.html is not None),
            "pages_failed": sum(1 for e in endpoints if e.fetch_status == "error"),
            "assets_discovered": len(assets),
            "assets_fetched": sum(1 for a in assets if a.fetch_status == "fetched"),
            "assets_skipped": sum(1 for a in assets if a.fetch_status == "skipped"),
            "out_of_scope_urls": len(self._out_of_scope),
            "errors_count": len(self._errors),
        }

    def _passes_filters(self, url: str) -> bool:
        parts = urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        if self._include and not any(p.search(target) for p in self._include):
            return False
        return not any(p.search(target) for p in self._exclude)

    def _emit(
        self, kind: str, url: str | None = None, message: str = "", data: dict | None = None
    ) -> None:
        """Notify the progress callback. Called on the event-loop thread; never raises."""
        if self._progress is None:
            return
        try:
            self._progress(ProgressEvent(kind, url, message, self._stats(), data or {}))
        except Exception:
            log.warning("progress callback raised; ignoring", exc_info=True)

    # ------------------------------------------------------------------ internals

    def _record_error(
        self,
        *,
        operation: str,
        url: str,
        code: str,
        message: str,
        status_code: int | None = None,
    ) -> None:
        self._errors.append(
            {
                "url": url,
                "operation": operation,
                "code": code,
                "message": message,
                "status_code": status_code,
            }
        )
        log.info("%s failed for %s: %s", operation, redact_url(url), code)
        kind = {"fetch_asset": "asset_failed", "validate_target": "page_failed"}.get(
            operation, "page_failed"
        )
        self._emit(kind, url, f"{code}: {message}"[:300])

    def _record_error_kwargs(self, **kwargs) -> None:
        self._record_error(**kwargs)

    def _schedule(self, url: str, depth: int) -> str:
        result = self._sched.try_enqueue(url, depth)
        if result == QUEUED:
            self._endpoints[url] = EndpointRecord(url=url, depth=depth)
        return result

    async def _worker(self) -> None:
        queue = self._sched.queue
        while True:
            url, depth = await queue.get()
            try:
                await self._process_page(url, depth)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never let one page kill the crawl
                record = self._endpoints[url]
                record.fetch_status = "error"
                record.error = {"code": "internal_error", "message": type(exc).__name__}
                self._record_error(
                    operation="process_page",
                    url=url,
                    code="internal_error",
                    message=type(exc).__name__,
                )
            finally:
                queue.task_done()

    async def _process_page(self, url: str, depth: int) -> None:
        self._emit("page_started", url, f"depth {depth}", {"depth": depth})
        record = self._endpoints[url]
        try:
            result = await self._fetcher.fetch(
                url,
                kind="page",
                accepted_types=HTML_TYPES,
                max_bytes=self._config.max_response_bytes,
            )
        except FetchError as exc:
            record.fetch_status = "error"
            record.final_url = exc.final_url or url
            record.status_code = exc.status_code
            record.content_type = exc.content_type
            record.redirect_chain = list(exc.redirect_chain)
            record.error = {"code": exc.code, "message": exc.message}
            self._record_error(
                operation="fetch_page",
                url=url,
                code=exc.code,
                message=exc.message,
                status_code=exc.status_code,
            )
            return

        record.final_url = result.final_url
        record.status_code = result.status_code
        record.content_type = result.content_type
        record.redirect_chain = list(result.redirect_chain)

        # A redirect may land on content another endpoint already owns: keep one copy.
        owner = self._content_owner.setdefault(result.final_url, url)
        self._sched.mark_seen(result.final_url)
        if owner != url:
            record.fetch_status = "duplicate_redirect"
            record.duplicate_of = owner
            self._emit(
                "page_fetched",
                url,
                f"duplicate of {owner}",
                {"depth": depth, "duplicate_of": owner, "children": []},
            )
            return

        html = decode_body(result.body, result.content_type_header, sniff_meta=True)
        record.html = html
        try:
            parsed = await asyncio.to_thread(parse_html, html, result.final_url)
        except Exception as exc:
            record.fetch_status = "error"
            record.error = {"code": "html_parse_error", "message": type(exc).__name__}
            self._record_error(
                operation="parse_page",
                url=url,
                code="html_parse_error",
                message=type(exc).__name__,
                status_code=result.status_code,
            )
            return

        record.fetch_status = "fetched"
        record.title = parsed.title
        record.inline_scripts = [_block_dict(b) for b in parsed.inline_scripts]
        record.inline_styles = [_block_dict(b) for b in parsed.inline_styles]
        record.js_files = list(parsed.script_urls)
        record.css_files = list(parsed.style_urls)

        for link in parsed.links:
            decision = self._scope.check_page_url(link.url)
            entry = {
                "url": link.url,
                "tag": link.tag,
                "in_scope": decision.allowed,
                "action": "",
                "reason": decision.reason,
            }
            if not decision.allowed:
                entry["action"] = "out_of_scope"
                item = self._out_of_scope.setdefault(
                    link.url, {"url": link.url, "reason": decision.reason, "referenced_by": []}
                )
                if url not in item["referenced_by"]:
                    item["referenced_by"].append(url)
            elif not self._passes_filters(link.url):
                entry["action"] = "skipped_by_filter"
            elif looks_like_non_html_resource(link.url):
                entry["action"] = "skipped_non_html_resource"
            else:
                entry["action"] = _ACTION_FOR[self._schedule(link.url, depth + 1)]
            record.discovered_links.append(entry)
        for ignored in parsed.ignored:
            record.discovered_links.append(
                {
                    "url": ignored.value,
                    "tag": ignored.tag,
                    "in_scope": False,
                    "action": "ignored",
                    "reason": ignored.reason,
                }
            )

        self._emit(
            "page_fetched",
            url,
            parsed.title or "",
            {
                "depth": depth,
                "title": parsed.title,
                "children": [d["url"] for d in record.discovered_links if d["action"] == "queued"],
                "js": len(parsed.script_urls),
                "css": len(parsed.style_urls),
                "inline": len(parsed.inline_scripts) + len(parsed.inline_styles),
            },
        )
        pending: list[str] = []
        for asset_url in parsed.script_urls:
            if self._collector.register(asset_url, JAVASCRIPT, url):
                pending.append(asset_url)
        for asset_url in parsed.style_urls:
            if self._collector.register(asset_url, CSS, url):
                pending.append(asset_url)
        if pending:
            await asyncio.gather(*(self._collector.fetch(u) for u in pending))

    # ------------------------------------------------------------------ output

    def _build_result(
        self,
        target: str,
        status: str,
        started: datetime,
        finished: datetime,
        limits: set[str],
        origin: str | None,
        collector: AssetCollector | None,
    ) -> dict:
        endpoints = [e.to_dict() for e in self._endpoints.values()]
        assets = [a.to_dict() for a in collector.records()] if collector else []
        summary = {
            "pages_discovered": len(endpoints),
            "pages_fetched": sum(1 for e in endpoints if e["html"] is not None),
            "pages_failed": sum(1 for e in endpoints if e["fetch_status"] == "error"),
            "pages_not_fetched": sum(1 for e in endpoints if e["fetch_status"] == "not_fetched"),
            "assets_discovered": len(assets),
            "assets_fetched": sum(1 for a in assets if a["fetch_status"] == "fetched"),
            "assets_skipped": sum(1 for a in assets if a["fetch_status"] == "skipped"),
            "out_of_scope_urls": len(self._out_of_scope),
            "errors_count": len(self._errors),
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "target_origin": origin,
            "crawl_status": status,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round((finished - started).total_seconds(), 3),
            "config": self._config.to_dict(),
            "limits_reached": sorted(limits),
            "summary": summary,
            "endpoints": endpoints,
            "assets": assets,
            "out_of_scope": list(self._out_of_scope.values()),
            "errors": list(self._errors),
            "limitations": list(LIMITATIONS),
        }


async def crawl(
    target_url: str,
    config: CrawlConfig | None = None,
    progress_callback: ProgressCallback | None = None,
    cancellation_token: CancellationToken | None = None,
) -> dict:
    """Crawl ``target_url`` and return the structured, JSON-serializable result.

    Only crawl targets you are authorized to assess. An invalid target does not raise: it
    yields ``crawl_status == "failed"`` with the reason in ``errors``.
    """
    return await Crawler(
        config, progress_callback=progress_callback, cancellation_token=cancellation_token
    ).run(target_url)


def crawl_sync(
    target_url: str,
    config: CrawlConfig | None = None,
    progress_callback: ProgressCallback | None = None,
    cancellation_token: CancellationToken | None = None,
) -> dict:
    """Blocking wrapper around :func:`crawl` for non-async callers.

    Raises RuntimeError if called from a running event loop (use ``await crawl(...)``).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(crawl(target_url, config, progress_callback, cancellation_token))
    raise RuntimeError(
        "crawl_sync() cannot be called from a running event loop; use `await crawl(...)`"
    )
