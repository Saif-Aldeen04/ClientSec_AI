"""Crawl configuration and resource limits."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

DEFAULT_USER_AGENT = "ClientSecAI-Crawler/1.0 (authorized security assessment)"


@dataclass(frozen=True)
class CrawlConfig:
    """All tunable limits and policies for one crawl.

    Depth is zero for the target page, one for links found on it, and so on.
    """

    #: Maximum number of distinct pages scheduled for fetching (including the target).
    max_pages: int = 100
    #: Maximum crawl depth. Links that would exceed it are recorded but not fetched.
    max_depth: int = 3
    #: Maximum number of HTTP requests in flight at the same time (pages and assets).
    max_concurrency: int = 5
    #: Total time allowed for one HTTP request (one redirect hop), in seconds.
    request_timeout: float = 10.0
    #: Maximum decoded size of an HTML page body, in bytes.
    max_response_bytes: int = 2 * 1024 * 1024
    #: Maximum decoded size of a JavaScript/CSS asset body, in bytes.
    max_asset_bytes: int = 5 * 1024 * 1024
    #: Maximum number of distinct assets fetched per crawl.
    max_assets: int = 1000
    #: Minimum delay between the start of two consecutive requests, in seconds (0 = none).
    crawl_delay: float = 0.0
    #: Maximum number of redirects followed for a single URL.
    max_redirects: int = 5
    #: Optional wall-clock limit for the whole crawl, in seconds.
    max_crawl_seconds: float | None = None
    #: Extra exact hostnames treated as in scope (same scheme and port as the target).
    #: Subdomains of the target are out of scope unless listed here.
    additional_allowed_hosts: tuple[str, ...] = ()
    #: Explicit cross-origin origins (``https://cdn.example.com``) from which assets may be fetched.
    asset_origin_allowlist: tuple[str, ...] = ()
    #: Download same-origin (and allowlisted) JS/CSS assets. If False, assets are only recorded.
    fetch_assets: bool = True
    #: Download JavaScript / CSS assets respectively (only when ``fetch_assets`` is True).
    fetch_js: bool = True
    fetch_css: bool = True
    #: Regular expressions matched (re.search) against ``path?query`` of in-scope page links.
    #: If ``include_patterns`` is set a link must match one; links matching any
    #: ``exclude_patterns`` are skipped. The target page itself is never filtered.
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    user_agent: str = DEFAULT_USER_AGENT
    #: Verify TLS certificates. Disabling is strongly discouraged.
    verify_tls: bool = True
    #: Optional path to a CA bundle (PEM) used instead of the default trust store.
    ca_bundle: str | None = None
    #: TEST-ONLY. Permits loopback/private destinations so local fixtures can be crawled.
    #: Cloud metadata endpoints stay blocked. Never enable this for real targets.
    unsafe_allow_private_networks: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "additional_allowed_hosts", tuple(self.additional_allowed_hosts))
        object.__setattr__(self, "asset_origin_allowlist", tuple(self.asset_origin_allowlist))
        object.__setattr__(self, "include_patterns", tuple(self.include_patterns))
        object.__setattr__(self, "exclude_patterns", tuple(self.exclude_patterns))
        for pattern in (*self.include_patterns, *self.exclude_patterns):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid pattern {pattern!r}: {exc}") from None
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be > 0")
        if self.max_response_bytes < 1 or self.max_asset_bytes < 1:
            raise ValueError("size limits must be >= 1 byte")
        if self.max_assets < 0:
            raise ValueError("max_assets must be >= 0")
        if self.crawl_delay < 0:
            raise ValueError("crawl_delay must be >= 0")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
        if self.max_crawl_seconds is not None and self.max_crawl_seconds <= 0:
            raise ValueError("max_crawl_seconds must be > 0 when set")

    def to_dict(self) -> dict:
        """JSON-serializable view (the CA bundle path is omitted)."""
        data = asdict(self)
        data.pop("ca_bundle", None)
        data["additional_allowed_hosts"] = list(self.additional_allowed_hosts)
        data["asset_origin_allowlist"] = list(self.asset_origin_allowlist)
        data["include_patterns"] = list(self.include_patterns)
        data["exclude_patterns"] = list(self.exclude_patterns)
        return data
