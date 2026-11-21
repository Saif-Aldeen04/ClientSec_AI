"""Output records and the schema version for the Member 2 contract."""

from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0"

LIMITATIONS = [
    "Pages are fetched with plain HTTP GET. JavaScript is not executed, so routes that only "
    "exist after client-side rendering are not discovered.",
    "Only endpoints reachable through processed sources (a/area/iframe/frame links in fetched "
    "HTML) are discovered; this is not an exhaustive enumeration of the site.",
    "Forms are not submitted, no authentication is performed and only GET requests are made; "
    "authenticated or state-dependent pages are not covered.",
    "robots.txt and sitemaps are not consulted. Inline event-handler attributes, JS-built URLs, "
    "CSS @import/url() references and link rel=preload are not followed.",
]


@dataclass
class EndpointRecord:
    url: str
    depth: int
    # pending -> fetched | error | duplicate_redirect | not_fetched (set at the end of a crawl)
    fetch_status: str = "pending"
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    title: str | None = None
    html: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    duplicate_of: str | None = None
    js_files: list[str] = field(default_factory=list)
    css_files: list[str] = field(default_factory=list)
    inline_scripts: list[dict] = field(default_factory=list)
    inline_styles: list[dict] = field(default_factory=list)
    discovered_links: list[dict] = field(default_factory=list)
    error: dict | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "depth": self.depth,
            "fetch_status": self.fetch_status,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "title": self.title,
            "html": self.html,
            "redirect_chain": list(self.redirect_chain),
            "duplicate_of": self.duplicate_of,
            "js_files": list(self.js_files),
            "css_files": list(self.css_files),
            "inline_scripts": list(self.inline_scripts),
            "inline_styles": list(self.inline_styles),
            "discovered_links": list(self.discovered_links),
            "error": self.error,
        }
