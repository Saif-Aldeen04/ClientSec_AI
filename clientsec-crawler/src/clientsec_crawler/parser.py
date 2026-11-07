"""HTML parsing: links, page references, inline/external JS and CSS (BeautifulSoup4).

The parser is pure: it takes decoded HTML plus the page URL and returns what the page
*references*. Scope decisions and fetching are made elsewhere.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from .errors import InvalidURLError
from .url_utils import clean_url_text, normalize_url, resolve_url

_LINK_TAGS = {"a": "href", "area": "href", "iframe": "src", "frame": "src"}


@dataclass
class LinkRef:
    url: str  # resolved, normalised, fragment removed
    tag: str


@dataclass
class IgnoredRef:
    value: str
    tag: str
    reason: str


@dataclass
class InlineBlock:
    index: int
    content: str
    content_sha256: str
    attrs: dict[str, str]


@dataclass
class ParsedPage:
    title: str | None = None
    base_url: str = ""
    links: list[LinkRef] = field(default_factory=list)
    script_urls: list[str] = field(default_factory=list)
    style_urls: list[str] = field(default_factory=list)
    inline_scripts: list[InlineBlock] = field(default_factory=list)
    inline_styles: list[InlineBlock] = field(default_factory=list)
    ignored: list[IgnoredRef] = field(default_factory=list)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _attr_str(value: object) -> str:
    return " ".join(value) if isinstance(value, list) else str(value)


def _title(soup: BeautifulSoup) -> str | None:
    titles = soup.find_all("title")
    if not titles:
        return None
    chosen = next(
        (t for t in titles if t.parent is not None and t.parent.name == "head"), titles[0]
    )
    text = " ".join(chosen.get_text().split())
    return text or None


def parse_html(html: str, page_url: str) -> ParsedPage:
    """Parse ``html`` fetched from ``page_url``. May raise if the parser fails."""
    soup = BeautifulSoup(html, "html.parser")
    result = ParsedPage(title=_title(soup), base_url=page_url)

    base = page_url
    base_tag = soup.find("base", href=True)
    if base_tag is not None:
        try:
            base = resolve_url(page_url, _attr_str(base_tag["href"]))
        except InvalidURLError:
            base = page_url
    result.base_url = base

    seen_links: set[str] = set()
    for tag in soup.find_all(list(_LINK_TAGS)):
        raw = tag.get(_LINK_TAGS[tag.name])
        if raw is None:
            continue
        raw = _attr_str(raw)
        stripped = clean_url_text(raw) if raw.strip() else ""
        if not stripped or stripped.startswith("#"):
            continue  # empty or same-page fragment
        try:
            url = resolve_url(base, stripped)
        except InvalidURLError as exc:
            result.ignored.append(IgnoredRef(stripped[:200], tag.name, exc.code))
            continue
        if url not in seen_links:
            seen_links.add(url)
            result.links.append(LinkRef(url, tag.name))

    seen_scripts: set[str] = set()
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src is not None:
            src_text = _attr_str(src).strip()
            if not src_text:
                continue
            try:
                url = normalize_url(src_text, base=base)
            except InvalidURLError as exc:
                result.ignored.append(IgnoredRef(src_text[:200], "script", exc.code))
                continue
            if url not in seen_scripts:
                seen_scripts.add(url)
                result.script_urls.append(url)
            continue
        content = tag.string if tag.string is not None else tag.get_text()
        if content and content.strip():
            attrs = {
                k: _attr_str(v) for k, v in tag.attrs.items() if k in ("type", "id", "nomodule")
            }
            result.inline_scripts.append(
                InlineBlock(len(result.inline_scripts), content, _sha256(content), attrs)
            )

    seen_styles: set[str] = set()
    for tag in soup.find_all("link"):
        rel = tag.get("rel") or []
        rel_tokens = [t.lower() for t in (rel if isinstance(rel, list) else str(rel).split())]
        href = tag.get("href")
        if "stylesheet" not in rel_tokens or href is None:
            continue
        href_text = _attr_str(href).strip()
        if not href_text:
            continue
        try:
            url = normalize_url(href_text, base=base)
        except InvalidURLError as exc:
            result.ignored.append(IgnoredRef(href_text[:200], "link", exc.code))
            continue
        if url not in seen_styles:
            seen_styles.add(url)
            result.style_urls.append(url)

    for tag in soup.find_all("style"):
        content = tag.string if tag.string is not None else tag.get_text()
        if content and content.strip():
            attrs = {k: _attr_str(v) for k, v in tag.attrs.items() if k in ("media", "type", "id")}
            result.inline_styles.append(
                InlineBlock(len(result.inline_styles), content, _sha256(content), attrs)
            )
    return result
