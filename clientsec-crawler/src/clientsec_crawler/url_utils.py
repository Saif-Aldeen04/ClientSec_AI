"""URL parsing and normalization.

Normalization policy (used for crawl identity and de-duplication):

* Scheme and host are lower-cased; IDN hosts are converted to punycode; a trailing
  dot on the host is removed. Numeric/ambiguous hosts such as ``127.1`` are rejected.
* Default ports (80 for http, 443 for https) are dropped; other ports are kept.
* The fragment is removed.
* An empty path becomes ``/``. A trailing slash is *significant*: ``/a`` and ``/a/``
  are distinct routes and are never merged.
* Dot segments (``/./``, ``/../``) are resolved. Percent-encoding is canonicalised
  (hex digits upper-cased, unreserved characters decoded, unsafe characters encoded).
* The query string is preserved verbatim apart from percent-encoding canonicalisation:
  parameters are never removed or re-ordered, because that can change application
  semantics. An empty ``?`` is dropped.
* URLs containing credentials (``user:pass@``) are rejected.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from .errors import InvalidURLError

DEFAULT_PORTS = {"http": 80, "https": 443}

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCT_TRIPLET = re.compile(r"%([0-9A-Fa-f]{2})")
_BARE_PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HOST_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_STRIP = "".join(chr(c) for c in range(0x21))
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

_PATH_SAFE = "/:@!$&'()*+,;=%"
_QUERY_SAFE = "/:@!$&'()*+,;=?%"

#: Extensions of URLs that are clearly not HTML pages and so never enter the page queue.
NON_HTML_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".bmp",
        ".avif",
        ".tif",
        ".tiff",
        ".pdf",
        ".zip",
        ".gz",
        ".tgz",
        ".tar",
        ".rar",
        ".7z",
        ".bz2",
        ".xz",
        ".mp3",
        ".mp4",
        ".m4a",
        ".wav",
        ".ogg",
        ".webm",
        ".avi",
        ".mov",
        ".mkv",
        ".flv",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".exe",
        ".dmg",
        ".iso",
        ".apk",
        ".msi",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".csv",
        ".json",
        ".xml",
        ".rss",
        ".atom",
        ".css",
        ".js",
        ".mjs",
        ".map",
        ".txt",
        ".wasm",
    }
)


def effective_port(scheme: str, port: int | None) -> int:
    """Return the explicit port, or the scheme default when none was given."""
    return port if port is not None else DEFAULT_PORTS[scheme]


def host_for_url(host: str) -> str:
    """Bracket IPv6 literals so the host can be placed in a URL or Host header."""
    return f"[{host}]" if ":" in host else host


def normalize_host(host: str | None) -> str:
    """Normalise a hostname or IP literal; raise InvalidURLError if it is not acceptable."""
    if not host:
        raise InvalidURLError("missing hostname", "missing_hostname")
    if "%" in host:
        raise InvalidURLError("hostname contains '%'", "invalid_hostname")
    text = host.strip().lower().rstrip(".")
    if not text:
        raise InvalidURLError("missing hostname", "missing_hostname")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    try:
        text = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidURLError("invalid hostname", "invalid_hostname") from exc
    if len(text) > 253:
        raise InvalidURLError("hostname too long", "invalid_hostname")
    labels = text.split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        raise InvalidURLError("invalid hostname", "invalid_hostname")
    if labels[-1].isdigit():
        raise InvalidURLError("ambiguous numeric hostname", "invalid_hostname")
    return text


def _fix_percent(text: str, safe: str) -> str:
    text = _BARE_PCT.sub("%25", text)

    def repl(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else "%" + match.group(1).upper()

    text = _PCT_TRIPLET.sub(repl, text)
    return quote(text, safe=safe)


def _remove_dot_segments(path: str) -> str:
    if "." not in path:
        return path
    segments = path.split("/")
    out: list[str] = []
    last_index = len(segments) - 1
    for index, segment in enumerate(segments):
        is_last = index == last_index
        if segment == ".":
            if is_last:
                out.append("")
            continue
        if segment == "..":
            if len(out) > 1:
                out.pop()
            if is_last:
                out.append("")
            continue
        out.append(segment)
    return "/".join(out)


def clean_url_text(raw: str) -> str:
    """Strip surrounding whitespace/control chars and remove tabs/newlines (as browsers do)."""
    text = raw.strip(_STRIP)
    text = re.sub(r"[\t\r\n]", "", text)
    if _CONTROL.search(text):
        raise InvalidURLError("URL contains control characters", "malformed_url")
    return text


def normalize_url(raw: str, base: str | None = None) -> str:
    """Resolve ``raw`` against ``base`` (if given) and return its canonical crawl identity.

    Raises InvalidURLError for unsupported schemes, credentials, bad hosts or ports.
    """
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string", "malformed_url")
    text = clean_url_text(raw)
    if not text:
        raise InvalidURLError("empty URL", "empty_url")
    try:
        if base is not None:
            text = urljoin(base, text)
        parts = urlsplit(text)
        port = parts.port
        hostname = parts.hostname
    except ValueError as exc:
        raise InvalidURLError(f"malformed URL: {exc}", "malformed_url") from exc

    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidURLError(f"unsupported scheme {scheme!r}", "unsupported_scheme")
    if "@" in parts.netloc:
        raise InvalidURLError(
            "URLs with embedded credentials are not allowed", "credentials_in_url"
        )
    host = normalize_host(hostname)
    if port is not None and not (1 <= port <= 65535):
        raise InvalidURLError("invalid port", "invalid_port")
    explicit_port = None if port is None or port == DEFAULT_PORTS[scheme] else port

    path = _remove_dot_segments(_fix_percent(parts.path, _PATH_SAFE)) or "/"
    query = _fix_percent(parts.query, _QUERY_SAFE)
    netloc = host_for_url(host) + (f":{explicit_port}" if explicit_port is not None else "")
    return urlunsplit((scheme, netloc, path, query, ""))


def resolve_url(base: str, href: str) -> str:
    """Resolve a (possibly relative) reference against ``base`` and normalise it."""
    return normalize_url(href, base=base)


def url_origin(url: str) -> tuple[str, str, int]:
    """Return ``(scheme, host, effective_port)`` for a normalised URL."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not parts.hostname:
        raise InvalidURLError("not an http(s) URL", "malformed_url")
    return scheme, parts.hostname.lower(), effective_port(scheme, parts.port)


def origin_string(scheme: str, host: str, port: int) -> str:
    """Render an origin tuple as a URL-style origin, omitting default ports."""
    suffix = "" if DEFAULT_PORTS[scheme] == port else f":{port}"
    return f"{scheme}://{host_for_url(host)}{suffix}"


def looks_like_non_html_resource(url: str) -> bool:
    """True if the URL path ends in an extension that is clearly not an HTML page."""
    path = urlsplit(url).path.lower()
    dot = path.rfind(".")
    if dot == -1 or "/" in path[dot:]:
        return False
    return path[dot:] in NON_HTML_EXTENSIONS


def redact_url(url: str) -> str:
    """Drop query/fragment so URLs are safe to log (query strings may carry tokens)."""
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))
    except ValueError:
        return "<unparseable-url>"
