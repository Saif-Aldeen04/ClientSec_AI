"""Bounded, redirect-safe HTTP fetching on top of ``httpx.AsyncClient``.

Security properties
-------------------
* Automatic redirects are disabled; every hop is re-validated against the scope policy
  *before* any DNS lookup or connection.
* DNS is resolved by us, **every** returned address is validated by the destination policy
  (any blocked address fails the request), and the connection is then made to the validated
  IP with the original hostname in the ``Host`` header and TLS SNI. The client therefore
  never re-resolves the name, which closes the DNS-rebinding window.
* Proxy environment variables are ignored (``trust_env=False``) so a proxy cannot bypass the
  IP checks. No cookies or ``Authorization`` headers are ever sent, so nothing sensitive can
  be forwarded to another origin. Keep-alive is disabled so a pooled connection verified for
  one hostname is never reused for another.
* Response bodies are streamed and aborted as soon as the decoded size exceeds the limit.

Limitation: validation happens in our process. A hostile or buggy local resolver, or a
network that rewrites traffic after our check, cannot be defended against here; run the
crawler in a network environment that also enforces egress rules for strong guarantees.
"""

from __future__ import annotations

import asyncio
import codecs
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Collection, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from .config import CrawlConfig
from .errors import FetchError, InvalidURLError
from .scope import ScopePolicy
from .url_utils import DEFAULT_PORTS, host_for_url, resolve_url

Resolver = Callable[[str, int], Awaitable[Sequence[str]]]

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_IP_ATTEMPTS = 3

HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
JS_TYPES = frozenset(
    {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-ecmascript",
        "text/jscript",
    }
)
CSS_TYPES = frozenset({"text/css"})

_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", re.IGNORECASE)
_META_CHARSET_RE = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", re.IGNORECASE)


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    content_type: str | None
    content_type_header: str | None
    body: bytes
    redirect_chain: list[str]


@dataclass
class _Hop:
    status: int
    content_type: str | None
    content_type_header: str | None
    body: bytes | None
    location: str | None


async def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` with the system resolver (runs in the loop's executor)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _media_type(header: str | None) -> str | None:
    if not header:
        return None
    return header.split(";", 1)[0].strip().lower() or None


def decode_body(body: bytes, content_type_header: str | None, *, sniff_meta: bool = False) -> str:
    """Decode bytes using the declared charset (or a meta tag / UTF-8), replacing bad bytes."""
    encoding = None
    if content_type_header:
        match = _CHARSET_RE.search(content_type_header)
        if match:
            encoding = match.group(1)
    if encoding is None and sniff_meta:
        match = _META_CHARSET_RE.search(body[:2048])
        if match:
            encoding = match.group(1).decode("ascii", "ignore")
    if encoding is None:
        encoding = "utf-8-sig" if body.startswith(codecs.BOM_UTF8) else "utf-8"
    try:
        codecs.lookup(encoding)
    except LookupError:
        encoding = "utf-8"
    return body.decode(encoding, errors="replace")


def _causes(exc: BaseException):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


class _RateLimiter:
    """Enforces a minimum interval between request starts."""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._delay <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self._delay
        if start > now:
            await asyncio.sleep(start - now)


async def _strip_sensitive_headers(request: httpx.Request) -> None:
    for name in ("cookie", "authorization", "proxy-authorization"):
        request.headers.pop(name, None)


class Fetcher:
    """Fetches one URL at a time under the crawl's global concurrency and size limits."""

    def __init__(
        self,
        config: CrawlConfig,
        scope: ScopePolicy,
        *,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._scope = scope
        self._resolver = resolver or system_resolver
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._limiter = _RateLimiter(config.crawl_delay)
        kwargs: dict = {}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            kwargs["verify"] = self._tls_verify()
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(config.request_timeout),
            limits=httpx.Limits(
                max_connections=config.max_concurrency, max_keepalive_connections=0
            ),
            event_hooks={"request": [_strip_sensitive_headers]},
            **kwargs,
        )

    def _tls_verify(self) -> ssl.SSLContext | bool:
        if not self._config.verify_tls:
            return False
        if self._config.ca_bundle:
            return ssl.create_default_context(cafile=self._config.ca_bundle)
        return True

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ public API

    async def fetch(
        self,
        url: str,
        *,
        kind: str,
        accepted_types: Collection[str] | None,
        max_bytes: int,
    ) -> FetchResult:
        """Fetch ``url`` (``kind`` is ``"page"`` or ``"asset"``), following in-scope redirects.

        Raises :class:`FetchError` for every expected failure.
        """
        check = self._scope.check_page_url if kind == "page" else self._scope.check_asset_url
        current = url
        chain: list[str] = []
        seen = {url}
        for _ in range(self._config.max_redirects + 1):
            decision = check(current)
            if not decision.allowed:
                code = "redirect_out_of_scope" if chain else "out_of_scope"
                raise FetchError(
                    code,
                    f"{current} is outside the allowed scope ({decision.reason})",
                    final_url=current,
                    redirect_chain=chain,
                )
            try:
                hop = await self._request_once(current, accepted_types, max_bytes)
            except FetchError as exc:
                exc.final_url = exc.final_url or current
                exc.redirect_chain = list(chain)
                raise
            if hop.location is None:
                assert hop.body is not None
                return FetchResult(
                    url=url,
                    final_url=current,
                    status_code=hop.status,
                    content_type=hop.content_type,
                    content_type_header=hop.content_type_header,
                    body=hop.body,
                    redirect_chain=chain,
                )
            try:
                nxt = resolve_url(current, hop.location)
            except InvalidURLError as exc:
                raise FetchError(
                    "invalid_redirect",
                    f"redirect target rejected: {exc.message}",
                    status_code=hop.status,
                    final_url=current,
                    redirect_chain=chain,
                ) from exc
            if nxt in seen:
                raise FetchError(
                    "redirect_loop",
                    "redirect loop detected",
                    status_code=hop.status,
                    final_url=current,
                    redirect_chain=chain,
                )
            seen.add(nxt)
            chain.append(nxt)
            current = nxt
        raise FetchError(
            "too_many_redirects",
            f"more than {self._config.max_redirects} redirects",
            final_url=current,
            redirect_chain=chain,
        )

    # ------------------------------------------------------------------ internals

    async def _resolve_name(self, host: str, port: int) -> list[str]:
        policy = self._scope.destination
        try:
            addresses = list(await self._resolver(host, port))
        except FetchError:
            raise
        except Exception as exc:
            raise FetchError("dns_error", f"DNS resolution failed ({type(exc).__name__})") from exc
        if not addresses:
            raise FetchError("dns_error", "DNS resolution returned no addresses")
        for address in addresses:
            reason = policy.check_ip(address)
            if reason:
                # One bad address poisons the answer: fail closed rather than filter.
                raise FetchError(
                    "blocked_destination", f"host resolves to a blocked address ({reason})"
                )
        return addresses

    async def _request_once(
        self, url: str, accepted_types: Collection[str] | None, max_bytes: int
    ) -> _Hop:
        async with self._semaphore:
            await self._limiter.wait()
            try:
                return await asyncio.wait_for(
                    self._attempt(url, accepted_types, max_bytes),
                    timeout=self._config.request_timeout,
                )
            except FetchError:
                raise
            except (asyncio.TimeoutError, httpx.TimeoutException) as exc:
                raise FetchError(
                    "timeout", f"request timed out after {self._config.request_timeout}s"
                ) from exc
            except httpx.TransportError as exc:
                if any(isinstance(c, ssl.SSLError) for c in _causes(exc)):
                    raise FetchError("tls_error", "TLS handshake or certificate failure") from exc
                code = (
                    "connection_error" if isinstance(exc, httpx.ConnectError) else "network_error"
                )
                raise FetchError(code, f"{type(exc).__name__}: {str(exc)[:160]}") from exc
            finally:
                self._client.cookies.clear()

    async def _attempt(
        self, url: str, accepted_types: Collection[str] | None, max_bytes: int
    ) -> _Hop:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or DEFAULT_PORTS[parts.scheme]
        policy = self._scope.destination
        reason = policy.check_hostname(host)
        if reason:
            raise FetchError("blocked_destination", f"destination blocked ({reason})")
        try:
            ipaddress.ip_address(host)
            is_literal = True
        except ValueError:
            is_literal = False
        if is_literal:
            addresses = [host]
            reason = policy.check_ip(host)
            if reason:
                raise FetchError("blocked_destination", f"destination address blocked ({reason})")
        else:
            addresses = await self._resolve_name(host, port)

        last_error: Exception | None = None
        for ip in addresses[:MAX_IP_ATTEMPTS]:
            try:
                return await self._stream_from_ip(
                    parts, host, port, ip, is_literal, accepted_types, max_bytes
                )
            except httpx.ConnectError as exc:
                if any(isinstance(c, ssl.SSLError) for c in _causes(exc)):
                    raise
                last_error = exc
            except httpx.ConnectTimeout as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    async def _stream_from_ip(
        self,
        parts,
        host: str,
        port: int,
        ip: str,
        is_literal: bool,
        accepted_types: Collection[str] | None,
        max_bytes: int,
    ) -> _Hop:
        # Connect to the validated IP; keep the original name for Host and TLS SNI/verification.
        target = urlunsplit(
            (parts.scheme, f"{host_for_url(ip)}:{port}", parts.path or "/", parts.query, "")
        )
        host_header = host_for_url(host)
        if port != DEFAULT_PORTS[parts.scheme]:
            host_header += f":{port}"
        headers = {
            "Host": host_header,
            "User-Agent": self._config.user_agent,
            "Accept": "text/html,application/xhtml+xml,text/css,application/javascript,*/*;q=0.5",
        }
        extensions = {}
        if parts.scheme == "https" and not is_literal:
            extensions["sni_hostname"] = host

        async with self._client.stream(
            "GET", target, headers=headers, extensions=extensions
        ) as response:
            status = response.status_code
            header = response.headers.get("content-type")
            media = _media_type(header)
            if status in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if location:
                    return _Hop(status, media, header, None, location)
            if not 200 <= status < 300:
                raise FetchError(
                    "http_error", f"HTTP {status}", status_code=status, content_type=media
                )
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(
                    "response_too_large",
                    f"declared Content-Length {declared} exceeds limit of {max_bytes} bytes",
                    status_code=status,
                    content_type=media,
                )
            if accepted_types is not None and media not in accepted_types:
                raise FetchError(
                    "unsupported_content_type",
                    f"unexpected content type {media!r}",
                    status_code=status,
                    content_type=media,
                )
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(
                        "response_too_large",
                        f"response body exceeds limit of {max_bytes} bytes",
                        status_code=status,
                        content_type=media,
                    )
                chunks.append(chunk)
            return _Hop(status, media, header, b"".join(chunks), None)
