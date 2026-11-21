"""Scope validation: target validation, origin locking and destination (SSRF) policy.

Two independent checks protect every request:

1. :class:`ScopePolicy` - *which URLs* may be requested (origin locking, allowlists).
2. :class:`DestinationPolicy` - *which IP addresses* may be connected to (SSRF guard).

Both are applied to the initial URL and again to every redirect hop.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .config import CrawlConfig
from .errors import InvalidTargetError, InvalidURLError
from .url_utils import normalize_host, normalize_url, origin_string, url_origin

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_METADATA_IPS = frozenset(
    ipaddress.ip_address(addr)
    for addr in (
        "169.254.169.254",  # AWS / Azure / GCP / OpenStack / DigitalOcean
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IPv6 metadata
    )
)
_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
# NAT64, local-use NAT64, Teredo and 6to4 can embed arbitrary IPv4 addresses: fail closed.
_BLOCKED_V6_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16")
)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str | None = None


ALLOWED = ScopeDecision(True)


class DestinationPolicy:
    """Decides whether a resolved IP address (or hostname) is a permitted destination."""

    def __init__(self, *, allow_private_networks: bool = False) -> None:
        self._allow_private = allow_private_networks

    def check_hostname(self, host: str) -> str | None:
        """Return a block reason for well-known internal metadata hostnames, else None."""
        if host.lower().rstrip(".") in _METADATA_HOSTS:
            return "cloud_metadata"
        return None

    def check_ip(self, value: str | IPAddress) -> str | None:
        """Return a block reason if connecting to ``value`` is not allowed, else None."""
        try:
            ip = ipaddress.ip_address(value.split("%", 1)[0] if isinstance(value, str) else value)
        except ValueError:
            return "invalid_address"
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip in _METADATA_IPS:
            return "cloud_metadata"
        if isinstance(ip, ipaddress.IPv6Address) and any(ip in n for n in _BLOCKED_V6_NETWORKS):
            return "transition_address"
        if ip.is_multicast:
            return "multicast"
        if ip.is_unspecified:
            return "unspecified"
        if self._allow_private:
            return None
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link_local"
        if ip.is_private:
            return "private"
        if ip.is_reserved:
            return "reserved"
        if not ip.is_global:
            return "not_global"
        return None


def validate_target_url(raw: object) -> str:
    """Validate the user supplied target and return its normalised form.

    Policy: only ``http``/``https``; a hostname is required; credentials are rejected;
    any port 1-65535 is accepted for the target itself (default ports are normalised
    away). Subsequent requests must match the target's exact scheme, host and port.
    Raises :class:`InvalidTargetError` with a stable ``code``.
    """
    if not isinstance(raw, str):
        raise InvalidTargetError("invalid_target_type", "target URL must be a string")
    if not raw.strip():
        raise InvalidTargetError("empty_target", "target URL is empty")
    try:
        return normalize_url(raw)
    except InvalidURLError as exc:
        raise InvalidTargetError(exc.code, f"invalid target URL: {exc.message}") from exc


class ScopePolicy:
    """Origin locking for pages and assets."""

    def __init__(self, target_url: str, config: CrawlConfig) -> None:
        self._scheme, self._host, self._port = url_origin(target_url)
        self._target_origin = (self._scheme, self._host, self._port)
        extra_hosts = {normalize_host(h) for h in config.additional_allowed_hosts}
        self._allowed_hosts = frozenset({self._host, *extra_hosts})
        self._asset_origins = frozenset(
            url_origin(normalize_url(origin)) for origin in config.asset_origin_allowlist
        )
        self.destination = DestinationPolicy(
            allow_private_networks=config.unsafe_allow_private_networks
        )

    @property
    def target_origin(self) -> str:
        return origin_string(*self._target_origin)

    def _is_subdomain_of_target(self, host: str) -> bool:
        target_labels = self._host.split(".")
        labels = host.split(".")
        return len(labels) > len(target_labels) and labels[-len(target_labels) :] == target_labels

    def check_page_url(self, url: str) -> ScopeDecision:
        """May this URL be requested as a page? Same scheme, allowed host, same port."""
        try:
            scheme, host, port = url_origin(url)
        except (InvalidURLError, ValueError):
            return ScopeDecision(False, "malformed_url")
        if scheme != self._scheme:
            return ScopeDecision(False, "different_scheme")
        if host not in self._allowed_hosts:
            if self._is_subdomain_of_target(host):
                return ScopeDecision(False, "subdomain_not_in_allowlist")
            return ScopeDecision(False, "different_host")
        if port != self._port:
            return ScopeDecision(False, "different_port")
        return ALLOWED

    def check_asset_url(self, url: str) -> ScopeDecision:
        """May this URL be downloaded as an asset? Page scope, or an explicit origin allowlist."""
        decision = self.check_page_url(url)
        if decision.allowed:
            return decision
        try:
            origin = url_origin(url)
        except (InvalidURLError, ValueError):
            return ScopeDecision(False, "malformed_url")
        if origin in self._asset_origins:
            return ALLOWED
        return ScopeDecision(False, "cross_origin_asset_not_allowlisted")
