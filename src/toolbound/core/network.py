"""Network policy: URL construction and target checks (SSRF defences).

This module is pure: it never performs I/O. URL-level checks happen here for
every request. IP-level checks (after DNS resolution) use :func:`check_ip` and
are performed by the transport, because only the transport knows which address
it actually connects to. The default :class:`~toolbound.SecureTransport`
resolves the host, checks **every** address, and connects to the checked
address, which defeats DNS rebinding between check and connect.

Residual risk is documented in ``docs/security.md``: a library cannot see
sidecar proxies, service meshes, or an upstream API that itself fetches URLs.
Run agents with egress firewall rules when they sit next to sensitive networks.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from .contracts import NetworkPolicy, host_allowed
from .errors import ErrorCode, NetworkBlocked, ToolFailure

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HOST_CHARS = re.compile(r"^[a-z0-9.-]+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")


@dataclass(frozen=True, slots=True)
class Target:
    """A URL that passed URL-level policy checks."""

    url: str
    scheme: str
    host: str
    port: int
    is_ip_literal: bool

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)


def check_url(url: str, policy: NetworkPolicy) -> Target:
    """Validate ``url`` against ``policy``. Raises :class:`NetworkBlocked`."""
    if _CONTROL.search(url) or "\\" in url or " " in url:
        raise NetworkBlocked("URL contains forbidden characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise NetworkBlocked("URL could not be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme == "http" and not policy.allow_http:
        raise NetworkBlocked("plain HTTP is not allowed for this service")
    if scheme not in ("http", "https"):
        raise NetworkBlocked(f"scheme {scheme!r} is not allowed")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise NetworkBlocked("URLs with userinfo are not allowed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise NetworkBlocked("URL has no host")
    ip = _parse_ip_literal(host)
    if ip is None:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise NetworkBlocked("host name is not valid") from exc
        if not _HOST_CHARS.match(host) or ".." in host:
            raise NetworkBlocked("host name is not valid")
        if _looks_numeric(host):
            # "2130706433", "0x7f.1", "017700000001": resolvers may treat these as IPs.
            raise NetworkBlocked("numeric host names are not allowed")
    else:
        host = str(ip)
        check_ip(ip, policy)
    if not host_allowed(host, policy):
        raise NetworkBlocked(f"host {host!r} is not in the service allowlist")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if effective_port not in policy.allow_ports:
        raise NetworkBlocked(f"port {effective_port} is not allowed")
    return Target(url, scheme, host, effective_port, ip is not None)


def _parse_ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _looks_numeric(host: str) -> bool:
    labels = host.split(".")
    return all(re.fullmatch(r"(0x[0-9a-f]*|[0-9]+)", label) for label in labels if label)


@lru_cache(maxsize=256)
def _networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(ip, ipaddress.IPv4Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64 or ip in _NAT64_LOCAL:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    # Deprecated IPv4-compatible addresses (::a.b.c.d).
    if int(ip) >> 32 == 0 and int(ip) > 1:
        return ipaddress.IPv4Address(int(ip))
    return None


def is_public_ip(ip: IPAddress) -> bool:
    """True if ``ip`` is a globally routable unicast address."""
    embedded = _embedded_ipv4(ip)
    if embedded is not None and not is_public_ip(embedded):
        return False
    return bool(ip.is_global) and not ip.is_multicast and not ip.is_unspecified


def check_ip(ip: IPAddress | str, policy: NetworkPolicy) -> None:
    """Raise :class:`NetworkBlocked` unless ``ip`` may be contacted under ``policy``.

    Non-public addresses (loopback, private, link-local including cloud metadata,
    CGNAT, ULA, multicast, reserved, and IPv4 embedded in IPv6) are blocked unless
    they fall inside one of ``policy.allow_networks``.
    """
    address = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    trusted = _networks(policy.allow_networks)
    if any(address in net for net in trusted if net.version == address.version):
        return
    embedded = _embedded_ipv4(address)
    if embedded is not None and any(embedded in net for net in trusted if net.version == 4):
        return
    if is_public_ip(address):
        return
    raise NetworkBlocked(f"address {address} is not a public address and is not allowlisted")


# --------------------------------------------------------------------------- building


def encode_path_param(name: str, value: Any) -> str:
    """Encode one path parameter strictly. Raises ``invalid_arguments``."""
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, f"{name}: path values must be scalars")
    text = str(value)
    if (
        text == ""
        or text in (".", "..")
        or _CONTROL.search(text)
        or any(c in text for c in "/\\?#")
    ):
        raise ToolFailure(
            ErrorCode.INVALID_ARGUMENTS,
            f"{name}: value is not allowed in a URL path segment",
        )
    lowered = text.lower()
    if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
        raise ToolFailure(
            ErrorCode.INVALID_ARGUMENTS,
            f"{name}: encoded path separators are not allowed",
        )
    return quote(text, safe="")


def build_url(
    base_url: str,
    path_template: str,
    path_values: Mapping[str, Any],
    query: Sequence[tuple[str, Any]],
) -> str:
    """Join trusted base URL and template with encoded values and query pairs."""
    path = path_template
    for name, value in path_values.items():
        path = path.replace("{" + name + "}", encode_path_param(name, value))
    base = urlsplit(base_url)
    full_path = (base.path.rstrip("/") + path) if path != "/" else (base.path or "/")
    url = f"{base.scheme}://{base.netloc}{full_path}"
    pairs = _flatten_query(query)
    if pairs:
        url += "?" + urlencode(pairs, doseq=False)
    built = urlsplit(url)
    if built.netloc != base.netloc or not built.path.startswith(base.path.rstrip("/") or "/"):
        raise NetworkBlocked("constructed URL escaped the service base URL")
    return url


def _flatten_query(query: Sequence[tuple[str, Any]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, value in query:
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, dict | list):
                raise ToolFailure(
                    ErrorCode.INVALID_ARGUMENTS, f"{name}: query values must be scalars"
                )
            if isinstance(item, bool):
                out.append((name, "true" if item else "false"))
            else:
                out.append((name, str(item)))
    return out


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme, (pa.hostname or "").lower(), port_a) == (
        pb.scheme,
        (pb.hostname or "").lower(),
        port_b,
    )
