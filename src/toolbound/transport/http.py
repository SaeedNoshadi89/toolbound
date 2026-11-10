"""The default secure transport, built on httpx.

For each request it:

1. resolves the host itself and checks **every** returned address against the
   service's network policy (one bad address blocks the request),
2. connects to the checked address, while TLS still verifies the certificate
   against the original host name (SNI + ``Host`` header), so DNS rebinding
   between "check" and "connect" is not possible,
3. never follows redirects (the core re-checks each hop) and ignores proxy
   environment variables (``trust_env=False``),
4. streams the body and aborts once the *decompressed* size exceeds the limit,
5. enforces a total deadline per attempt, defeating slow-drip responses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx

from toolbound.core.errors import ErrorCode, NetworkBlocked, ToolFailure
from toolbound.core.network import check_ip
from toolbound.core.ports import HttpRequest, HttpResponse


class Resolver(Protocol):
    """Resolves a host name to IP address strings."""

    async def resolve(self, host: str, port: int) -> list[str]: ...


class SystemResolver:
    """Uses the operating system resolver (``getaddrinfo``)."""

    async def resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]).split("%")[0] for info in infos})


class SecureTransport:
    """SSRF-hardened HTTP transport. Share one instance per event loop.

    Args:
        resolver: Host resolver (injectable for tests).
        verify: TLS verification (``True``, a CA bundle path, or an
            ``ssl.SSLContext``). Disabling it is not supported.
        max_connections: Connection pool size.
    """

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        verify: bool | str = True,
        max_connections: int = 100,
    ) -> None:
        if verify is False:
            raise ValueError("TLS verification cannot be disabled")
        self._resolver: Resolver = resolver or SystemResolver()
        self._verify = verify
        self._max_connections = max_connections
        # One client per host name: connections are opened to a pinned IP, and a
        # pool keyed by IP must never reuse a TLS session made for another host.
        self._clients: dict[str, httpx.AsyncClient] = {}

    def _client_for(self, host: str) -> httpx.AsyncClient:
        client = self._clients.get(host)
        if client is None:
            client = httpx.AsyncClient(
                follow_redirects=False,
                trust_env=False,
                verify=self._verify,
                limits=httpx.Limits(
                    max_connections=self._max_connections, max_keepalive_connections=20
                ),
                headers={"Accept-Encoding": "gzip, deflate"},
            )
            self._clients[host] = client
        return client

    async def aclose(self) -> None:
        clients, self._clients = list(self._clients.values()), {}
        for client in clients:
            await client.aclose()

    async def __aenter__(self) -> SecureTransport:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def send(self, request: HttpRequest) -> HttpResponse:
        parts = urlsplit(request.url)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(request.timeout):
                address = await self._pick_address(host, port, request)
                pinned = _with_host(parts, address, port)
                headers = [(k, v) for k, v in request.headers if k.lower() != "host"]
                default_port = 443 if parts.scheme == "https" else 80
                host_header = host if port == default_port else f"{host}:{port}"
                headers.append(("Host", host_header))
                extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
                timeout = httpx.Timeout(request.timeout, connect=request.connect_timeout)
                client = self._client_for(host)
                http_request = client.build_request(
                    request.method,
                    pinned,
                    headers=headers,
                    content=request.body,
                    timeout=timeout,
                    extensions=extensions,
                )
                response = await client.send(http_request, stream=True)
                try:
                    declared = response.headers.get("content-length")
                    if (
                        declared
                        and declared.isdigit()
                        and int(declared) > request.max_response_bytes
                    ):
                        raise ToolFailure(
                            ErrorCode.RESPONSE_TOO_LARGE,
                            "upstream response exceeds the size limit",
                            retryable=False,
                        )
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > request.max_response_bytes:
                            raise ToolFailure(
                                ErrorCode.RESPONSE_TOO_LARGE,
                                "upstream response exceeds the size limit",
                                retryable=False,
                            )
                        chunks.append(chunk)
                finally:
                    await response.aclose()
        except TimeoutError:
            raise ToolFailure(ErrorCode.TIMEOUT, "upstream did not respond in time") from None
        except httpx.TimeoutException:
            raise ToolFailure(ErrorCode.TIMEOUT, "upstream did not respond in time") from None
        except httpx.DecodingError:
            raise ToolFailure(
                ErrorCode.UPSTREAM_ERROR, "upstream sent an undecodable body", retryable=False
            ) from None
        except (httpx.TransportError, OSError) as exc:
            raise ToolFailure(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"could not reach upstream ({type(exc).__name__})",
            ) from None
        return HttpResponse(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=b"".join(chunks),
            url=request.url,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            extensions={"peer_address": address},
        )

    async def _pick_address(self, host: str, port: int, request: HttpRequest) -> str:
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            check_ip(literal, request.network)
            return str(literal)
        try:
            addresses = await self._resolver.resolve(host, port)
        except OSError:
            raise ToolFailure(
                ErrorCode.UPSTREAM_UNAVAILABLE, "could not resolve upstream host"
            ) from None
        if not addresses:
            raise ToolFailure(ErrorCode.UPSTREAM_UNAVAILABLE, "upstream host has no addresses")
        for address in addresses:
            check_ip(address, request.network)  # every address must pass
        # Prefer IPv4 for predictability, then the first address.
        v4 = [a for a in addresses if ":" not in a]
        return (v4 or addresses)[0]


def _with_host(parts: SplitResult, address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return urlunsplit((parts.scheme, f"{host}:{port}", parts.path, parts.query, ""))


__all__ = ["NetworkBlocked", "Resolver", "SecureTransport", "SystemResolver"]
