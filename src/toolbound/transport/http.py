"""The default secure transport, built on httpx.

For each request it:

1. resolves the host itself and checks **every** returned address against the
   service's network policy (one bad address blocks the request),
2. connects only to checked addresses, while TLS still verifies the certificate
   against the original host name (SNI + ``Host`` header), so DNS rebinding
   between "check" and "connect" is not possible. If connecting to one checked
   address fails, the next checked address is tried,
3. never follows redirects (the core re-checks each hop), ignores proxy
   environment variables (``trust_env=False``), and **never stores cookies**,
   so state set by an upstream for one user can never be sent on behalf of
   another,
4. streams the body and decompresses it itself, capping every step, so it aborts
   once the *decompressed* size exceeds the limit without ever inflating more,
5. enforces a total deadline per attempt, defeating slow-drip responses,
6. reports whether a failed request may have reached the upstream, so callers
   can tell "certainly not sent" from "outcome unknown".

One instance can be shared by several event loops (for example FastAPI test
clients that each start their own loop): HTTP clients are kept per event loop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import time
import weakref
import zlib
from http.cookiejar import CookieJar, DefaultCookiePolicy
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


def _no_cookie_jar() -> CookieJar:
    """A cookie jar that refuses to store anything.

    httpx clients keep cookies by default. A shared client would then replay a
    ``Set-Cookie`` received during one user's call on every later call, for
    every user and tenant. Toolbound never wants that.
    """
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


class SecureTransport:
    """SSRF-hardened HTTP transport.

    Args:
        resolver: Host resolver (injectable for tests).
        verify: TLS verification (``True``, a CA bundle path, or an
            ``ssl.SSLContext``). Disabling it is not supported.
        max_connections: Connection pool size per host and event loop.
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
        self._resolver: Resolver = resolver if resolver is not None else SystemResolver()
        self._verify = verify
        self._max_connections = max_connections
        # Clients are bound to the event loop that created them, and to one host
        # name: connections are opened to a pinned IP, and a pool keyed by IP must
        # never reuse a TLS session made for another host.
        self._clients: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, dict[str, httpx.AsyncClient]
        ] = weakref.WeakKeyDictionary()
        self._lock = threading.Lock()

    def _client_for(self, host: str) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        with self._lock:
            per_loop = self._clients.get(loop)
            if per_loop is None:
                per_loop = self._clients[loop] = {}
            client = per_loop.get(host)
            if client is None:
                client = httpx.AsyncClient(
                    follow_redirects=False,
                    trust_env=False,
                    verify=self._verify,
                    cookies=_no_cookie_jar(),
                    limits=httpx.Limits(
                        max_connections=self._max_connections, max_keepalive_connections=20
                    ),
                    headers={"Accept-Encoding": "gzip, deflate"},
                )
                per_loop[host] = client
        return client

    async def aclose(self) -> None:
        """Close the clients that belong to the running event loop."""
        loop = asyncio.get_running_loop()
        with self._lock:
            mine = self._clients.pop(loop, {})
        for client in mine.values():
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
        sent: bool | None = False  # becomes None once bytes may have left
        try:
            async with asyncio.timeout(request.timeout):
                addresses = await self._addresses(host, port, request)
                client = self._client_for(host)
                default_port = 443 if parts.scheme == "https" else 80
                host_header = host if port == default_port else f"{host}:{port}"
                headers = [(k, v) for k, v in request.headers if k.lower() != "host"]
                headers.append(("Host", host_header))
                extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
                timeout = httpx.Timeout(request.timeout, connect=request.connect_timeout)
                response: httpx.Response | None = None
                address = addresses[0]
                sent = None  # from here on, bytes may reach the upstream
                for index, address in enumerate(addresses):
                    http_request = client.build_request(
                        request.method,
                        _with_host(parts, address, port),
                        headers=headers,
                        content=request.body,
                        timeout=timeout,
                        extensions=extensions,
                    )
                    try:
                        response = await client.send(http_request, stream=True)
                        break
                    except (httpx.ConnectError, httpx.ConnectTimeout):
                        # Nothing was sent; another checked address may work.
                        if index == len(addresses) - 1:
                            raise
                assert response is not None
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
                    decoder = _BoundedDecoder(
                        response.headers.get("content-encoding", ""), request.max_response_bytes
                    )
                    chunks: list[bytes] = []
                    async for raw in response.aiter_raw():
                        chunks.append(decoder.feed(raw))
                    chunks.append(decoder.finish())
                finally:
                    await response.aclose()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            code = (
                ErrorCode.UPSTREAM_UNAVAILABLE
                if isinstance(exc, httpx.ConnectError)
                else ErrorCode.TIMEOUT
            )
            raise ToolFailure(
                code, f"could not connect to upstream ({type(exc).__name__})", request_sent=False
            ) from None
        except TimeoutError:
            raise ToolFailure(
                ErrorCode.TIMEOUT,
                "upstream did not respond in time",
                request_sent=_after_connect(sent),
            ) from None
        except httpx.TimeoutException:
            raise ToolFailure(
                ErrorCode.TIMEOUT, "upstream did not respond in time", request_sent=None
            ) from None
        except httpx.DecodingError:
            raise ToolFailure(
                ErrorCode.UPSTREAM_ERROR, "upstream sent an undecodable body", retryable=False
            ) from None
        except (httpx.TransportError, OSError) as exc:
            raise ToolFailure(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"could not reach upstream ({type(exc).__name__})",
                request_sent=None,
            ) from None
        return HttpResponse(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=b"".join(chunks),
            url=request.url,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            extensions={"peer_address": address},
        )

    async def _addresses(self, host: str, port: int, request: HttpRequest) -> list[str]:
        """All addresses for ``host``, each checked; IPv4 first for predictability."""
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            check_ip(literal, request.network)
            return [str(literal)]
        try:
            addresses = await self._resolver.resolve(host, port)
        except OSError:
            raise ToolFailure(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                "could not resolve upstream host",
                request_sent=False,
            ) from None
        if not addresses:
            raise ToolFailure(
                ErrorCode.UPSTREAM_UNAVAILABLE, "upstream host has no addresses", request_sent=False
            )
        for address in addresses:
            check_ip(address, request.network)  # every address must pass
        v4 = [a for a in addresses if ":" not in a]
        v6 = [a for a in addresses if ":" in a]
        return v4 + v6


def _too_large() -> ToolFailure:
    return ToolFailure(
        ErrorCode.RESPONSE_TOO_LARGE, "upstream response exceeds the size limit", retryable=False
    )


def _undecodable() -> ToolFailure:
    return ToolFailure(
        ErrorCode.UPSTREAM_ERROR, "upstream sent an undecodable body", retryable=False
    )


class _BoundedDecoder:
    """Decodes ``Content-Encoding`` while never holding more than ``limit + 1`` bytes.

    httpx decompresses each raw chunk in full before the caller can count it, so a
    64 KiB gzip chunk can expand to tens of MiB first. Here every decompress call is
    capped with ``max_length``, so output stops one byte past the limit.
    """

    def __init__(self, content_encoding: str, limit: int) -> None:
        codings = [c.strip().lower() for c in content_encoding.split(",") if c.strip()]
        codings = [c for c in codings if c != "identity"]
        if len(codings) > 1:
            raise _undecodable()  # stacked encodings: never requested, not supported
        self._coding = codings[0] if codings else None
        if self._coding not in (None, "gzip", "x-gzip", "deflate"):
            raise _undecodable()  # only gzip and deflate are requested
        self._limit = limit
        self._size = 0
        self._obj: zlib._Decompress | None = None
        if self._coding in ("gzip", "x-gzip"):
            self._obj = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self._first = b""  # deflate: buffered until the zlib/raw choice is made

    def _count(self, data: bytes) -> bytes:
        self._size += len(data)
        if self._size > self._limit:
            raise _too_large()
        return data

    def _drain(self, data: bytes) -> bytes:
        assert self._obj is not None
        out: list[bytes] = []
        try:
            while data:
                piece = self._obj.decompress(data, self._limit - self._size + 1)
                out.append(self._count(piece))
                data = self._obj.unconsumed_tail
        except zlib.error:
            raise _undecodable() from None
        return b"".join(out)

    def feed(self, data: bytes) -> bytes:
        if self._coding is None:
            return self._count(data)
        if self._obj is None:  # deflate: RFC says zlib-wrapped, many servers send raw
            self._first += data
            if len(self._first) < 2:
                return b""
            data, self._first = self._first, b""
            wrapped = (data[0] & 0x0F) == 8 and int.from_bytes(data[:2], "big") % 31 == 0
            self._obj = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
        return self._drain(data)

    def finish(self) -> bytes:
        if self._coding is None:
            return b""
        if self._obj is None:
            if not self._first:
                return b""
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            data, self._first = self._first, b""
            return self._drain(data)
        try:
            return self._count(self._obj.flush())
        except zlib.error:
            raise _undecodable() from None


def _after_connect(sent: bool | None) -> bool | None:
    return False if sent is False else None


def _with_host(parts: SplitResult, address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return urlunsplit((parts.scheme, f"{host}:{port}", parts.path, parts.query, ""))


__all__ = ["NetworkBlocked", "Resolver", "SecureTransport", "SystemResolver"]
