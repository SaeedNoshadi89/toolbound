"""Ports: the small interfaces through which the core talks to the outside world.

Each port has a default implementation; replace any of them by passing your own
object to :class:`~toolbound.Gateway`. All are plain :class:`typing.Protocol`
types: no base class to inherit from, no registration.
"""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .contracts import NetworkPolicy

if TYPE_CHECKING:
    from .approval import PendingApproval
    from .context import ExecutionContext
    from .contracts import ToolSpec
    from .observe import Event


# --------------------------------------------------------------------------- transport


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """A fully built request that already passed URL-level policy checks."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    network: NetworkPolicy
    timeout: float
    connect_timeout: float
    max_response_bytes: int

    def __repr__(self) -> str:
        # Headers, body and query values can hold credentials: never print them.
        base, _, query = self.url.partition("?")
        names = sorted({k.lower() for k, _ in self.headers})
        body = f"<{len(self.body)} bytes>" if self.body else None
        return (
            f"HttpRequest(method={self.method!r}, url={base + ('?…' if query else '')!r}, "
            f"headers={names!r}, body={body})"
        )


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A bounded upstream response. ``headers`` keys are lower-case."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str
    elapsed_ms: float = 0.0
    extensions: Mapping[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"HttpResponse(status={self.status}, url={self.url.partition('?')[0]!r}, "
            f"body=<{len(self.body)} bytes>)"
        )


@runtime_checkable
class Transport(Protocol):
    """Sends one HTTP request. Must not follow redirects (the core does that).

    Production transports must enforce IP-level policy with
    :func:`toolbound.core.network.check_ip` on the address they connect to, cap
    the (decompressed) body at ``max_response_bytes`` and raise:

    * :class:`toolbound.core.errors.NetworkBlocked` for policy violations,
    * :class:`toolbound.core.errors.ToolFailure` with ``TIMEOUT``,
      ``UPSTREAM_UNAVAILABLE`` or ``RESPONSE_TOO_LARGE`` for transport failures.
    """

    async def send(self, request: HttpRequest) -> HttpResponse: ...

    async def aclose(self) -> None: ...


# --------------------------------------------------------------------------- credentials


@runtime_checkable
class CredentialProvider(Protocol):
    """Returns the secret value for a credential *name* (sync or async)."""

    def get(self, name: str, ctx: ExecutionContext) -> str | Awaitable[str | None] | None: ...


# --------------------------------------------------------------------------- policy


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """What the authorizer sees: who, which tool, which validated arguments."""

    ctx: ExecutionContext
    tool: ToolSpec
    arguments: Mapping[str, Any]
    bound: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Decision:
    """An authorization decision. ``reason`` is shown to the model when denied."""

    allowed: bool
    reason: str = "not permitted"

    @classmethod
    def allow(cls) -> Decision:
        return cls(True, "")

    @classmethod
    def deny(cls, reason: str = "not permitted") -> Decision:
        return cls(False, reason)


class Authorizer(Protocol):
    """Application-owned policy hook (sync or async), returning bool or Decision."""

    def __call__(
        self, request: AuthorizationRequest
    ) -> bool | Decision | Awaitable[bool | Decision]: ...


class Approver(Protocol):
    """Inline human-approval hook (sync or async). Return True to approve."""

    def __call__(self, pending: PendingApproval) -> bool | Awaitable[bool]: ...


# --------------------------------------------------------------------------- utilities


@runtime_checkable
class TokenEstimator(Protocol):
    """Estimates how many tokens a string uses for a model."""

    def count(self, text: str) -> int: ...


@runtime_checkable
class Observer(Protocol):
    """Receives structured events. Events never contain argument or body values."""

    def on_event(self, event: Event) -> None: ...


@runtime_checkable
class StateStore(Protocol):
    """Shared state for replay protection (single-use approvals, call-id dedupe).

    The default is in-memory and per-process. For multiple workers, implement
    ``claim`` on a shared store (for example Redis ``SET key 1 NX EX ttl``).
    """

    async def claim(self, key: str, ttl_seconds: float) -> bool:
        """Atomically record ``key``. Return False if it was already present."""
        ...
