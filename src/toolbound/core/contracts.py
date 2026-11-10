"""Contract types: the developer-controlled definition of what a tool may do.

Everything in this module is **trusted configuration**. The model never sees
URLs, credentials, bound parameters, network policy, or limits. It only sees a
tool's name, description, and input schema.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit

from .context import ExecutionContext
from .errors import ConfigurationError
from .paths import MISSING

_TOOL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CREDENTIAL_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_FORBIDDEN_STATIC_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-connection",
        "authorization",
        "cookie",
    }
)
_MAX_DESCRIPTION = 1024


class Effect(StrEnum):
    """What a tool does to the outside world. Drives approval and retry rules."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


# --------------------------------------------------------------------------- bindings


@dataclass(frozen=True, slots=True)
class FromContext:
    """Bind a request parameter to a value from the trusted :class:`ExecutionContext`.

    ``path`` is one of ``"actor"``, ``"tenant"``, ``"request_id"`` or
    ``"attributes.<key>"``.
    """

    path: str

    def __post_init__(self) -> None:
        if self.path in {"actor", "tenant", "request_id"}:
            return
        if self.path.startswith("attributes.") and len(self.path) > len("attributes."):
            return
        raise ConfigurationError(
            f"invalid context binding {self.path!r}: use 'actor', 'tenant', "
            "'request_id' or 'attributes.<key>'"
        )

    def resolve(self, ctx: ExecutionContext) -> Any:
        if self.path == "actor":
            return ctx.actor
        if self.path == "tenant":
            if ctx.tenant is None:
                raise LookupError("tenant")
            return ctx.tenant
        if self.path == "request_id":
            return ctx.request_id
        key = self.path.removeprefix("attributes.")
        if key not in ctx.attributes:
            raise LookupError(key)
        return ctx.attributes[key]


@dataclass(frozen=True, slots=True)
class Const:
    """Bind a request parameter to a fixed value."""

    value: Any


Binding = FromContext | Const | Callable[[ExecutionContext], Any]


def from_ctx(path: str) -> FromContext:
    """Shorthand for :class:`FromContext`: ``from_ctx("attributes.repo_owner")``."""
    return FromContext(path)


def parse_binding(value: Any) -> Binding:
    """Parse a declarative binding (``"ctx.actor"`` or ``{"const": 1}``)."""
    if isinstance(value, FromContext | Const) or callable(value):
        return value  # type: ignore[no-any-return]
    if isinstance(value, str) and value.startswith("ctx."):
        return FromContext(value.removeprefix("ctx."))
    if isinstance(value, Mapping) and set(value) == {"const"}:
        return Const(value["const"])
    raise ConfigurationError(
        f"invalid binding {value!r}: use 'ctx.actor', 'ctx.tenant', "
        "'ctx.attributes.<key>' or {const: <value>}"
    )


def resolve_binding(binding: Binding, ctx: ExecutionContext) -> Any:
    if isinstance(binding, FromContext):
        return binding.resolve(ctx)
    if isinstance(binding, Const):
        return binding.value
    return binding(ctx)


# --------------------------------------------------------------------------- auth


@dataclass(frozen=True, slots=True)
class NoAuth:
    """No credentials are attached."""


@dataclass(frozen=True, slots=True)
class BearerAuth:
    """``Authorization: Bearer <credential>``. ``credential`` is a *name*, not a value."""

    credential: str


@dataclass(frozen=True, slots=True)
class ApiKeyAuth:
    """An API key sent in a header (default ``X-API-Key``) or a query parameter.

    Prefer headers: query-string keys are more likely to end up in upstream logs.
    """

    credential: str
    header: str | None = "X-API-Key"
    query: str | None = None


@dataclass(frozen=True, slots=True)
class BasicAuth:
    """HTTP Basic auth. The credential value must be ``"username:password"``."""

    credential: str


Auth = NoAuth | BearerAuth | ApiKeyAuth | BasicAuth


def _validate_auth(auth: Auth) -> None:
    if isinstance(auth, NoAuth):
        return
    if not isinstance(auth, BearerAuth | ApiKeyAuth | BasicAuth):
        raise ConfigurationError(f"unsupported auth type {type(auth).__name__}")
    if not _CREDENTIAL_NAME.match(auth.credential):
        raise ConfigurationError(
            "auth.credential must be a credential *name* (letters, digits, _.:-), "
            "never the secret value itself"
        )
    if isinstance(auth, ApiKeyAuth):
        if (auth.header is None) == (auth.query is None):
            raise ConfigurationError("ApiKeyAuth needs exactly one of header= or query=")
        if auth.header is not None:
            _validate_header_name(auth.header, allow_reserved=False)


# --------------------------------------------------------------------------- policies


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Where requests for a service may go.

    Args:
        allow_hosts: Exact hostnames (or ``*.example.com`` for subdomains).
            Defaults to the host of ``Service.base_url``.
        allow_ports: Allowed ports. Defaults to 443 (and 80 when ``allow_http``).
        allow_http: Permit plain-HTTP targets. Off by default.
        allow_networks: CIDR ranges that are trusted even though they are
            private, loopback, or link-local (for internal services). Leave empty
            for internet APIs: non-public addresses are then always blocked.
        follow_redirects: Follow 3xx responses. Each hop is re-checked against
            this policy, and credentials are dropped on a change of origin.
        max_redirects: Maximum hops when ``follow_redirects`` is on.
    """

    allow_hosts: tuple[str, ...] = ()
    allow_ports: tuple[int, ...] = ()
    allow_http: bool = False
    allow_networks: tuple[str, ...] = ()
    follow_redirects: bool = False
    max_redirects: int = 3


@dataclass(frozen=True, slots=True)
class Limits:
    """Size and time limits for one upstream service."""

    timeout: float = 15.0
    connect_timeout: float = 5.0
    max_request_bytes: int = 256 * 1024
    max_response_bytes: int = 5 * 1024 * 1024
    max_concurrency: int = 8
    #: Deadline for one tool call including every retry, backoff and wait for a
    #: concurrency slot. ``timeout`` bounds a single attempt.
    total_timeout: float = 60.0

    def __post_init__(self) -> None:
        if self.timeout <= 0 or self.connect_timeout <= 0 or self.total_timeout <= 0:
            raise ConfigurationError("timeouts must be positive")
        if self.total_timeout < self.timeout:
            raise ConfigurationError("total_timeout must be at least timeout")
        if self.max_request_bytes <= 0 or self.max_response_bytes <= 0:
            raise ConfigurationError("byte limits must be positive")
        if self.max_concurrency < 1:
            raise ConfigurationError("max_concurrency must be at least 1")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retries with exponential backoff and full jitter.

    Retries only happen for safe methods (GET, HEAD, OPTIONS) or for operations
    that declare an ``idempotency_header``. Non-idempotent calls are never
    repeated automatically.
    """

    max_attempts: int = 3
    backoff_base: float = 0.25
    backoff_max: float = 4.0
    retry_statuses: frozenset[int] = frozenset({429, 502, 503, 504})
    max_retry_after: float = 30.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ConfigurationError("max_attempts must be at least 1")
        if self.backoff_base < 0 or self.backoff_max < 0 or self.max_retry_after < 0:
            raise ConfigurationError("backoff values must be non-negative")


@dataclass(frozen=True, slots=True)
class RateLimit:
    """At most ``calls`` executions per ``per_seconds`` window, per ``scope``."""

    calls: int
    per_seconds: float
    scope: Literal["actor", "tenant", "global"] = "actor"

    def __post_init__(self) -> None:
        if self.calls < 1 or self.per_seconds <= 0:
            raise ConfigurationError("rate limit needs calls >= 1 and per_seconds > 0")


# --------------------------------------------------------------------------- output


@dataclass(frozen=True, slots=True)
class Field:
    """A projected output field with optional limits and transforms.

    A plain string in a shape (``"author": "user.login"``) is shorthand for
    ``Field("user.login")``.

    Args:
        source: Path into the upstream value (see :mod:`toolbound.core.paths`).
        max_chars: Per-field string limit, overriding ``Output.max_chars``.
        max_items: Per-field list limit, overriding ``Output.max_items``.
        transform: A built-in transform name (``"lower"``, ``"upper"``,
            ``"strip"``, ``"count"``, ``"first"``, ``"join"``, ``"bool"``,
            ``"str"``) or a trusted Python callable.
        default: Value used when the source path is missing.
        shape: Nested shape applied to the value (to each element if a list).
    """

    source: str
    max_chars: int | None = None
    max_items: int | None = None
    transform: str | Callable[[Any], Any] | None = None
    default: Any = MISSING
    shape: Mapping[str, FieldSpec] | None = None


FieldSpec = str | Field

OverflowMode = Literal["truncate", "reject"]
SchemaMode = Literal["strict", "warn"]


def _default_redact_keys() -> tuple[str, ...]:
    return (
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "set-cookie",
        "private_key",
        "session",
        "session_id",
        "x-api-key",
        "client_assertion",
    )


@dataclass(frozen=True, slots=True)
class Output:
    """How an upstream response becomes the model-visible result.

    Args:
        root: Path to the part of the response to keep (``"$"`` = everything).
            If it selects a list, ``shape`` is applied to every element.
        shape: Allowlist of output keys mapped to source paths. ``None`` passes
            the selected value through (limits and redaction still apply).
            Prefer an explicit shape: allowlists are the primary data-minimization
            control, redaction is only a second layer.
        required: Output keys that must never be dropped to save space (for
            example identifiers or citations). If they cannot fit the budget the
            call fails with ``result_too_large`` instead of returning a misleading
            result.
        max_items: Maximum elements in any list (including the root list).
        max_chars: Maximum characters in any string.
        max_tokens: Token budget for the ``data`` part of the result.
        overflow: ``"truncate"`` (trim and report what was dropped) or
            ``"reject"`` (fail if anything would need to be dropped).
        selectable: Expose an optional ``fields`` argument so the model can ask
            for a subset of the top-level shape keys. Required keys are always
            included.
        redact_keys: Object keys (case-insensitive) whose values are replaced
            with ``"[REDACTED]"`` anywhere in the result.
        redact_secrets: Mask common secret formats (API keys, JWTs, private
            keys) in string values.
        redactors: Extra trusted hooks ``(path, value) -> value`` for PII rules.
        schema: Optional JSON Schema the selected upstream value must match.
        schema_mode: ``"strict"`` fails the call on mismatch; ``"warn"`` returns
            the result with a warning.
        error_shape: Optional shape applied to upstream error bodies so the model
            sees a short, useful error message instead of only a status code.
        accept_text: Accept ``text/*`` responses (returned as a string).
        transform: Final trusted transform applied after shaping.
        continuation: For read tools that return lists: when items are left
            out (``max_items`` or the budget), return a signed ``next_cursor``
            that resumes at the next item. Enabled automatically for operations
            with ``pagination``. Continuing re-runs the request, so it assumes
            the upstream ordering is stable.
    """

    root: str = "$"
    shape: Mapping[str, FieldSpec] | None = None
    required: tuple[str, ...] = ()
    max_items: int = 50
    max_chars: int = 4000
    max_tokens: int | None = 2000
    overflow: OverflowMode = "truncate"
    selectable: bool = False
    redact_keys: tuple[str, ...] = field(default_factory=_default_redact_keys)
    redact_secrets: bool = True
    redactors: tuple[Callable[[str, Any], Any], ...] = ()
    schema: Mapping[str, Any] | None = None
    schema_mode: SchemaMode = "strict"
    error_shape: Mapping[str, FieldSpec] | None = None
    accept_text: bool = False
    transform: Callable[[Any], Any] | None = None
    continuation: bool = False

    def __post_init__(self) -> None:
        if self.max_items < 1 or self.max_chars < 1:
            raise ConfigurationError("max_items and max_chars must be at least 1")
        if self.max_tokens is not None and self.max_tokens < 16:
            raise ConfigurationError("max_tokens must be at least 16")
        if self.overflow not in ("truncate", "reject"):
            raise ConfigurationError("overflow must be 'truncate' or 'reject'")
        if self.schema_mode not in ("strict", "warn"):
            raise ConfigurationError("schema_mode must be 'strict' or 'warn'")
        if self.required and self.shape is None:
            raise ConfigurationError("Output.required needs an explicit shape")
        if self.shape is not None:
            missing = [k for k in self.required if k not in self.shape]
            if missing:
                raise ConfigurationError(f"required keys not in shape: {missing}")
        if self.selectable and self.shape is None:
            raise ConfigurationError("Output.selectable needs an explicit shape")


@dataclass(frozen=True, slots=True)
class Pagination:
    """Upstream pagination. The model only ever sees an opaque, signed cursor.

    * ``cursor``: the next token is read from ``next_path`` in the response and
      sent back in the ``param`` query parameter.
    * ``link``: the RFC 8288 ``Link: <...>; rel="next"`` header is followed. The
      URL must stay on the same origin and path, and is re-checked against the
      network policy.
    * ``page``: a page number in ``param`` starting at ``start``. If
      ``page_size`` is set, a short page ends the sequence.
    """

    type: Literal["cursor", "link", "page"]
    param: str | None = None
    next_path: str | None = None
    start: int = 1
    page_size: int | None = None

    def __post_init__(self) -> None:
        if self.type == "cursor" and (not self.param or not self.next_path):
            raise ConfigurationError("cursor pagination needs param= and next_path=")
        if self.type == "page" and not self.param:
            raise ConfigurationError("page pagination needs param=")
        if self.type not in ("cursor", "link", "page"):
            raise ConfigurationError("pagination type must be cursor, link or page")


# --------------------------------------------------------------------------- service


@dataclass(frozen=True, slots=True)
class Service:
    """A trusted upstream REST service: base URL, credentials and policies."""

    name: str
    base_url: str
    auth: Auth = field(default_factory=NoAuth)
    headers: Mapping[str, str] = field(default_factory=dict)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    limits: Limits = field(default_factory=Limits)
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    def __post_init__(self) -> None:
        if not _TOOL_NAME.match(self.name):
            raise ConfigurationError(f"invalid service name {self.name!r}")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("https", "http"):
            raise ConfigurationError(f"service {self.name}: base_url must be http(s)")
        if parts.scheme == "http" and not self.network.allow_http:
            raise ConfigurationError(
                f"service {self.name}: http:// base_url requires network.allow_http=True"
            )
        if parts.username is not None or parts.password is not None:
            raise ConfigurationError(f"service {self.name}: base_url must not contain userinfo")
        if parts.query or parts.fragment:
            raise ConfigurationError(f"service {self.name}: base_url must not have query/fragment")
        if not parts.hostname:
            raise ConfigurationError(f"service {self.name}: base_url has no host")
        _validate_auth(self.auth)
        for name, value in self.headers.items():
            _validate_header_name(name, allow_reserved=False)
            _validate_header_value(name, value)
        host = parts.hostname.lower()
        net = self.network
        hosts = tuple(h.lower().rstrip(".") for h in net.allow_hosts) or (host,)
        if not any(_host_matches(host, pattern) for pattern in hosts):
            raise ConfigurationError(
                f"service {self.name}: base_url host {host!r} is not in network.allow_hosts"
            )
        default_port = 443 if parts.scheme == "https" else 80
        ports = net.allow_ports or ((443, 80) if net.allow_http else (443,))
        if (parts.port or default_port) not in ports:
            raise ConfigurationError(
                f"service {self.name}: base_url port is not in network.allow_ports"
            )
        if net.max_redirects < 0:
            raise ConfigurationError("max_redirects must be >= 0")
        import ipaddress

        for cidr in net.allow_networks:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigurationError(f"invalid CIDR in allow_networks: {cidr!r}") from exc
        object.__setattr__(
            self,
            "network",
            NetworkPolicy(
                allow_hosts=hosts,
                allow_ports=tuple(ports),
                allow_http=net.allow_http,
                allow_networks=net.allow_networks,
                follow_redirects=net.follow_redirects,
                max_redirects=net.max_redirects,
            ),
        )
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))
        object.__setattr__(self, "headers", dict(self.headers))


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def host_allowed(host: str, policy: NetworkPolicy) -> bool:
    host = host.lower().rstrip(".")
    return any(_host_matches(host, p) for p in policy.allow_hosts)


def _validate_header_name(name: str, *, allow_reserved: bool) -> None:
    if not _HEADER_NAME.match(name):
        raise ConfigurationError(f"invalid header name {name!r}")
    if not allow_reserved and name.lower() in _FORBIDDEN_STATIC_HEADERS:
        raise ConfigurationError(
            f"header {name!r} cannot be set statically (use auth= for credentials)"
        )


def _validate_header_value(name: str, value: str) -> None:
    if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
        raise ConfigurationError(f"invalid value for header {name!r}")


# --------------------------------------------------------------------------- tools


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolSpec:
    """Fields shared by REST operations and Python tools."""

    name: str
    description: str
    input: Mapping[str, Any] = field(default_factory=dict)
    #: ``None`` is resolved in ``__post_init__``: REST operations infer it from the
    #: HTTP method; Python tools must declare it.
    effect: Effect = None  # type: ignore[assignment]
    output: Output = field(default_factory=Output)
    bind: Mapping[str, Binding] = field(default_factory=dict)
    required_scopes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    group: str | None = None
    requires_approval: bool | None = None
    rate_limit: RateLimit | None = None

    def __post_init__(self) -> None:
        if not _TOOL_NAME.match(self.name):
            raise ConfigurationError(
                f"invalid tool name {self.name!r}: use 1-64 letters, digits, '_' or '-', "
                "starting with a letter"
            )
        if not isinstance(self.description, str) or not self.description.strip():
            raise ConfigurationError(f"tool {self.name}: description is required")
        if len(self.description) > _MAX_DESCRIPTION:
            raise ConfigurationError(
                f"tool {self.name}: description longer than {_MAX_DESCRIPTION} characters"
            )
        if not _unset(self.effect):
            object.__setattr__(self, "effect", Effect(self.effect))
        object.__setattr__(self, "bind", {k: parse_binding(v) for k, v in dict(self.bind).items()})
        object.__setattr__(self, "required_scopes", tuple(self.required_scopes))
        object.__setattr__(self, "tags", tuple(self.tags))
        if self.group is not None and not _TOOL_NAME.match(self.group):
            raise ConfigurationError(f"tool {self.name}: invalid group name {self.group!r}")

    @property
    def needs_approval(self) -> bool:
        if self.requires_approval is not None:
            return self.requires_approval
        return self.effect is Effect.DESTRUCTIVE


def _unset(value: object) -> bool:
    return value is None


_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Default effect per HTTP method when a contract does not declare one. A POST
#: that only reads (a search endpoint) must say ``effect="read"`` explicitly.
_METHOD_EFFECTS = {
    "GET": Effect.READ,
    "HEAD": Effect.READ,
    "OPTIONS": Effect.READ,
    "POST": Effect.WRITE,
    "PUT": Effect.WRITE,
    "PATCH": Effect.WRITE,
    "DELETE": Effect.DESTRUCTIVE,
}
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Operation(ToolSpec):
    """A REST-backed tool.

    Argument placement: names that appear in ``path`` placeholders go into the
    path (strictly encoded). Remaining arguments go into the query string for
    GET/HEAD/DELETE/OPTIONS and into the body otherwise, unless ``query`` /
    ``body`` list names explicitly.
    """

    service: Service
    method: str = "GET"
    path: str = "/"
    query: tuple[str, ...] | None = None
    body: tuple[str, ...] | None = None
    body_format: Literal["json", "form"] = "json"
    headers: Mapping[str, str] = field(default_factory=dict)
    idempotency_header: str | None = None
    pagination: Pagination | None = None

    def __post_init__(self) -> None:
        ToolSpec.__post_init__(self)
        method = self.method.upper()
        if method not in _METHODS:
            raise ConfigurationError(f"tool {self.name}: unsupported HTTP method {self.method!r}")
        object.__setattr__(self, "method", method)
        inferred = _METHOD_EFFECTS[method]
        if _unset(self.effect):
            object.__setattr__(self, "effect", inferred)
        elif method == "DELETE" and self.effect is Effect.READ:
            raise ConfigurationError(
                f"tool {self.name}: a DELETE operation cannot be effect='read'"
            )
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ConfigurationError(
                f"tool {self.name}: path must start with '/' and contain no query or fragment"
            )
        if ".." in self.path.split("/"):
            raise ConfigurationError(f"tool {self.name}: path must not contain '..'")
        if self.body_format not in ("json", "form"):
            raise ConfigurationError(f"tool {self.name}: body_format must be json or form")
        for name, value in self.headers.items():
            _validate_header_name(name, allow_reserved=False)
            _validate_header_value(name, value)
        if self.idempotency_header is not None:
            _validate_header_name(self.idempotency_header, allow_reserved=False)
        if self.pagination is not None and self.effect is not Effect.READ:
            raise ConfigurationError(f"tool {self.name}: pagination is only for read tools")
        object.__setattr__(self, "headers", dict(self.headers))
        if self.query is not None:
            object.__setattr__(self, "query", tuple(self.query))
        if self.body is not None:
            object.__setattr__(self, "body", tuple(self.body))

    @property
    def path_params(self) -> tuple[str, ...]:
        return tuple(_PLACEHOLDER.findall(self.path))


@dataclass(frozen=True, slots=True, kw_only=True)
class PythonTool(ToolSpec):
    """A tool implemented by a trusted Python function.

    Toolbound does **not** sandbox the handler. It runs with your application's
    full privileges. Toolbound validates its input, enforces authorization,
    approval, rate limits and timeouts, and shapes its output, exactly like a
    REST operation.

    The handler receives validated arguments (and bound values) as keyword
    arguments. If it declares a parameter named ``ctx``, the trusted
    :class:`ExecutionContext` is passed there. Sync handlers run in a worker
    thread.
    """

    handler: Callable[..., Any]
    timeout: float = 30.0

    def __post_init__(self) -> None:
        ToolSpec.__post_init__(self)
        if _unset(self.effect):
            raise ConfigurationError(
                f"tool {self.name}: Python tools must declare effect='read', 'write' or "
                "'destructive' (Toolbound cannot tell what a handler does)"
            )
        if not callable(self.handler):
            raise ConfigurationError(f"tool {self.name}: handler must be callable")
        if self.timeout <= 0:
            raise ConfigurationError(f"tool {self.name}: timeout must be positive")


Tool = Operation | PythonTool
