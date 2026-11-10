"""The Gateway: one execution pipeline for every tool.

REST operations and Python tools pass through the same steps::

    resolve tool (visibility) -> validate arguments -> resolve trusted bindings
    -> open cursor -> required scopes -> authorize() -> rate limit
    -> approval (if required) -> replay check -> execute -> shape output -> result
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import functools
import inspect
import json
import logging
import random
import re
import secrets
import threading
import time
import warnings
import weakref
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path as FsPath
from typing import Any, TypeVar, cast
from urllib.parse import urlencode, urljoin, urlsplit

from .approval import ApprovalManager, PendingApproval
from .budget import ByteEstimator
from .context import ExecutionContext
from .contracts import (
    SAFE_METHODS,
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    Effect,
    NoAuth,
    Operation,
    Output,
    PythonTool,
    Tool,
    resolve_binding,
)
from .errors import (
    ApprovalInvalid,
    ConfigurationError,
    ErrorCode,
    NetworkBlocked,
    ToolboundWarning,
    ToolFailure,
)
from .exposure import Strategy, ToolDefinition, group_definitions
from .network import build_url, check_url, same_origin
from .observe import Event, NullObserver
from .paths import MISSING, parse_path
from .ports import (
    Approver,
    AuthorizationRequest,
    Authorizer,
    CredentialProvider,
    Decision,
    HttpRequest,
    HttpResponse,
    Observer,
    StateStore,
    TokenEstimator,
    Transport,
)
from .pyschema import handler_parameters, infer_input_schema
from .ratelimit import RateLimiter
from .result import ResultMeta, ToolError, ToolResult
from .schema import RESERVED_ARGUMENTS, ArgumentValidator, normalize_input_schema
from .shaping import CompiledOutput, ShapeResult, compile_output, process, shape_error_body
from .signing import Signer, canonical_digest
from .state import MemoryStateStore, claim_or_fail

logger = logging.getLogger("toolbound")

_CURSOR_PREFIX = "tbc2"
_MAX_CURSOR = 4096
#: Above this many bytes, output shaping runs in a worker thread so a large
#: upstream response cannot stall the event loop.
_OFFLOAD_BYTES = 256 * 1024
_USER_AGENT = "toolbound/0.2"
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_REQUEST_ID_HEADERS = ("x-request-id", "x-github-request-id", "request-id", "x-amzn-requestid")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,80}$")
_JSON_TYPE = re.compile(r"^application/(?:[\w.+-]+\+)?json$")

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(slots=True)
class _Registered:
    spec: Tool
    schema: dict[str, Any]
    validator: ArgumentValidator
    output: CompiledOutput
    fingerprint: str
    selectable: bool
    has_cursor: bool
    accepts_ctx: bool = False


class _ApprovalNeeded(Exception):
    def __init__(self, pending: PendingApproval) -> None:
        self.pending = pending


def allow_all(request: AuthorizationRequest) -> bool:
    """Authorizer that allows every visible tool. Use only for demos and tests."""
    return True


def deny_all(request: AuthorizationRequest) -> bool:
    """Authorizer that denies everything."""
    return False


class Gateway:
    """Registers tools and executes model tool calls under trusted policy.

    Args:
        authorize: **Required.** Your policy hook ``(AuthorizationRequest) -> bool |
            Decision`` (sync or async). Pass :func:`allow_all` explicitly to
            disable application-level authorization.
        credentials: Resolves credential names to secret values.
        approver: Optional inline approval hook. Without one, calls that need
            approval return ``approval_required`` with a :class:`PendingApproval`
            for your UI, and you finish them with :meth:`resume`.
        transport: HTTP transport. Defaults to :class:`toolbound.SecureTransport`.
        estimator: Token estimator. Defaults to :class:`ByteEstimator`.
        observer: Receives structured events. Defaults to no-op.
        state: Store for single-use approvals and call-id replay protection.
        secret: HMAC key (>= 32 bytes) for cursors and approval grants. If
            omitted a random per-process key is used, so cursors and grants do
            not survive restarts or work across processes.
        visibility: Optional ``(ctx, tool) -> bool`` deciding which tools a
            user can even see. Hidden tools behave exactly like unknown tools.
        transforms: Named trusted transforms usable from declarative shapes.
        max_argument_bytes: Upper bound for serialized tool arguments.
    """

    def __init__(
        self,
        *,
        authorize: Authorizer,
        credentials: CredentialProvider | None = None,
        approver: Approver | None = None,
        transport: Transport | None = None,
        estimator: TokenEstimator | None = None,
        observer: Observer | None = None,
        state: StateStore | None = None,
        secret: bytes | str | None = None,
        visibility: Callable[[ExecutionContext, Tool], bool] | None = None,
        transforms: Mapping[str, Callable[[Any], Any]] | None = None,
        approval_ttl: float = 600,
        cursor_ttl: float = 3600,
        call_id_ttl: float = 86_400,
        max_argument_bytes: int = 64 * 1024,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if authorize is None or not callable(authorize):
            raise ConfigurationError(
                "Gateway(authorize=...) is required. Pass your policy function, or "
                "toolbound.allow_all to explicitly disable application authorization."
            )
        self._authorize_hook = authorize
        self._credentials = credentials
        self._approver = approver
        self._transport = transport
        self._owns_transport = transport is None
        self._estimator: TokenEstimator = estimator if estimator is not None else ByteEstimator()
        self._observer: Observer = observer if observer is not None else NullObserver()
        self._state: StateStore = state if state is not None else MemoryStateStore()
        self._signer = Signer(secret)
        self._approvals = ApprovalManager(self._signer, self._state, ttl_seconds=approval_ttl)
        self._visibility = visibility
        self._transforms = dict(transforms or {})
        self._cursor_ttl = cursor_ttl
        self._call_id_ttl = call_id_ttl
        self._max_argument_bytes = max_argument_bytes
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter, not crypto
        self._tools: dict[str, _Registered] = {}
        self._groups: dict[str, list[str]] = {}
        # asyncio primitives belong to one event loop; keep them per loop.
        self._semaphores: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, dict[str, asyncio.Semaphore]
        ] = weakref.WeakKeyDictionary()
        self._sem_lock = threading.Lock()
        self._rate = RateLimiter()
        self._warned_ephemeral = False
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None

    # ------------------------------------------------------------------ lifecycle

    async def __aenter__(self) -> Gateway:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the transport if the gateway created it."""
        if self._transport is not None and self._owns_transport:
            await self._transport.aclose()
            self._transport = None
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def _get_transport(self) -> Transport:
        if self._transport is None:
            from toolbound.transport.http import SecureTransport

            self._transport = SecureTransport()
            self._owns_transport = True
        return self._transport

    # ------------------------------------------------------------------ registration

    def register(self, *tools: Tool) -> Gateway:
        """Register REST operations and/or Python tools. Returns ``self``."""
        for spec in tools:
            self._register_one(spec)
        return self

    def tool(
        self,
        func: Callable[..., Any] | None = None,
        /,
        *,
        name: str | None = None,
        description: str | None = None,
        input: Mapping[str, Any] | None = None,
        effect: Effect | str | None = None,
        output: Output | None = None,
        bind: Mapping[str, Any] | None = None,
        required_scopes: Sequence[str] = (),
        tags: Sequence[str] = (),
        group: str | None = None,
        requires_approval: bool | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Decorator registering a trusted Python function as a tool.

        The input schema is inferred from type hints unless ``input`` is given;
        the description defaults to the first paragraph of the docstring.
        """

        def decorate(fn: F) -> F:
            doc = inspect.getdoc(fn) or ""
            spec = PythonTool(
                name=name or fn.__name__,
                description=description or doc.split("\n\n")[0].strip(),
                input=dict(input) if input is not None else {},
                effect=cast(Effect, None if effect is None else Effect(effect)),
                output=output if output is not None else Output(),
                bind=dict(bind or {}),
                required_scopes=tuple(required_scopes),
                tags=tuple(tags),
                group=group,
                requires_approval=requires_approval,
                handler=fn,
                timeout=timeout,
            )
            self._register_one(spec, infer=input is None)
            return fn

        return decorate(func) if func is not None else decorate

    def load(self, path: str | FsPath) -> Gateway:
        """Load declarative contracts from a ``.yaml``/``.json`` file or directory."""
        from toolbound.loaders import load_contracts

        return self.register(*load_contracts(path))

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools)

    def get_tool(self, name: str) -> Tool:
        return self._tools[name].spec

    def _register_one(self, spec: Tool, *, infer: bool = False) -> None:
        if not isinstance(spec, Operation | PythonTool):
            raise ConfigurationError(f"cannot register {type(spec).__name__}; expected a Tool")
        if spec.name in self._tools or spec.name in self._groups:
            raise ConfigurationError(f"a tool named {spec.name!r} is already registered")
        if spec.group is not None and spec.group in self._tools:
            raise ConfigurationError(f"group {spec.group!r} clashes with a tool name")

        bound_names = set(spec.bind)
        if isinstance(spec, PythonTool) and (infer or not spec.input):
            raw_schema: Mapping[str, Any] = infer_input_schema(spec.handler, exclude=bound_names)
        else:
            raw_schema = spec.input
        schema = normalize_input_schema(spec.name, raw_schema)
        props: dict[str, Any] = schema["properties"]
        required = set(schema.get("required", []))

        clash = bound_names & set(props)
        if clash:
            raise ConfigurationError(
                f"tool {spec.name}: bound parameter(s) {sorted(clash)} must not appear in the "
                "model-visible input"
            )
        reserved = RESERVED_ARGUMENTS & set(props)
        if reserved:
            raise ConfigurationError(
                f"tool {spec.name}: argument names {sorted(reserved)} are reserved"
            )

        accepts_ctx = False
        if isinstance(spec, Operation):
            for param in spec.path_params:
                if param in bound_names:
                    continue
                if param not in props:
                    raise ConfigurationError(
                        f"tool {spec.name}: path parameter {{{param}}} is neither an input "
                        "property nor bound"
                    )
                if param not in required:
                    raise ConfigurationError(
                        f"tool {spec.name}: path parameter {param!r} must be required"
                    )
            known = set(props) | bound_names
            for listed in (spec.query or ()) + (spec.body or ()):
                if listed not in known:
                    raise ConfigurationError(
                        f"tool {spec.name}: {listed!r} in query/body is not an input or binding"
                    )
            pagination = spec.pagination
            if pagination is not None and pagination.param in known:
                raise ConfigurationError(
                    f"tool {spec.name}: pagination param {pagination.param!r} must not be an input"
                )
            if pagination is not None and pagination.next_path:
                parse_path(pagination.next_path)
        else:
            names, var_kw, accepts_ctx = handler_parameters(spec.handler)
            missing = (set(props) | bound_names) - names
            if missing and not var_kw:
                raise ConfigurationError(
                    f"tool {spec.name}: handler does not accept argument(s) {sorted(missing)}"
                )

        compiled = compile_output(spec.output, self._transforms)
        selectable = spec.output.selectable
        has_cursor = spec.effect is Effect.READ and (
            spec.output.continuation
            or (isinstance(spec, Operation) and spec.pagination is not None)
        )
        if selectable:
            keys = compiled.selectable_fields
            always = sorted(compiled.required)
            desc = "Optional subset of fields to return; omit for all."
            if always:
                desc += f" Always included: {', '.join(always)}."
            props["fields"] = {
                "type": "array",
                "items": {"type": "string", "enum": keys},
                "uniqueItems": True,
                "description": desc,
            }
        if has_cursor:
            props["cursor"] = {
                "type": "string",
                "maxLength": 4096,
                "description": "Opaque next_cursor from a previous result, to get more.",
            }

        validator = ArgumentValidator(schema, max_argument_bytes=self._max_argument_bytes)
        fingerprint = canonical_digest(_fingerprint_source(spec, schema))
        self._tools[spec.name] = _Registered(
            spec=spec,
            schema=schema,
            validator=validator,
            output=compiled,
            fingerprint=fingerprint,
            selectable=selectable,
            has_cursor=has_cursor,
            accepts_ctx=accepts_ctx,
        )
        if spec.group is not None:
            self._groups.setdefault(spec.group, []).append(spec.name)

    # ------------------------------------------------------------------ exposure

    def definitions(
        self,
        ctx: ExecutionContext,
        *,
        tags: Iterable[str] | None = None,
        names: Iterable[str] | None = None,
        strategy: Strategy = "direct",
    ) -> list[ToolDefinition]:
        """Tool definitions visible to ``ctx``, optionally filtered by tags/names.

        ``strategy="grouped"`` merges tools sharing a ``group`` into one tool with
        an ``action`` argument (fewer definitions for larger catalogs).
        """
        wanted_tags = set(tags) if tags is not None else None
        wanted_names = set(names) if names is not None else None
        visible: list[_Registered] = []
        for reg in self._tools.values():
            if wanted_names is not None and reg.spec.name not in wanted_names:
                continue
            if wanted_tags is not None and not wanted_tags & set(reg.spec.tags):
                continue
            if self._visible(reg.spec, ctx):
                visible.append(reg)
        direct = [
            ToolDefinition(r.spec.name, r.spec.description, json.loads(json.dumps(r.schema)))
            for r in visible
        ]
        if strategy == "direct":
            return direct
        if strategy != "grouped":
            raise ValueError("strategy must be 'direct' or 'grouped'")
        out: list[ToolDefinition] = []
        grouped: dict[str, list[ToolDefinition]] = {}
        for reg, definition in zip(visible, direct, strict=True):
            if reg.spec.group is None:
                out.append(definition)
            else:
                grouped.setdefault(reg.spec.group, []).append(definition)
        for group, members in grouped.items():
            out.append(members[0] if len(members) == 1 else group_definitions(group, members))
        return out

    def _visible(self, spec: Tool, ctx: ExecutionContext) -> bool:
        if not set(spec.required_scopes) <= ctx.scopes:
            return False
        return self._visibility is None or bool(self._visibility(ctx, spec))

    # ------------------------------------------------------------------ approvals

    def pending_approval(self, request: PendingApproval | str) -> PendingApproval:
        """Rebuild and verify a :class:`PendingApproval` from its ``token``.

        Use it when an approval request comes back from storage, a browser or a
        workflow engine. Raises :class:`~toolbound.ApprovalInvalid` if the token
        is forged, altered, expired, or from another gateway secret.
        """
        return self._approvals.open(request)

    def grant(self, request: PendingApproval | str, *, approved_by: str) -> str:
        """Issue a single-use grant for a gateway-issued approval request (host code only).

        ``request`` is a :class:`PendingApproval` or its ``token``. Only the
        token is trusted: the other fields of a ``PendingApproval`` object are
        ignored. Raises :class:`~toolbound.ApprovalInvalid` for a forged or
        expired request.
        """
        return self._approvals.grant(request, approved_by=approved_by)

    async def deny(self, request: PendingApproval | str) -> PendingApproval:
        """Record that a human rejected a request; it can never be granted afterwards.

        Raises :class:`~toolbound.ApprovalInvalid` for a forged or expired request.
        """
        return await self._approvals.deny(request)

    async def resume(
        self,
        request: PendingApproval | str,
        *,
        ctx: ExecutionContext,
        approved_by: str,
        call_id: str | None = None,
    ) -> ToolResult:
        """Approve a request and execute it in one step (host code only).

        The tool and arguments come from the verified request token, and the
        call runs under the live ``ctx``, which must match the requesting actor
        and tenant. Never raises for an invalid request: it returns an
        ``approval_invalid`` result.
        """
        if not isinstance(ctx, ExecutionContext):
            raise TypeError("ctx must be an ExecutionContext created by trusted code")
        try:
            pending = self._approvals.open(request)
            token = self._approvals.grant(pending, approved_by=approved_by)
        except ApprovalInvalid as failure:
            return ToolResult(
                ok=False,
                tool=request.tool if isinstance(request, PendingApproval) else "<approval>",
                error=ToolError(failure.code, failure.message),
                call_id=call_id,
            )
        return await self.call(
            pending.tool, dict(pending.arguments), ctx=ctx, approval=token, call_id=call_id
        )

    # ------------------------------------------------------------------ execution

    async def call(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        *,
        ctx: ExecutionContext,
        call_id: str | None = None,
        approval: str | None = None,
    ) -> ToolResult:
        """Execute one tool call. Never raises for expected failures.

        Args:
            name: Tool (or group) name chosen by the model.
            arguments: Arguments chosen by the model (untrusted).
            ctx: Trusted execution context from your application.
            call_id: The provider's tool-call id. For write/destructive tools a
                repeated id is rejected, preventing accidental double execution.
            approval: A grant token from :meth:`grant` (host code only).
        """
        if not isinstance(ctx, ExecutionContext):
            raise TypeError("ctx must be an ExecutionContext created by trusted code")
        started = time.perf_counter()
        display = name if isinstance(name, str) and len(name) <= 64 else "<invalid>"
        self._emit("call.start", display, ctx)
        http_status: list[int] = []
        try:
            name, arguments = self._resolve_group(name, arguments, ctx)
            reg = self._tools.get(name) if isinstance(name, str) else None
            if reg is None or not self._visible(reg.spec, ctx):
                raise ToolFailure(ErrorCode.UNKNOWN_TOOL, f"unknown tool {display!r}")
            display = reg.spec.name
            result = await self._run(reg, arguments, ctx, call_id, approval, http_status)
        except _ApprovalNeeded as needed:
            self._emit("approval.required", display, ctx, outcome="approval_required")
            result = ToolResult(
                ok=False,
                tool=display,
                error=ToolError(
                    ErrorCode.APPROVAL_REQUIRED,
                    "This action needs human approval. The request was sent to the user; "
                    "wait for their decision instead of retrying.",
                ),
                approval=needed.pending,
                call_id=call_id,
            )
        except ToolFailure as failure:
            if failure.code in (ErrorCode.FORBIDDEN,):
                self._emit("policy.denied", display, ctx, outcome=failure.code.value)
            elif failure.code is ErrorCode.NETWORK_BLOCKED:
                self._emit("network.blocked", display, ctx, outcome=failure.code.value)
            result = ToolResult(
                ok=False,
                tool=display,
                error=ToolError(
                    failure.code,
                    failure.message,
                    retryable=failure.retryable,
                    details=dict(failure.details),
                    retry_after=failure.retry_after,
                ),
                http_status=failure.http_status,
                call_id=call_id,
            )
        except asyncio.CancelledError:
            self._emit("call.end", display, ctx, outcome="cancelled")
            raise
        except Exception:
            logger.exception("tool %s failed with an unexpected error", display)
            result = ToolResult(
                ok=False,
                tool=display,
                error=ToolError(ErrorCode.INTERNAL_ERROR, "the tool failed with an internal error"),
                call_id=call_id,
            )
        duration = (time.perf_counter() - started) * 1000
        result = replace(result, duration_ms=duration)
        self._emit(
            "call.end",
            display,
            ctx,
            outcome="ok" if result.ok else result.error.code.value if result.error else None,
            duration_ms=duration,
            http_status=result.http_status,
        )
        return result

    def _resolve_group(
        self, name: str, arguments: Mapping[str, Any] | None, ctx: ExecutionContext
    ) -> tuple[str, Mapping[str, Any] | None]:
        if not isinstance(name, str) or name not in self._groups:
            return name, arguments
        if not isinstance(arguments, Mapping):
            raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, "arguments must be a JSON object")
        extra = set(arguments) - {"action", "arguments"}
        if extra:
            raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, f"unknown argument(s) {sorted(extra)}")
        action = arguments.get("action")
        visible = [n for n in self._groups[name] if self._visible(self._tools[n].spec, ctx)]
        if action not in visible:  # hidden actions look exactly like missing ones
            raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, f"action must be one of {visible}")
        inner = arguments.get("arguments", {})
        return str(action), inner

    async def _run(
        self,
        reg: _Registered,
        arguments: Mapping[str, Any] | None,
        ctx: ExecutionContext,
        call_id: str | None,
        approval: str | None,
        http_status: list[int],
    ) -> ToolResult:
        spec = reg.spec
        raw = {} if arguments is None else arguments
        args = reg.validator.validate(dict(raw) if isinstance(raw, Mapping) else raw)
        fields = args.pop("fields", None) if reg.selectable else None
        cursor_token = args.pop("cursor", None) if reg.has_cursor else None
        bound = self._resolve_bound(spec, ctx)
        cursor_state = (
            self._open_cursor(cursor_token, reg, ctx, args, bound) if cursor_token else None
        )

        missing_scopes = set(spec.required_scopes) - ctx.scopes
        if missing_scopes:
            raise ToolFailure(ErrorCode.FORBIDDEN, "missing required permission for this tool")
        decision = await self._authorize(AuthorizationRequest(ctx, spec, dict(args), dict(bound)))
        if not decision.allowed:
            raise ToolFailure(ErrorCode.FORBIDDEN, decision.reason or "not permitted")
        if spec.rate_limit is not None:
            self._rate.check(spec.name, spec.rate_limit, ctx)

        grant: dict[str, Any] | None = None
        if spec.needs_approval:
            grant = await self._ensure_approval(reg, ctx, args, bound, approval)

        async def commit() -> None:
            """Claim the call id, then use up the approval: right before execution,
            after every check that can fail without side effects."""
            if call_id is not None and spec.effect is not Effect.READ:
                key = (
                    f"call:{canonical_digest([ctx.actor, ctx.tenant])[:16]}:"
                    f"{canonical_digest([spec.name, str(call_id)])}"
                )
                if not await claim_or_fail(self._state, key, self._call_id_ttl):
                    raise ToolFailure(
                        ErrorCode.DUPLICATE_CALL,
                        "this tool call was already executed; it will not run twice",
                    )
            if grant is not None:
                await self._approvals.claim(grant, ctx)
                self._emit(
                    "approval.granted",
                    spec.name,
                    ctx,
                    outcome="ok",
                    attributes={"approved_by": grant.get("by")},
                )

        idempotency_key = (str(grant["i"]) if grant is not None else None) or (
            canonical_digest([ctx.actor, ctx.tenant, spec.name, str(call_id)])[:32]
            if call_id
            else None
        )
        if isinstance(spec, Operation):
            shaped, meta_source, next_upstream, status = await self._execute_rest(
                reg, spec, ctx, args, bound, cursor_state, fields, idempotency_key, commit
            )
            http_status.append(status)
        else:
            await commit()
            shaped = await self._execute_python(reg, spec, ctx, args, bound, cursor_state, fields)
            meta_source, next_upstream, status = {"tool": spec.name}, None, None

        next_cursor = None
        if reg.has_cursor:
            current_upstream = cursor_state.get("u") if cursor_state else None
            if shaped.next_offset is not None:
                next_cursor = self._issue_cursor(
                    reg, ctx, args, bound, current_upstream, shaped.next_offset
                )
            elif next_upstream is not None:
                next_cursor = self._issue_cursor(reg, ctx, args, bound, next_upstream, 0)

        report = shaped.report
        meta = ResultMeta(
            truncated=report.truncated,
            omitted=tuple(report.omissions()),
            redacted=report.redacted,
            warnings=tuple(report.warnings),
            next_cursor=next_cursor,
            items_returned=len(shaped.data) if isinstance(shaped.data, list) else None,
            items_total=shaped.total_items,
            estimated_tokens=shaped.estimated_tokens,
            source=meta_source,
        )
        for warning in report.warnings:
            self._emit(
                "schema.warning", spec.name, ctx, outcome="warning", attributes={"warning": warning}
            )
        return ToolResult(
            ok=True,
            tool=spec.name,
            data=shaped.data,
            meta=meta,
            http_status=status,
            call_id=call_id,
        )

    def _resolve_bound(self, spec: Tool, ctx: ExecutionContext) -> dict[str, Any]:
        bound: dict[str, Any] = {}
        for name, binding in spec.bind.items():
            try:
                bound[name] = resolve_binding(binding, ctx)
            except LookupError as exc:
                logger.error(
                    "tool %s: context value %s is missing for binding %r", spec.name, exc, name
                )
                raise ToolFailure(
                    ErrorCode.FORBIDDEN, "the current session lacks context required by this tool"
                ) from None
        return bound

    async def _authorize(self, request: AuthorizationRequest) -> Decision:
        outcome = self._authorize_hook(request)
        if inspect.isawaitable(outcome):
            outcome = await outcome
        if isinstance(outcome, Decision):
            return outcome
        if outcome is True:
            return Decision.allow()
        if outcome is False:
            return Decision.deny()
        raise ConfigurationError("authorize() must return bool or Decision")

    async def _ensure_approval(
        self,
        reg: _Registered,
        ctx: ExecutionContext,
        args: Mapping[str, Any],
        bound: Mapping[str, Any],
        token: str | None,
    ) -> dict[str, Any]:
        """Return a verified (not yet used) grant, or stop for approval."""
        spec = reg.spec
        if token is not None:
            return self._approvals.verify(
                token,
                ctx=ctx,
                tool=spec.name,
                fingerprint=reg.fingerprint,
                arguments=args,
                bound=bound,
            )
        self._warn_if_ephemeral()
        pending = self._approvals.create(
            ctx=ctx,
            tool=spec.name,
            effect=spec.effect,
            fingerprint=reg.fingerprint,
            arguments=args,
            bound=bound,
            target=self._approval_target(reg, args, bound),
        )
        if self._approver is None:
            raise _ApprovalNeeded(pending)
        decision = self._approver(pending)
        if inspect.isawaitable(decision):
            decision = await decision
        if decision is not True:
            raise ToolFailure(ErrorCode.APPROVAL_DENIED, "the user did not approve this action")
        grant = self._approvals.grant(pending, approved_by="inline-approver")
        return self._approvals.verify(
            grant,
            ctx=ctx,
            tool=spec.name,
            fingerprint=reg.fingerprint,
            arguments=args,
            bound=bound,
        )

    def _approval_target(
        self, reg: _Registered, args: Mapping[str, Any], bound: Mapping[str, Any]
    ) -> dict[str, Any]:
        spec = reg.spec
        if not isinstance(spec, Operation):
            return {"kind": "python", "tool": spec.name}
        values = {k: args[k] for k in reg.schema["properties"] if k in args}
        values.update(bound)
        path_values = {p: values[p] for p in spec.path_params}
        remaining = {k: v for k, v in values.items() if k not in path_values}
        query_names, body_names = _placement(spec, remaining)
        query = [(k, remaining[k]) for k in query_names if k in remaining]
        return {
            "kind": "rest",
            "service": spec.service.name,
            "method": spec.method,
            "url": build_url(spec.service.base_url, spec.path, path_values, query),
            "body_fields": [k for k in body_names if k in remaining],
        }

    def _warn_if_ephemeral(self) -> None:
        if self._signer.ephemeral and not self._warned_ephemeral:
            self._warned_ephemeral = True
            warnings.warn(
                "Gateway has no secret=, so it uses a random per-process key: cursors and "
                "approvals stop working after a restart and across workers. Pass a 32+ byte "
                "secret from your secret manager in production.",
                ToolboundWarning,
                stacklevel=3,
            )

    # ------------------------------------------------------------------ cursors

    def _cursor_binding(
        self,
        reg: _Registered,
        ctx: ExecutionContext,
        args: Mapping[str, Any],
        bound: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "t": reg.spec.name,
            "f": reg.fingerprint[:16],
            "a": canonical_digest([ctx.actor, ctx.tenant])[:16],
            "h": canonical_digest(dict(args))[:16],
            # Trusted values too: a cursor minted under one org/repo binding must not
            # replay that binding after the session's context changed.
            "b": canonical_digest(dict(bound))[:16],
        }

    def _issue_cursor(
        self,
        reg: _Registered,
        ctx: ExecutionContext,
        args: Mapping[str, Any],
        bound: Mapping[str, Any],
        upstream: Any,
        offset: int,
    ) -> str | None:
        self._warn_if_ephemeral()
        payload = {**self._cursor_binding(reg, ctx, args, bound), "u": upstream, "o": offset}
        token = self._signer.seal(_CURSOR_PREFIX, payload, self._cursor_ttl)
        if len(token) > _MAX_CURSOR:
            logger.warning("tool %s: upstream cursor too large to carry; stopping", reg.spec.name)
            return None
        return token

    def _open_cursor(
        self,
        token: Any,
        reg: _Registered,
        ctx: ExecutionContext,
        args: Mapping[str, Any],
        bound: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = self._signer.unseal(_CURSOR_PREFIX, token, max_length=_MAX_CURSOR)
        if payload is None:
            raise ToolFailure(ErrorCode.INVALID_CURSOR, "cursor is invalid or has expired")
        expected = self._cursor_binding(reg, ctx, args, bound)
        if any(payload.get(k) != v for k, v in expected.items()):
            raise ToolFailure(
                ErrorCode.INVALID_CURSOR,
                "cursor belongs to a different tool, user, or set of arguments",
            )
        if not isinstance(payload.get("o"), int) or payload["o"] < 0:
            raise ToolFailure(ErrorCode.INVALID_CURSOR, "cursor is invalid")
        return payload

    # ------------------------------------------------------------------ python tools

    async def _execute_python(
        self,
        reg: _Registered,
        spec: PythonTool,
        ctx: ExecutionContext,
        args: dict[str, Any],
        bound: dict[str, Any],
        cursor_state: dict[str, Any] | None,
        fields: list[str] | None,
    ) -> ShapeResult:
        kwargs = {**args, **bound}
        if reg.accepts_ctx:
            kwargs["ctx"] = ctx
        try:
            async with asyncio.timeout(spec.timeout):
                if inspect.iscoroutinefunction(spec.handler):
                    value = await spec.handler(**kwargs)
                else:
                    # A private pool: stuck handlers can never starve the default
                    # executor that DNS resolution (getaddrinfo) relies on.
                    value = await asyncio.get_running_loop().run_in_executor(
                        self._handler_pool(), functools.partial(spec.handler, **kwargs)
                    )
                    if inspect.isawaitable(value):
                        value = await value
        except TimeoutError:
            if spec.effect is not Effect.READ:
                # The handler may have done its work (or still be running in a thread).
                raise ToolFailure(
                    ErrorCode.OUTCOME_UNKNOWN,
                    f"tool timed out after {spec.timeout:g}s; the action may or may not have "
                    "been applied. Check the current state before trying again.",
                    retryable=False,
                ) from None
            raise ToolFailure(
                ErrorCode.TIMEOUT, f"tool timed out after {spec.timeout:g}s"
            ) from None
        try:
            size = len(json.dumps(value))
        except (TypeError, ValueError):
            raise ToolFailure(
                ErrorCode.INTERNAL_ERROR, "the tool returned a value that is not JSON-serializable"
            ) from None
        offset = int(cursor_state["o"]) if cursor_state else 0
        return await self._process(reg, value, size, offset=offset, fields=fields, secrets=())

    async def _process(
        self,
        reg: _Registered,
        value: Any,
        size: int,
        *,
        offset: int,
        fields: list[str] | None,
        secrets: Sequence[str],
    ) -> ShapeResult:
        def run() -> ShapeResult:
            return process(
                reg.output,
                value,
                estimator=self._estimator,
                offset=offset,
                selected=fields,
                secrets=secrets,
            )

        if size > _OFFLOAD_BYTES:
            return await asyncio.to_thread(run)
        return run()

    # ------------------------------------------------------------------ REST

    async def _execute_rest(
        self,
        reg: _Registered,
        op: Operation,
        ctx: ExecutionContext,
        args: dict[str, Any],
        bound: dict[str, Any],
        cursor_state: dict[str, Any] | None,
        fields: list[str] | None,
        idempotency_key: str | None,
        commit: Callable[[], Awaitable[None]],
    ) -> tuple[ShapeResult, dict[str, Any], Any, int]:
        svc = op.service
        # Deterministic order (schema order, then bindings) regardless of model output order.
        values = {k: args[k] for k in reg.schema["properties"] if k in args}
        values.update(bound)
        path_values = {p: values[p] for p in op.path_params}
        remaining = {k: v for k, v in values.items() if k not in path_values}
        query_names, body_names = _placement(op, remaining)
        query = [(k, remaining[k]) for k in query_names if k in remaining]
        body = {k: remaining[k] for k in body_names if k in remaining}

        upstream = cursor_state.get("u") if cursor_state else None
        pagination = op.pagination
        page_number: int | None = None
        if pagination is not None and pagination.type == "page":
            page_number = int(upstream) if isinstance(upstream, int) else pagination.start
            query.append((str(pagination.param), page_number))
        elif pagination is not None and pagination.type == "cursor" and upstream is not None:
            query.append((str(pagination.param), upstream))

        secrets: list[str] = []
        headers: dict[str, str] = {"Accept": "application/json", "User-Agent": _USER_AGENT}
        headers.update(svc.headers)
        headers.update(op.headers)
        credential_header: str | None = None
        auth = svc.auth
        if not isinstance(auth, NoAuth):
            secret = await self._credential(auth.credential, ctx, svc.name)
            secrets.append(secret)
            if isinstance(auth, BearerAuth):
                credential_header = "Authorization"
                headers["Authorization"] = f"Bearer {secret}"
            elif isinstance(auth, BasicAuth):
                credential_header = "Authorization"
                headers["Authorization"] = "Basic " + base64.b64encode(secret.encode()).decode()
                secrets.append(headers["Authorization"].split(" ", 1)[1])
            elif isinstance(auth, ApiKeyAuth):
                if auth.header is not None:
                    credential_header = auth.header
                    headers[auth.header] = secret
                else:
                    query.append((str(auth.query), secret))
        if op.idempotency_header is not None:
            headers[op.idempotency_header] = idempotency_key or _random_key()

        if pagination is not None and pagination.type == "link" and isinstance(upstream, str):
            url = upstream
            expected = build_url(svc.base_url, op.path, path_values, [])
            if not same_origin(url, expected) or urlsplit(url).path != urlsplit(expected).path:
                raise ToolFailure(ErrorCode.INVALID_CURSOR, "cursor does not match this operation")
            if isinstance(auth, ApiKeyAuth) and auth.query is not None:
                url += ("&" if "?" in url else "?") + urlencode({auth.query: secrets[0]})
        else:
            url = build_url(svc.base_url, op.path, path_values, query)
        check_url(url, svc.network)

        payload: bytes | None = None
        if body or (op.method in ("POST", "PUT", "PATCH") and op.body is not None):
            if op.body_format == "json":
                payload = json.dumps(body, ensure_ascii=False).encode()
                headers["Content-Type"] = "application/json"
            else:
                payload = urlencode(list(body.items()), doseq=True).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if len(payload) > svc.limits.max_request_bytes:
                raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, "request body is too large")

        request = HttpRequest(
            method=op.method,
            url=url,
            headers=tuple(headers.items()),
            body=payload,
            network=svc.network,
            timeout=svc.limits.timeout,
            connect_timeout=svc.limits.connect_timeout,
            max_response_bytes=svc.limits.max_response_bytes,
        )
        await commit()  # everything above can fail without side effects
        try:
            response = await self._send(op, request, ctx, credential_header)
        except ToolFailure as failure:
            if op.effect is not Effect.READ and failure.request_sent is not False:
                # Some attempt or redirect hop may have reached the upstream.
                raise ToolFailure(
                    ErrorCode.OUTCOME_UNKNOWN,
                    "the upstream did not confirm the result; the change may or may not have "
                    "been applied. Check the current state before trying again.",
                    retryable=False,
                ) from None
            raise
        source = {"service": svc.name, "operation": op.name, "status": response.status}
        request_id = next(
            (response.headers[h] for h in _REQUEST_ID_HEADERS if h in response.headers), None
        )
        if request_id and _SAFE_ID.match(request_id):
            source["request_id"] = request_id

        if response.status >= 400:
            raise self._upstream_failure(reg, response, secrets, write=op.effect is not Effect.READ)
        if 300 <= response.status < 400:
            if op.effect is not Effect.READ:
                raise ToolFailure(
                    ErrorCode.OUTCOME_UNKNOWN,
                    f"the upstream answered with a redirect (HTTP {response.status}) after "
                    "receiving the request; the change may or may not have been applied. "
                    "Check the current state before trying again.",
                    retryable=False,
                    http_status=response.status,
                )
            raise ToolFailure(
                ErrorCode.UPSTREAM_ERROR,
                f"upstream redirected (HTTP {response.status}) and redirects are disabled",
                http_status=response.status,
            )
        if len(response.body) > _OFFLOAD_BYTES:
            decoded = await asyncio.to_thread(_decode_body, response, reg.output.spec.accept_text)
        else:
            decoded = _decode_body(response, reg.output.spec.accept_text)
        offset = int(cursor_state["o"]) if cursor_state else 0
        shaped = await self._process(
            reg, decoded, len(response.body), offset=offset, fields=fields, secrets=secrets
        )
        next_upstream = None
        if pagination is not None and shaped.next_offset is None:
            next_upstream = _next_upstream(op, response, decoded, reg, page_number, shaped)
        return shaped, source, next_upstream, response.status

    async def _credential(self, name: str, ctx: ExecutionContext, service: str) -> str:
        if self._credentials is None:
            raise ConfigurationError(
                f"service {service} needs credential {name!r} but no credentials= provider is set"
            )
        value = self._credentials.get(name, ctx)
        if inspect.isawaitable(value):
            value = await value
        if not value or not isinstance(value, str):
            logger.error("credential %r for service %s is not available", name, service)
            raise ToolFailure(
                ErrorCode.INTERNAL_ERROR, f"credentials for service {service} are not configured"
            )
        if any(c in value for c in "\r\n\x00"):
            raise ToolFailure(ErrorCode.INTERNAL_ERROR, "configured credential is malformed")
        return value

    async def _send(
        self,
        op: Operation,
        request: HttpRequest,
        ctx: ExecutionContext,
        credential_header: str | None,
    ) -> HttpResponse:
        svc = op.service
        retry = svc.retry
        # Retry automatically only what cannot change state twice: declared reads over
        # safe methods, or requests that carry a stable idempotency key.
        retry_allowed = (
            op.effect is Effect.READ and op.method in SAFE_METHODS
        ) or op.idempotency_header is not None
        attempts = retry.max_attempts if retry_allowed else 1
        semaphore = self._semaphore(f"{svc.name}|{svc.base_url}", svc.limits.max_concurrency)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + svc.limits.total_timeout
        try:
            async with asyncio.timeout_at(deadline), semaphore:
                return await self._attempts(op, request, ctx, credential_header, attempts, deadline)
        except TimeoutError:
            raise ToolFailure(
                ErrorCode.TIMEOUT,
                f"the call exceeded its {svc.limits.total_timeout:g}s deadline",
                request_sent=None,
            ) from None

    def _handler_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._sem_lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=32, thread_name_prefix="toolbound-tool"
                )
            return self._executor

    def _semaphore(self, service: str, limit: int) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        with self._sem_lock:
            per_loop = self._semaphores.get(loop)
            if per_loop is None:
                per_loop = self._semaphores[loop] = {}
            semaphore = per_loop.get(service)
            if semaphore is None:
                semaphore = per_loop[service] = asyncio.Semaphore(limit)
        return semaphore

    async def _attempts(
        self,
        op: Operation,
        request: HttpRequest,
        ctx: ExecutionContext,
        credential_header: str | None,
        attempts: int,
        deadline: float,
    ) -> HttpResponse:
        retry = op.service.retry
        loop = asyncio.get_running_loop()
        maybe_sent = False  # did any earlier attempt possibly reach the upstream?
        for attempt in range(1, attempts + 1):
            try:
                response = await self._send_following_redirects(op, request, credential_header)
            except ToolFailure as failure:
                if failure.request_sent is not False:
                    maybe_sent = True
                elif maybe_sent:
                    failure.request_sent = None  # this attempt was not sent, an earlier one was
                self._emit(
                    "http.attempt", op.name, ctx, outcome=failure.code.value, attempt=attempt
                )
                if failure.code in (ErrorCode.TIMEOUT, ErrorCode.UPSTREAM_UNAVAILABLE) and (
                    attempt < attempts
                ):
                    delay = self._backoff(retry.backoff_base, retry.backoff_max, attempt)
                    if loop.time() + delay >= deadline:
                        raise
                    await self._sleep(delay)
                    continue
                raise
            self._emit(
                "http.attempt",
                op.name,
                ctx,
                outcome="ok",
                attempt=attempt,
                http_status=response.status,
            )
            if response.status in retry.retry_statuses and attempt < attempts:
                if response.status != 429:  # a 5xx does not prove nothing was applied
                    maybe_sent = True
                retry_after = _retry_after(response)
                if retry_after is not None and retry_after > retry.max_retry_after:
                    return response
                delay = (
                    retry_after
                    if retry_after is not None
                    else self._backoff(retry.backoff_base, retry.backoff_max, attempt)
                )
                if loop.time() + delay >= deadline:
                    return response  # no time left to wait and retry
                await self._sleep(delay)
                continue
            return response
        raise AssertionError("unreachable")  # pragma: no cover

    def _backoff(self, base: float, cap: float, attempt: int) -> float:
        return self._rng.uniform(0, min(cap, base * (2 ** (attempt - 1))))

    async def _send_following_redirects(
        self, op: Operation, request: HttpRequest, credential_header: str | None
    ) -> HttpResponse:
        policy = op.service.network
        transport = self._get_transport()
        current = request
        hops = 0
        while True:
            try:
                response = await transport.send(current)
            except ToolFailure as failure:
                if hops > 0:  # an earlier hop already delivered the request
                    failure.request_sent = None
                raise
            if response.status not in _REDIRECTS or "location" not in response.headers:
                return response
            if not policy.follow_redirects:
                return response
            hops += 1
            if hops > policy.max_redirects:
                raise ToolFailure(
                    ErrorCode.UPSTREAM_ERROR, "too many redirects", http_status=response.status
                )
            target = urljoin(current.url, response.headers["location"])
            try:
                check_url(target, policy)
            except ToolFailure as failure:
                failure.request_sent = None  # the first hop was delivered
                raise
            headers = list(current.headers)
            if not same_origin(current.url, target):
                drop = {"authorization", "cookie"}
                if credential_header:
                    drop.add(credential_header.lower())
                # Query-string API keys are not copied either: Location is used verbatim.
                headers = [(k, v) for k, v in headers if k.lower() not in drop]
            method, body = current.method, current.body
            if response.status == 303 or (response.status in (301, 302) and method == "POST"):
                method, body = "GET", None
                headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
            current = replace(current, url=target, headers=tuple(headers), method=method, body=body)

    def _upstream_failure(
        self,
        reg: _Registered,
        response: HttpResponse,
        secrets: Sequence[str],
        *,
        write: bool = False,
    ) -> ToolFailure:
        status = response.status
        details: dict[str, object] = {"http_status": status}
        try:
            body = json.loads(response.body) if response.body else None
        except (ValueError, UnicodeDecodeError):
            body = None
        shaped = shape_error_body(reg.output, body, secrets=secrets)
        if shaped:
            details["upstream"] = shaped
        if status == 429:
            return ToolFailure(
                ErrorCode.RATE_LIMITED,
                "upstream rate limit reached (HTTP 429)",
                http_status=status,
                details=details,
                retry_after=_retry_after(response),
            )
        if status in (401, 403):
            message = f"upstream refused the request (HTTP {status})"
        elif status == 404:
            message = "upstream resource not found (HTTP 404)"
        elif status >= 500:
            if write:
                # A server error after a write does not prove nothing changed.
                return ToolFailure(
                    ErrorCode.UPSTREAM_ERROR,
                    f"upstream service error (HTTP {status}); the change may or may not have "
                    "been applied. Check the current state before trying again.",
                    retryable=False,
                    http_status=status,
                    details=details,
                )
            return ToolFailure(
                ErrorCode.UPSTREAM_ERROR,
                f"upstream service error (HTTP {status})",
                retryable=True,
                http_status=status,
                details=details,
            )
        else:
            message = f"upstream rejected the request (HTTP {status})"
        return ToolFailure(
            ErrorCode.UPSTREAM_ERROR, message, retryable=False, http_status=status, details=details
        )

    # ------------------------------------------------------------------ events

    def _emit(self, name: str, tool: str, ctx: ExecutionContext, **fields: Any) -> None:
        try:
            self._observer.on_event(
                Event(
                    name=name,
                    tool=tool,
                    actor=ctx.actor,
                    request_id=ctx.request_id,
                    tenant=ctx.tenant,
                    **fields,
                )
            )
        except Exception:
            logger.exception("observer failed")


# ---------------------------------------------------------------------- helpers


def _fingerprint_source(spec: Tool, schema: Mapping[str, Any]) -> dict[str, Any]:
    source: dict[str, Any] = {
        "name": spec.name,
        "effect": spec.effect.value,
        "schema": schema,
        "bind": sorted(spec.bind),
        "scopes": sorted(spec.required_scopes),
    }
    if isinstance(spec, Operation):
        source.update(
            kind="rest",
            method=spec.method,
            path=spec.path,
            base_url=spec.service.base_url,
            service=spec.service.name,
            query=spec.query,
            body=spec.body,
        )
    else:
        source.update(kind="python", handler=getattr(spec.handler, "__qualname__", "?"))
    return source


def _placement(op: Operation, remaining: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    names = list(remaining)
    if op.query is not None and op.body is not None:
        return list(op.query), list(op.body)
    body_method = op.method in ("POST", "PUT", "PATCH")
    if op.query is not None:
        rest = [n for n in names if n not in op.query]
        return list(op.query), rest if body_method else []
    if op.body is not None:
        rest = [n for n in names if n not in op.body]
        return rest, list(op.body)
    return ([], names) if body_method else (names, [])


def _random_key() -> str:
    return secrets.token_hex(16)


def _retry_after(response: HttpResponse) -> float | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(value)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError):
        return None


def _decode_body(response: HttpResponse, accept_text: bool) -> Any:
    if response.status in (204, 205) or not response.body:
        return None
    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if _JSON_TYPE.match(content_type) or (not content_type and response.body[:1] in (b"{", b"[")):
        try:
            return json.loads(response.body)
        except (ValueError, UnicodeDecodeError):
            raise ToolFailure(
                ErrorCode.UPSTREAM_SCHEMA_MISMATCH,
                "upstream returned malformed JSON",
                retryable=False,
            ) from None
    if accept_text and content_type.startswith("text/"):
        charset = "utf-8"
        for part in response.headers.get("content-type", "").split(";")[1:]:
            key, _, val = part.strip().partition("=")
            if key.lower() == "charset" and val:
                charset = val.strip('"')
        try:
            return response.body.decode(charset, errors="replace")
        except LookupError:
            return response.body.decode("utf-8", errors="replace")
    raise ToolFailure(
        ErrorCode.UNSUPPORTED_CONTENT_TYPE,
        f"upstream returned unsupported content type {content_type or 'unknown'!r}",
        retryable=False,
    )


_LINK_NEXT = re.compile(r'<([^>]+)>\s*;[^,]*rel="?next"?', re.IGNORECASE)


def _next_upstream(
    op: Operation,
    response: HttpResponse,
    decoded: Any,
    reg: _Registered,
    page_number: int | None,
    shaped: ShapeResult,
) -> Any:
    pagination = op.pagination
    assert pagination is not None
    if pagination.type == "cursor":
        value = parse_path(str(pagination.next_path)).get(decoded)
        if value is MISSING or value in (None, "", False):
            return None
        if not isinstance(value, str | int) or len(str(value)) > 2048:
            return None
        return value
    if pagination.type == "link":
        match = _LINK_NEXT.search(response.headers.get("link", ""))
        if not match:
            return None
        target = urljoin(response.url, match.group(1))
        try:
            check_url(target, op.service.network)
        except NetworkBlocked:
            return None
        if (
            not same_origin(target, response.url)
            or urlsplit(target).path != urlsplit(response.url).path
        ):
            return None
        if isinstance(op.service.auth, ApiKeyAuth) and op.service.auth.query:
            # never store a credential inside a cursor
            parts = urlsplit(target)
            from urllib.parse import parse_qsl

            kept = [(k, v) for k, v in parse_qsl(parts.query) if k != op.service.auth.query]
            target = parts._replace(query=urlencode(kept)).geturl()
        return target
    count = shaped.total_items
    if count is None or count == 0 or page_number is None:
        return None
    if pagination.page_size is not None and count < pagination.page_size:
        return None
    return page_number + 1
