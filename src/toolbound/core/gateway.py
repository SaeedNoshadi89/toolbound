"""The Gateway: one execution pipeline for every tool.

REST operations and Python tools pass through the same steps::

    resolve tool (visibility) -> validate arguments -> resolve trusted bindings
    -> open cursor -> required scopes -> authorize() -> rate limit
    -> approval (if required) -> replay check -> execute -> shape output -> result
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import random
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path as FsPath
from typing import Any, TypeVar
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
from .errors import ConfigurationError, ErrorCode, NetworkBlocked, ToolFailure
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
from .state import MemoryStateStore

logger = logging.getLogger("toolbound")

_CURSOR_PREFIX = "tbc1"
_USER_AGENT = "toolbound/0.1"
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
        self._estimator: TokenEstimator = estimator or ByteEstimator()
        self._observer: Observer = observer or NullObserver()
        self._state: StateStore = state or MemoryStateStore()
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
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._rate = RateLimiter()

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
        effect: Effect | str = Effect.READ,
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
                effect=Effect(effect),
                output=output or Output(),
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

    def grant(self, pending: PendingApproval, *, approved_by: str) -> str:
        """Issue a single-use approval token for ``pending`` (host code only)."""
        return self._approvals.grant(pending, approved_by=approved_by)

    async def resume(
        self,
        pending: PendingApproval,
        *,
        ctx: ExecutionContext,
        approved_by: str,
        call_id: str | None = None,
    ) -> ToolResult:
        """Approve ``pending`` and execute it in one step (host code only)."""
        token = self.grant(pending, approved_by=approved_by)
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
        if action not in self._groups[name]:
            visible = [n for n in self._groups[name] if self._visible(self._tools[n].spec, ctx)]
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
        cursor_state = self._open_cursor(cursor_token, reg, ctx, args) if cursor_token else None

        missing_scopes = set(spec.required_scopes) - ctx.scopes
        if missing_scopes:
            raise ToolFailure(ErrorCode.FORBIDDEN, "missing required permission for this tool")
        decision = await self._authorize(AuthorizationRequest(ctx, spec, dict(args), dict(bound)))
        if not decision.allowed:
            raise ToolFailure(ErrorCode.FORBIDDEN, decision.reason or "not permitted")
        if spec.rate_limit is not None:
            self._rate.check(spec.name, spec.rate_limit, ctx)

        approval_id: str | None = None
        if spec.needs_approval:
            approval_id = await self._ensure_approval(reg, ctx, args, bound, approval)

        if call_id is not None and spec.effect is not Effect.READ:
            key = f"call:{canonical_digest([ctx.actor, ctx.tenant, spec.name, str(call_id)])}"
            if not await self._state.claim(key, self._call_id_ttl):
                raise ToolFailure(
                    ErrorCode.DUPLICATE_CALL,
                    "this tool call was already executed; it will not run twice",
                )

        idempotency_key = approval_id or (
            canonical_digest([ctx.actor, spec.name, str(call_id)])[:32] if call_id else None
        )
        if isinstance(spec, Operation):
            shaped, meta_source, next_upstream, status = await self._execute_rest(
                reg, spec, ctx, args, bound, cursor_state, fields, idempotency_key
            )
            http_status.append(status)
        else:
            shaped = await self._execute_python(reg, spec, ctx, args, bound, cursor_state, fields)
            meta_source, next_upstream, status = {"tool": spec.name}, None, None

        next_cursor = None
        if reg.has_cursor:
            current_upstream = cursor_state.get("u") if cursor_state else None
            if shaped.next_offset is not None:
                next_cursor = self._issue_cursor(
                    reg, ctx, args, current_upstream, shaped.next_offset
                )
            elif next_upstream is not None:
                next_cursor = self._issue_cursor(reg, ctx, args, next_upstream, 0)

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
    ) -> str:
        spec = reg.spec
        if token is not None:
            payload = await self._approvals.consume(
                token,
                ctx=ctx,
                tool=spec.name,
                fingerprint=reg.fingerprint,
                arguments=args,
                bound=bound,
            )
            self._emit(
                "approval.granted",
                spec.name,
                ctx,
                outcome="ok",
                attributes={"approved_by": payload.get("by")},
            )
            return str(payload["i"])
        pending = self._approvals.create(
            ctx=ctx,
            tool=spec.name,
            effect=spec.effect,
            fingerprint=reg.fingerprint,
            arguments=args,
            bound=bound,
        )
        if self._approver is None:
            raise _ApprovalNeeded(pending)
        decision = self._approver(pending)
        if inspect.isawaitable(decision):
            decision = await decision
        if decision is not True:
            raise ToolFailure(ErrorCode.APPROVAL_DENIED, "the user did not approve this action")
        grant = self._approvals.grant(pending, approved_by="inline-approver")
        await self._approvals.consume(
            grant,
            ctx=ctx,
            tool=spec.name,
            fingerprint=reg.fingerprint,
            arguments=args,
            bound=bound,
        )
        self._emit("approval.granted", spec.name, ctx, outcome="ok")
        return pending.id

    # ------------------------------------------------------------------ cursors

    def _cursor_binding(
        self, reg: _Registered, ctx: ExecutionContext, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "t": reg.spec.name,
            "f": reg.fingerprint[:16],
            "a": canonical_digest([ctx.actor, ctx.tenant])[:16],
            "h": canonical_digest(dict(args))[:16],
        }

    def _issue_cursor(
        self,
        reg: _Registered,
        ctx: ExecutionContext,
        args: Mapping[str, Any],
        upstream: Any,
        offset: int,
    ) -> str:
        payload = {**self._cursor_binding(reg, ctx, args), "u": upstream, "o": offset}
        return self._signer.sign(_CURSOR_PREFIX, payload, self._cursor_ttl)

    def _open_cursor(
        self, token: Any, reg: _Registered, ctx: ExecutionContext, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload = self._signer.verify(_CURSOR_PREFIX, token)
        if payload is None:
            raise ToolFailure(ErrorCode.INVALID_CURSOR, "cursor is invalid or has expired")
        expected = self._cursor_binding(reg, ctx, args)
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
                    value = await asyncio.to_thread(spec.handler, **kwargs)
                    if inspect.isawaitable(value):
                        value = await value
        except TimeoutError:
            raise ToolFailure(
                ErrorCode.TIMEOUT, f"tool timed out after {spec.timeout:g}s"
            ) from None
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            raise ToolFailure(
                ErrorCode.INTERNAL_ERROR, "the tool returned a value that is not JSON-serializable"
            ) from None
        offset = int(cursor_state["o"]) if cursor_state else 0
        return process(reg.output, value, estimator=self._estimator, offset=offset, selected=fields)

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
        response = await self._send(op, request, ctx, credential_header)
        source = {"service": svc.name, "operation": op.name, "status": response.status}
        request_id = next(
            (response.headers[h] for h in _REQUEST_ID_HEADERS if h in response.headers), None
        )
        if request_id and _SAFE_ID.match(request_id):
            source["request_id"] = request_id

        if response.status >= 400:
            raise self._upstream_failure(reg, response, secrets)
        if 300 <= response.status < 400:
            raise ToolFailure(
                ErrorCode.UPSTREAM_ERROR,
                f"upstream redirected (HTTP {response.status}) and redirects are disabled",
                http_status=response.status,
            )
        decoded = _decode_body(response, reg.output.spec.accept_text)
        offset = int(cursor_state["o"]) if cursor_state else 0
        shaped = process(
            reg.output,
            decoded,
            estimator=self._estimator,
            offset=offset,
            selected=fields,
            secrets=secrets,
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
        retry_allowed = op.method in SAFE_METHODS or op.idempotency_header is not None
        attempts = retry.max_attempts if retry_allowed else 1
        semaphore = self._semaphores.get(svc.name)
        if semaphore is None:
            semaphore = self._semaphores[svc.name] = asyncio.Semaphore(svc.limits.max_concurrency)
        async with semaphore:
            for attempt in range(1, attempts + 1):
                try:
                    response = await self._send_following_redirects(op, request, credential_header)
                except ToolFailure as failure:
                    self._emit(
                        "http.attempt", op.name, ctx, outcome=failure.code.value, attempt=attempt
                    )
                    if failure.code in (ErrorCode.TIMEOUT, ErrorCode.UPSTREAM_UNAVAILABLE) and (
                        attempt < attempts
                    ):
                        await self._sleep(
                            self._backoff(retry.backoff_base, retry.backoff_max, attempt)
                        )
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
                    retry_after = _retry_after(response)
                    if retry_after is not None and retry_after > retry.max_retry_after:
                        return response
                    delay = (
                        retry_after
                        if retry_after is not None
                        else self._backoff(retry.backoff_base, retry.backoff_max, attempt)
                    )
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
            response = await transport.send(current)
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
            check_url(target, policy)
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
        self, reg: _Registered, response: HttpResponse, secrets: Sequence[str]
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
