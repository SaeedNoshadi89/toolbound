"""Human approval bound to one exact call.

Flow:

1. A call that needs approval returns ``approval_required`` with a
   :class:`PendingApproval`. Its :attr:`~PendingApproval.token` is an
   **encrypted, authenticated approval request** issued by the gateway. It
   carries the tool, the validated arguments and a digest of the trusted bound
   values, actor and tenant. Store or round-trip the token freely (database,
   browser, LangGraph interrupt): it cannot be altered or forged, and its
   contents cannot be read without the gateway secret.
2. Host code shows the request to a human (:meth:`Gateway.pending_approval`
   rebuilds the display data from a token) and, on approval, calls
   :meth:`Gateway.grant` or :meth:`Gateway.resume` **with the token**. The
   fields of a ``PendingApproval`` object are never trusted, only its token.
3. The grant is an HMAC-signed, single-use token committing to the request id
   and digest. :meth:`Gateway.call` verifies it, recomputes the digest from the
   live call and the live :class:`ExecutionContext`, and claims the request id
   in the :class:`~toolbound.core.ports.StateStore` so it runs at most once.

Grants are passed to :meth:`Gateway.call` as a keyword argument by host code,
never through tool arguments, so a model cannot approve its own actions.
"""

from __future__ import annotations

import json
import secrets
import time
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .context import ExecutionContext
from .contracts import Effect
from .errors import ApprovalInvalid
from .ports import StateStore
from .signing import Signer, canonical_digest
from .state import claim_or_fail

_GRANT_PREFIX = "tba2"
_REQUEST_PREFIX = "tbr1"
_MAX_REQUEST_TOKEN = 512 * 1024
_SUMMARY_LIMIT = 2000


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """A call waiting for a human decision.

    Show the human :attr:`arguments`, :attr:`bound` and :attr:`target` (or at
    least :attr:`summary`, checking :attr:`summary_truncated`). Persist or send
    :attr:`token`; :meth:`to_dict` is JSON-safe and includes it.
    """

    id: str
    tool: str
    effect: Effect
    actor: str
    tenant: str | None
    arguments: Mapping[str, Any]
    bound: Mapping[str, Any]
    summary: str
    digest: str
    expires_at: float
    token: str = ""
    target: Mapping[str, Any] = field(default_factory=dict)
    summary_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "effect": self.effect.value,
            "actor": self.actor,
            "tenant": self.tenant,
            "target": dict(self.target),
            "arguments": dict(self.arguments),
            "bound": dict(self.bound),
            "summary": self.summary,
            "summary_truncated": self.summary_truncated,
            "expires_at": self.expires_at,
            "token": self.token,
        }


def approval_digest(
    *,
    tool: str,
    fingerprint: str,
    ctx: ExecutionContext,
    arguments: Mapping[str, Any],
    bound: Mapping[str, Any],
) -> str:
    return canonical_digest(
        {
            "tool": tool,
            "contract": fingerprint,
            "actor": ctx.actor,
            "tenant": ctx.tenant,
            "arguments": dict(arguments),
            "bound": dict(bound),
        }
    )


def _display(value: Any) -> str:
    """JSON for humans: control, format and bidi characters are escaped."""
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return "".join(
        f"\\u{ord(c):04x}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c
        for c in text
    )


def _summary(
    tool: str,
    effect: Effect,
    target: Mapping[str, Any],
    ctx: ExecutionContext,
    arguments: Mapping[str, Any],
    bound: Mapping[str, Any],
) -> tuple[str, bool]:
    if target.get("kind") == "rest":
        where = f"{target.get('method')} {target.get('url')}"
    else:
        where = f"Python tool {tool}"
    who = f"actor {_display(ctx.actor)}" + (
        f", tenant {_display(ctx.tenant)}" if ctx.tenant is not None else ""
    )
    text = (
        f"[{effect.value.upper()}] {where} (tool {tool}) for {who}. "
        f"Arguments: {_display(dict(arguments))}. Trusted values: {_display(dict(bound))}."
    )
    if len(text) <= _SUMMARY_LIMIT:
        return text, False
    hidden = len(text) - _SUMMARY_LIMIT
    return (
        text[:_SUMMARY_LIMIT]
        + f" … [{hidden} more characters not shown: review the full arguments before approving]",
        True,
    )


class ApprovalManager:
    """Issues approval requests and grants, and verifies grants exactly once."""

    def __init__(self, signer: Signer, store: StateStore, *, ttl_seconds: float = 600) -> None:
        if not 0 < ttl_seconds <= MAX_APPROVAL_TTL:
            raise ValueError(f"approval_ttl must be between 0 and {MAX_APPROVAL_TTL} seconds")
        self._signer = signer
        self._store = store
        self.ttl_seconds = ttl_seconds

    def create(
        self,
        *,
        ctx: ExecutionContext,
        tool: str,
        effect: Effect,
        fingerprint: str,
        arguments: Mapping[str, Any],
        bound: Mapping[str, Any],
        target: Mapping[str, Any] | None = None,
    ) -> PendingApproval:
        digest = approval_digest(
            tool=tool, fingerprint=fingerprint, ctx=ctx, arguments=arguments, bound=bound
        )
        request_id = secrets.token_urlsafe(16)
        expires_at = time.time() + self.ttl_seconds
        target_map = dict(target or {})
        summary, truncated = _summary(tool, effect, target_map, ctx, arguments, bound)
        token = self._signer.seal(
            _REQUEST_PREFIX,
            {
                "i": request_id,
                "d": digest,
                "t": tool,
                "e": effect.value,
                "a": dict(arguments),
                "b": dict(bound),
                "u": ctx.actor,
                "n": ctx.tenant,
                "g": target_map,
                "x": expires_at,
            },
            self.ttl_seconds,
        )
        return PendingApproval(
            id=request_id,
            tool=tool,
            effect=effect,
            actor=ctx.actor,
            tenant=ctx.tenant,
            arguments=dict(arguments),
            bound=dict(bound),
            summary=summary,
            digest=digest,
            expires_at=expires_at,
            token=token,
            target=target_map,
            summary_truncated=truncated,
        )

    def open(self, request: PendingApproval | str) -> PendingApproval:
        """Rebuild a :class:`PendingApproval` from its token. Raises :class:`ApprovalInvalid`."""
        token = request.token if isinstance(request, PendingApproval) else request
        payload = self._signer.unseal(_REQUEST_PREFIX, token, max_length=_MAX_REQUEST_TOKEN)
        if payload is None:
            raise ApprovalInvalid("approval request is invalid, forged or expired")
        try:
            effect = Effect(payload["e"])
            arguments = dict(payload["a"])
            bound = dict(payload["b"])
            target = dict(payload["g"])
            tool, actor, tenant = str(payload["t"]), str(payload["u"]), payload["n"]
            request_id, digest = str(payload["i"]), str(payload["d"])
            expires_at = float(payload["x"])
        except (KeyError, TypeError, ValueError):
            raise ApprovalInvalid("approval request is malformed") from None
        ctx = ExecutionContext(actor=actor, tenant=tenant)
        summary, truncated = _summary(tool, effect, target, ctx, arguments, bound)
        return PendingApproval(
            id=request_id,
            tool=tool,
            effect=effect,
            actor=actor,
            tenant=tenant,
            arguments=arguments,
            bound=bound,
            summary=summary,
            digest=digest,
            expires_at=expires_at,
            token=str(token),
            target=target,
            summary_truncated=truncated,
        )

    def grant(self, request: PendingApproval | str, *, approved_by: str) -> str:
        """Issue a single-use grant for a gateway-issued request. Host code only."""
        if not approved_by or not isinstance(approved_by, str):
            raise ValueError("approved_by is required for the audit trail")
        pending = self.open(request)  # verifies the token; object fields are ignored
        remaining = pending.expires_at - time.time()
        if remaining <= 0:
            raise ApprovalInvalid("approval request has expired")
        return self._signer.sign(
            _GRANT_PREFIX, {"i": pending.id, "d": pending.digest, "by": approved_by}, remaining
        )

    def verify(
        self,
        token: str,
        *,
        ctx: ExecutionContext,
        tool: str,
        fingerprint: str,
        arguments: Mapping[str, Any],
        bound: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Check a grant against the live call without using it up."""
        payload = self._signer.verify(_GRANT_PREFIX, token)
        if payload is None:
            raise ApprovalInvalid("approval is invalid or has expired")
        expected = approval_digest(
            tool=tool, fingerprint=fingerprint, ctx=ctx, arguments=arguments, bound=bound
        )
        if payload.get("d") != expected:
            raise ApprovalInvalid(
                "approval does not match this call (tool, arguments, actor, tenant or "
                "trusted values changed)"
            )
        return payload

    async def claim(self, payload: Mapping[str, Any], ctx: ExecutionContext) -> None:
        """Use a verified grant (once). Called immediately before execution."""
        if not await claim_or_fail(self._store, _claim_key(ctx, str(payload["i"])), _CLAIM_TTL):
            raise ApprovalInvalid("approval has already been used or was rejected")

    async def deny(self, request: PendingApproval | str) -> PendingApproval:
        """Record a refusal: the request can never be granted afterwards."""
        pending = self.open(request)
        ctx = ExecutionContext(actor=pending.actor, tenant=pending.tenant)
        await claim_or_fail(self._store, _claim_key(ctx, pending.id), _CLAIM_TTL)
        return pending

    async def consume(
        self,
        token: str,
        *,
        ctx: ExecutionContext,
        tool: str,
        fingerprint: str,
        arguments: Mapping[str, Any],
        bound: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify and claim in one step."""
        payload = self.verify(
            token, ctx=ctx, tool=tool, fingerprint=fingerprint, arguments=arguments, bound=bound
        )
        await self.claim(payload, ctx)
        return payload


#: Claims must outlive any grant. Grants never live longer than the request TTL, which
#: is capped at ``MAX_APPROVAL_TTL``, so a fixed claim TTL is safe even when workers
#: are configured with different ``approval_ttl`` values.
MAX_APPROVAL_TTL = 7 * 24 * 3600
_CLAIM_TTL = MAX_APPROVAL_TTL + 3600


def _claim_key(ctx: ExecutionContext, request_id: str) -> str:
    return f"approval:{canonical_digest([ctx.actor, ctx.tenant])[:16]}:{request_id}"
