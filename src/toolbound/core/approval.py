"""Human approval bound to one exact call.

An approval grant is an HMAC-signed token that commits to a digest of:

* the tool name and its contract fingerprint (a changed contract invalidates it),
* the authenticated actor and tenant from the trusted context,
* the validated, model-supplied arguments, and
* the trusted bound values.

Grants expire, can be used **once** (enforced through the
:class:`~toolbound.core.ports.StateStore`), and are passed to
:meth:`Gateway.call` as a keyword argument by host code, never through tool
arguments, so a model cannot approve its own actions.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .context import ExecutionContext
from .contracts import Effect
from .errors import ErrorCode, ToolFailure
from .ports import StateStore
from .signing import Signer, canonical_digest

_PREFIX = "tba1"


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """A call waiting for a human decision. Show ``summary`` in your approval UI."""

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "effect": self.effect.value,
            "actor": self.actor,
            "tenant": self.tenant,
            "arguments": dict(self.arguments),
            "summary": self.summary,
            "expires_at": self.expires_at,
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


class ApprovalManager:
    """Creates pending approvals, issues grants, and verifies them exactly once."""

    def __init__(self, signer: Signer, store: StateStore, *, ttl_seconds: float = 600) -> None:
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
    ) -> PendingApproval:
        digest = approval_digest(
            tool=tool, fingerprint=fingerprint, ctx=ctx, arguments=arguments, bound=bound
        )
        rendered = json.dumps(dict(arguments), ensure_ascii=False, sort_keys=True, default=str)
        if len(rendered) > 500:
            rendered = rendered[:499] + "…"
        return PendingApproval(
            id=secrets.token_urlsafe(16),
            tool=tool,
            effect=effect,
            actor=ctx.actor,
            tenant=ctx.tenant,
            arguments=dict(arguments),
            bound=dict(bound),
            summary=f"{tool}({rendered}) [{effect.value}] for actor {ctx.actor}",
            digest=digest,
            expires_at=time.time() + self.ttl_seconds,
        )

    def grant(self, pending: PendingApproval, *, approved_by: str) -> str:
        """Issue a single-use grant token for ``pending``. Call from host code only."""
        if not approved_by:
            raise ValueError("approved_by is required for the audit trail")
        remaining = pending.expires_at - time.time()
        if remaining <= 0:
            raise ToolFailure(ErrorCode.APPROVAL_INVALID, "approval request has expired")
        return self._signer.sign(
            _PREFIX, {"i": pending.id, "d": pending.digest, "by": approved_by}, remaining
        )

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
        payload = self._signer.verify(_PREFIX, token)
        if payload is None:
            raise ToolFailure(ErrorCode.APPROVAL_INVALID, "approval is invalid or has expired")
        expected = approval_digest(
            tool=tool, fingerprint=fingerprint, ctx=ctx, arguments=arguments, bound=bound
        )
        if payload.get("d") != expected:
            raise ToolFailure(
                ErrorCode.APPROVAL_INVALID,
                "approval does not match this call (tool, arguments, actor or tenant changed)",
            )
        if not await self._store.claim(f"approval:{payload['i']}", self.ttl_seconds + 60):
            raise ToolFailure(ErrorCode.APPROVAL_INVALID, "approval has already been used")
        return payload
