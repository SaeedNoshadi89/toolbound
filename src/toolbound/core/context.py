"""Trusted execution context.

The :class:`ExecutionContext` is created by **your application** after it has
authenticated the end user. It is never built from model output. Everything
security-relevant (who is acting, for which tenant, with which scopes) comes from
here, not from tool arguments.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


def _new_request_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Identity and environment for one agent turn, supplied by trusted code.

    Args:
        actor: Stable identifier of the authenticated user or service account.
        tenant: Optional tenant / organization identifier for multi-tenant apps.
        scopes: Permissions granted to the actor (checked against
            ``Tool.required_scopes``).
        attributes: Extra trusted values that contracts may bind into requests
            (for example ``{"repo_owner": "acme"}``). Never put secrets here;
            use a :class:`~toolbound.CredentialProvider` instead.
        request_id: Correlation id for logs and approvals. Generated if omitted.
    """

    actor: str
    tenant: str | None = None
    scopes: frozenset[str] = frozenset()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=_new_request_id)

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str) or not self.actor:
            raise ValueError("ExecutionContext.actor must be a non-empty string")
        object.__setattr__(self, "scopes", frozenset(self.scopes))
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    def __repr__(self) -> str:
        # Attribute values are deliberately not printed: they may be sensitive.
        keys = ", ".join(sorted(self.attributes))
        return (
            f"ExecutionContext(actor={self.actor!r}, tenant={self.tenant!r}, "
            f"scopes={sorted(self.scopes)!r}, attributes=[{keys}], "
            f"request_id={self.request_id!r})"
        )
