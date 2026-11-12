"""Error types.

Two kinds of failure exist in Toolbound:

* **Developer errors** (an invalid contract, a missing policy) raise
  :class:`ConfigurationError` at registration time, so mistakes surface while
  the application starts rather than in front of a model.
* **Runtime failures** (invalid arguments, denied authorization, a blocked
  network target, an upstream error) never raise from :meth:`Gateway.call`.
  They are returned as a :class:`~toolbound.ToolResult` with ``ok=False`` and an
  :class:`ErrorCode`, so the agent loop can hand a safe, structured error back
  to the model.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class ToolboundError(Exception):
    """Base class for every exception raised by Toolbound."""


class ToolboundWarning(UserWarning):
    """A risky but legal configuration (for example an ephemeral signing key).

    Turn these into errors in CI with ``-W error::toolbound.ToolboundWarning``.
    """


class StateStoreError(ToolboundError):
    """A :class:`~toolbound.StateStore` could not record a claim.

    Toolbound fails closed: the call is not executed.
    """


class ConfigurationError(ToolboundError):
    """A contract, tool, or gateway setting is invalid. Raised to the developer."""


class ErrorCode(StrEnum):
    """Stable, machine-readable codes for failed tool calls."""

    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    INVALID_CURSOR = "invalid_cursor"
    FORBIDDEN = "forbidden"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_INVALID = "approval_invalid"
    DUPLICATE_CALL = "duplicate_call"
    RATE_LIMITED = "rate_limited"
    NETWORK_BLOCKED = "network_blocked"
    TIMEOUT = "timeout"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_SCHEMA_MISMATCH = "upstream_schema_mismatch"
    UNSUPPORTED_CONTENT_TYPE = "unsupported_content_type"
    RESPONSE_TOO_LARGE = "response_too_large"
    RESULT_TOO_LARGE = "result_too_large"
    OUTCOME_UNKNOWN = "outcome_unknown"
    REFUSED = "refused"
    INTERNAL_ERROR = "internal_error"


#: Codes where repeating the same call later may succeed.
RETRYABLE_CODES = frozenset(
    {ErrorCode.RATE_LIMITED, ErrorCode.TIMEOUT, ErrorCode.UPSTREAM_UNAVAILABLE}
)


class ToolFailure(ToolboundError):
    """Internal signal used to stop the pipeline with a model-safe error.

    The ``message`` must never contain secrets, credentials, raw upstream bodies,
    or stack traces: it is shown to the model.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retryable: bool | None = None,
        http_status: int | None = None,
        details: dict[str, object] | None = None,
        retry_after: float | None = None,
        request_sent: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = code in RETRYABLE_CODES if retryable is None else retryable
        self.http_status = http_status
        self.details = details or {}
        self.retry_after = retry_after
        #: ``False`` when the request certainly never reached the upstream (DNS,
        #: connect, policy). ``None`` means it may have been sent.
        self.request_sent = request_sent


class NetworkBlocked(ToolFailure):
    """A request target violated the network policy."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.NETWORK_BLOCKED, message, retryable=False, request_sent=False)


class ApprovalInvalid(ToolFailure):
    """An approval request or grant is forged, expired, reused, or for another call.

    Raised by :meth:`Gateway.grant` (host code); :meth:`Gateway.call` returns it
    as an ``approval_invalid`` result instead.
    """

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.APPROVAL_INVALID, message, retryable=False)


_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESERVED_DETAILS = frozenset({"code", "message", "retryable", "retry_after_seconds", "reason"})
_MAX_DETAILS_BYTES = 2048


class ToolRefusal(ToolboundError):
    """Raised by a trusted Python tool to refuse a call for a business reason.

    The call fails with code ``refused`` and ``details["reason"]`` set to
    ``reason`` (for example ``"version_conflict"``), plus ``details``. Nothing is
    retried. For a write tool it means the handler did not apply the action, so the
    outcome is known (unlike ``outcome_unknown``). Any other exception from a
    handler is still ``internal_error``.

    ``message`` and ``details`` are shown to the model: never put secrets, personal
    data or raw upstream text in them.

    Args:
        reason: Stable machine-readable reason: lowercase letters, digits and
            ``_``, starting with a letter, at most 64 characters.
        message: Short, model-safe explanation.
        details: Optional JSON-serializable extra fields (at most 2 KiB); the keys
            ``code``, ``message``, ``retryable``, ``retry_after_seconds`` and
            ``reason`` are reserved.
    """

    def __init__(
        self, reason: str, message: str = "", *, details: Mapping[str, Any] | None = None
    ) -> None:
        if not isinstance(reason, str) or not _REASON.match(reason):
            raise ValueError(f"invalid refusal reason {reason!r}")
        extra = dict(details or {})
        reserved = _RESERVED_DETAILS & set(extra)
        if reserved:
            raise ValueError(f"refusal details use reserved key(s) {sorted(reserved)}")
        try:
            size = len(json.dumps(extra))
        except (TypeError, ValueError):
            raise ValueError("refusal details must be JSON-serializable") from None
        if size > _MAX_DETAILS_BYTES:
            raise ValueError(f"refusal details larger than {_MAX_DETAILS_BYTES} bytes")
        message = message or f"the tool refused this call ({reason})"
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details = extra
