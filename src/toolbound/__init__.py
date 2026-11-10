"""Toolbound: contract-first, secure-by-default tools for AI agents."""

from toolbound.core.approval import PendingApproval
from toolbound.core.budget import ByteEstimator
from toolbound.core.context import ExecutionContext
from toolbound.core.contracts import (
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    Const,
    Effect,
    Field,
    FromContext,
    Limits,
    NetworkPolicy,
    NoAuth,
    Operation,
    Output,
    Pagination,
    PythonTool,
    RateLimit,
    RetryPolicy,
    Service,
    Tool,
    ToolSpec,
    from_ctx,
)
from toolbound.core.credentials import EnvCredentials, StaticCredentials
from toolbound.core.errors import (
    ApprovalInvalid,
    ConfigurationError,
    ErrorCode,
    NetworkBlocked,
    StateStoreError,
    ToolboundError,
    ToolboundWarning,
    ToolFailure,
)
from toolbound.core.exposure import ToolDefinition
from toolbound.core.gateway import Gateway, allow_all, deny_all
from toolbound.core.observe import Event, LoggingObserver
from toolbound.core.ports import (
    AuthorizationRequest,
    Decision,
    HttpRequest,
    HttpResponse,
    StateStore,
    TokenEstimator,
    Transport,
)
from toolbound.core.result import ResultMeta, ToolError, ToolResult
from toolbound.core.shaping import Omission
from toolbound.core.state import MemoryStateStore
from toolbound.transport.mock import MockResponse, MockTransport

__version__ = "0.2.0"


def __getattr__(name: str) -> object:
    if name == "SecureTransport":
        from toolbound.transport.http import SecureTransport

        return SecureTransport
    raise AttributeError(name)


__all__ = [
    "ApiKeyAuth",
    "ApprovalInvalid",
    "AuthorizationRequest",
    "BasicAuth",
    "BearerAuth",
    "ByteEstimator",
    "ConfigurationError",
    "Const",
    "Decision",
    "Effect",
    "EnvCredentials",
    "ErrorCode",
    "Event",
    "ExecutionContext",
    "Field",
    "FromContext",
    "Gateway",
    "HttpRequest",
    "HttpResponse",
    "Limits",
    "LoggingObserver",
    "MemoryStateStore",
    "MockResponse",
    "MockTransport",
    "NetworkBlocked",
    "NetworkPolicy",
    "NoAuth",
    "Omission",
    "Operation",
    "Output",
    "Pagination",
    "PendingApproval",
    "PythonTool",
    "RateLimit",
    "ResultMeta",
    "RetryPolicy",
    "SecureTransport",
    "Service",
    "StateStore",
    "StateStoreError",
    "StaticCredentials",
    "TokenEstimator",
    "Tool",
    "ToolDefinition",
    "ToolError",
    "ToolFailure",
    "ToolResult",
    "ToolSpec",
    "ToolboundError",
    "ToolboundWarning",
    "Transport",
    "__version__",
    "allow_all",
    "deny_all",
    "from_ctx",
]
