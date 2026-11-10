"""HTTP transports (outbound adapters).

``SecureTransport`` (httpx-based) is imported lazily so that the core and the
mock transport can be used without httpx.
"""

from typing import Any

from .mock import MockResponse, MockTransport

__all__ = ["MockResponse", "MockTransport", "Resolver", "SecureTransport", "SystemResolver"]


def __getattr__(name: str) -> Any:
    if name in ("SecureTransport", "SystemResolver", "Resolver"):
        from . import http

        return getattr(http, name)
    raise AttributeError(name)
