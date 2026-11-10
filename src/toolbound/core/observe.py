"""Structured events for logging, metrics and tracing.

Events carry identifiers, timings and outcomes only. Argument values, request
bodies, response bodies and credentials are never included.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("toolbound")


@dataclass(frozen=True, slots=True)
class Event:
    """One observable step.

    ``name`` is one of ``call.start``, ``call.end``, ``http.attempt``,
    ``approval.required``, ``approval.granted``, ``policy.denied``,
    ``network.blocked``, ``schema.warning``.
    """

    name: str
    tool: str
    actor: str
    request_id: str
    tenant: str | None = None
    outcome: str | None = None
    duration_ms: float | None = None
    http_status: int | None = None
    attempt: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


class NullObserver:
    def on_event(self, event: Event) -> None:
        return None


class LoggingObserver:
    """Logs events to the ``toolbound`` logger at INFO (failures at WARNING)."""

    def __init__(self, log: logging.Logger | None = None) -> None:
        self._log = log or logger

    def on_event(self, event: Event) -> None:
        level = logging.WARNING if event.outcome not in (None, "ok") else logging.INFO
        self._log.log(
            level,
            "%s tool=%s actor=%s outcome=%s status=%s duration_ms=%s request_id=%s",
            event.name,
            event.tool,
            event.actor,
            event.outcome,
            event.http_status,
            None if event.duration_ms is None else round(event.duration_ms, 2),
            event.request_id,
        )
