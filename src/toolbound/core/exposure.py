"""Model-visible tool definitions, independent of any provider format."""

from __future__ import annotations

import copy
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

Strategy = Literal["direct", "grouped"]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Name, description and JSON Schema: everything a model is allowed to see."""

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": copy.deepcopy(self.input_schema),
        }


def _summarize(schema: dict[str, Any]) -> str:
    """Compact one-line argument summary, e.g. ``id: string*, limit: integer 1..100``."""
    required = set(schema.get("required", []))
    parts = []
    for name, prop in schema.get("properties", {}).items():
        if not isinstance(prop, dict):
            continue
        if "enum" in prop:
            kind = "|".join(str(v) for v in prop["enum"])
        elif "const" in prop:
            kind = f"={prop['const']}"
        else:
            kind = str(prop.get("type", "any"))
            if "minimum" in prop or "maximum" in prop:
                kind += f" {prop.get('minimum', '')}..{prop.get('maximum', '')}"
        parts.append(f"{name}: {kind}{'*' if name in required else ''}")
    return ", ".join(parts) or "none"


def group_definitions(group: str, members: Sequence[ToolDefinition]) -> ToolDefinition:
    """Combine several tools into one compact, ``action``-dispatched definition.

    The model-facing schema for ``arguments`` is a plain object; each action's
    arguments are summarized in the description (``*`` marks required). The full
    per-action schema is still enforced by the gateway after dispatch.
    """
    lines = [f"Actions on {group}. Set `action`; put its arguments in `arguments` (* = required)."]
    for d in members:
        lines.append(f"- {d.name}: {d.description.strip()} Args: {_summarize(d.input_schema)}")
    description = "\n".join(lines)
    schema = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": [d.name for d in members]},
            "arguments": {"type": "object"},
        },
        "required": ["action", "arguments"],
        "additionalProperties": False,
    }
    return ToolDefinition(group, description, schema)
