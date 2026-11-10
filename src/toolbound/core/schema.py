"""Input schema normalization and validation (structural validation only).

Structural validation proves that arguments have the expected shape. It says
nothing about whether the caller may act (authorization) or whether data is
true (factual verification).
"""

from __future__ import annotations

import copy
import json
import warnings
from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from .errors import ConfigurationError, ErrorCode, ToolboundWarning, ToolFailure

_CHECKED_FORMATS = frozenset(FormatChecker().checkers)

_MAX_SCHEMA_DEPTH = 16
_MAX_SCHEMA_BYTES = 64 * 1024
_MAX_MESSAGE = 240

RESERVED_ARGUMENTS = frozenset({"fields", "cursor"})


def normalize_input_schema(tool_name: str, spec: Mapping[str, Any]) -> dict[str, Any]:
    """Turn a developer input spec into a closed, checked JSON Schema object.

    ``spec`` is either a full JSON Schema with ``"type": "object"`` or a
    shorthand mapping of property name to property schema. In shorthand, every
    property without a ``default`` is required.
    """
    raw: dict[str, Any] = copy.deepcopy(dict(spec))
    schema: dict[str, Any]
    if "type" in raw:
        if raw.get("type") != "object":
            raise ConfigurationError(f"tool {tool_name}: input schema must be type 'object'")
        schema = raw
        schema.setdefault("properties", {})
    else:
        required = [k for k, v in raw.items() if not (isinstance(v, Mapping) and "default" in v)]
        schema = {"type": "object", "properties": raw, "required": required}

    if schema.get("additionalProperties", False) is not False:
        raise ConfigurationError(
            f"tool {tool_name}: top-level additionalProperties must be false; unknown "
            "arguments are always rejected"
        )
    schema["additionalProperties"] = False
    _close_nested_objects(schema, depth=0, tool_name=tool_name)
    _reject_remote_refs(schema, tool_name)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ConfigurationError(f"tool {tool_name}: invalid input schema: {exc.message}") from exc
    if len(json.dumps(schema)) > _MAX_SCHEMA_BYTES:
        raise ConfigurationError(f"tool {tool_name}: input schema is too large")
    unchecked = sorted(_formats(schema) - _CHECKED_FORMATS)
    if unchecked:
        warnings.warn(
            f"tool {tool_name}: JSON Schema format(s) {unchecked} are not enforced in this "
            "environment (jsonschema needs optional packages for them). Use 'pattern', "
            "'enum' or limits for anything security-relevant.",
            ToolboundWarning,
            stacklevel=4,
        )
    return schema


def _formats(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        value = node.get("format")
        if isinstance(value, str):
            found.add(value)
        for child in node.values():
            found |= _formats(child)
    elif isinstance(node, list):
        for child in node:
            found |= _formats(child)
    return found


def _close_nested_objects(node: Any, *, depth: int, tool_name: str, where: str = "") -> None:
    """Close every nested object schema that lists ``properties``.

    Unknown keys are rejected unless the contract sets ``additionalProperties``
    explicitly. A schema counts as an object schema when it has ``properties``,
    whatever its ``type`` says (``["object", "null"]``, or no ``type`` at all). An
    object schema *without* ``properties`` and without an explicit
    ``additionalProperties`` accepts any keys; that is allowed but warned about.
    """
    if depth > _MAX_SCHEMA_DEPTH:
        raise ConfigurationError(f"tool {tool_name}: input schema nests too deeply")
    if isinstance(node, dict):
        if depth > 0 and _is_object_schema(node):
            if "properties" in node:
                node.setdefault("additionalProperties", False)
            elif "additionalProperties" not in node and "patternProperties" not in node:
                warnings.warn(
                    f"tool {tool_name}: object at {where or '$'} accepts any keys. Add "
                    "'properties' (unknown keys are then rejected) or set "
                    "'additionalProperties' explicitly.",
                    ToolboundWarning,
                    stacklevel=5,
                )
        for key, value in node.items():
            if key in ("properties", "$defs", "definitions", "patternProperties"):
                if isinstance(value, dict):
                    for name, sub in value.items():
                        _close_nested_objects(
                            sub, depth=depth + 1, tool_name=tool_name, where=f"{where}.{name}"
                        )
            elif isinstance(value, dict | list):
                _close_nested_objects(value, depth=depth + 1, tool_name=tool_name, where=where)
    elif isinstance(node, list):
        for item in node:
            _close_nested_objects(item, depth=depth + 1, tool_name=tool_name, where=where)


def _is_object_schema(node: dict[str, Any]) -> bool:
    kind = node.get("type")
    if "properties" in node:
        return True
    return kind == "object" or (isinstance(kind, list) and "object" in kind)


def _reject_remote_refs(node: Any, tool_name: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("$ref", "$dynamicRef") and not (
                isinstance(value, str) and value.startswith("#")
            ):
                raise ConfigurationError(f"tool {tool_name}: only local '#/...' $ref is allowed")
            if key == "$id":
                raise ConfigurationError(f"tool {tool_name}: $id is not allowed in input schemas")
            _reject_remote_refs(value, tool_name)
    elif isinstance(node, list):
        for item in node:
            _reject_remote_refs(item, tool_name)


class ArgumentValidator:
    """Compiled validator for one tool's arguments."""

    def __init__(self, schema: dict[str, Any], *, max_argument_bytes: int) -> None:
        self.schema = schema
        self._validator = Draft202012Validator(schema, format_checker=FormatChecker())
        self._defaults = {
            name: prop["default"]
            for name, prop in schema.get("properties", {}).items()
            if isinstance(prop, dict) and "default" in prop
        }
        self._max_bytes = max_argument_bytes

    def validate(self, arguments: Any) -> dict[str, Any]:
        """Return validated arguments (with top-level defaults) or raise ToolFailure."""
        if not isinstance(arguments, dict):
            raise ToolFailure(ErrorCode.INVALID_ARGUMENTS, "arguments must be a JSON object")
        try:
            size = len(json.dumps(arguments, ensure_ascii=False).encode())
        except (TypeError, ValueError) as exc:
            raise ToolFailure(
                ErrorCode.INVALID_ARGUMENTS, "arguments must be JSON-serializable"
            ) from exc
        if size > self._max_bytes:
            raise ToolFailure(
                ErrorCode.INVALID_ARGUMENTS,
                f"arguments are too large ({size} bytes, limit {self._max_bytes})",
            )
        errors = sorted(self._validator.iter_errors(arguments), key=_error_sort_key)
        if errors:
            raise ToolFailure(
                ErrorCode.INVALID_ARGUMENTS,
                "; ".join(_describe(e) for e in errors[:3]),
                details={"allowed_arguments": sorted(self.schema.get("properties", {}))},
            )
        result = dict(arguments)
        for name, value in self._defaults.items():
            result.setdefault(name, copy.deepcopy(value))
        return result


def _error_sort_key(error: ValidationError) -> tuple[int, str]:
    return (len(error.absolute_path), str(list(error.absolute_path)))


def _describe(error: ValidationError) -> str:
    location = ".".join(str(p) for p in error.absolute_path) or "arguments"
    if error.validator == "additionalProperties":
        props = error.schema.get("properties", {}) if isinstance(error.schema, dict) else {}
        extra = sorted(set(error.instance) - set(props)) if isinstance(error.instance, dict) else []
        message = f"unknown argument(s) {extra}" if extra else error.message
    else:
        message = error.message
    text = f"{location}: {message}"
    return text if len(text) <= _MAX_MESSAGE else text[: _MAX_MESSAGE - 1] + "…"
