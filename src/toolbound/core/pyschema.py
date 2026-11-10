"""Infer a JSON Schema from a Python handler's signature (for PythonTool)."""

from __future__ import annotations

import enum
import inspect
import json
import types
import typing
from collections.abc import Callable, Iterable
from typing import Any, Literal, Union, get_args, get_origin

from .errors import ConfigurationError

_SIMPLE: dict[type, dict[str, Any]] = {
    str: {"type": "string"},
    int: {"type": "integer"},
    float: {"type": "number"},
    bool: {"type": "boolean"},
    dict: {"type": "object"},
}


def handler_parameters(fn: Callable[..., Any]) -> tuple[set[str], bool, bool]:
    """Return (named parameters, accepts **kwargs, accepts ctx)."""
    sig = inspect.signature(fn)
    names: set[str] = set()
    var_kw = False
    for name, param in sig.parameters.items():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            var_kw = True
        elif param.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            names.add(name)
    return names - {"ctx"}, var_kw, "ctx" in sig.parameters


def infer_input_schema(fn: Callable[..., Any], *, exclude: Iterable[str] = ()) -> dict[str, Any]:
    """Build an input schema from type hints. Raises ConfigurationError if unsupported."""
    skip = set(exclude) | {"ctx"}
    sig = inspect.signature(fn)
    try:
        hints = typing.get_type_hints(fn, include_extras=True)
    except Exception as exc:
        raise ConfigurationError(f"cannot read type hints of {fn!r}: {exc}") from exc
    properties: dict[str, Any] = {}
    required: list[str] = []
    for name, param in sig.parameters.items():
        if name in skip or param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if param.kind is inspect.Parameter.POSITIONAL_ONLY:
            raise ConfigurationError(f"{fn.__name__}: positional-only parameters are not supported")
        if name not in hints:
            raise ConfigurationError(
                f"{fn.__name__}: parameter {name!r} needs a type hint (or pass input= explicitly)"
            )
        schema = _schema_for(hints[name], fn.__name__, name)
        if param.default is inspect.Parameter.empty:
            required.append(name)
        else:
            try:
                json.dumps(param.default)
            except TypeError as exc:
                raise ConfigurationError(
                    f"{fn.__name__}: default of {name!r} is not JSON-serializable"
                ) from exc
            schema["default"] = param.default
        properties[name] = schema
    return {"type": "object", "properties": properties, "required": required}


def _schema_for(tp: Any, fn: str, name: str) -> dict[str, Any]:
    origin = get_origin(tp)
    if origin is typing.Annotated:
        base, *meta = get_args(tp)
        schema = _schema_for(base, fn, name)
        for item in meta:
            if isinstance(item, str):
                schema["description"] = item
            elif isinstance(item, dict):
                schema.update(item)
        return schema
    if tp in _SIMPLE:
        return dict(_SIMPLE[tp])
    if origin is Literal:
        return {"enum": list(get_args(tp))}
    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        return {"enum": [m.value for m in tp]}
    if origin in (list, tuple, set, frozenset) or tp in (list, tuple):
        args = get_args(tp)
        array: dict[str, Any] = {"type": "array"}
        if args and args[0] is not Ellipsis:
            array["items"] = _schema_for(args[0], fn, name)
        if origin in (set, frozenset):
            array["uniqueItems"] = True
        return array
    if origin is dict:
        return {"type": "object"}
    if origin in (Union, types.UnionType):
        members = [a for a in get_args(tp) if a is not type(None)]
        nullable = len(members) != len(get_args(tp))
        if len(members) == 1:
            inner = _schema_for(members[0], fn, name)
            return {"anyOf": [inner, {"type": "null"}]} if nullable else inner
        options = [_schema_for(m, fn, name) for m in members]
        if nullable:
            options.append({"type": "null"})
        return {"anyOf": options}
    raise ConfigurationError(
        f"{fn}: cannot infer a schema for parameter {name!r} ({tp!r}); pass input= explicitly"
    )
