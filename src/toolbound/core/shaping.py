"""The output pipeline: from an upstream value to bounded, model-visible data.

Order (each step is deterministic)::

    select root -> schema check -> skip continuation offset -> project (shape)
    -> trusted transform -> redact -> item/string limits -> fit token budget

Everything that is dropped or shortened is recorded as an :class:`Omission`, so
the result can say exactly what is missing and why. Nothing is summarized.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, quote_plus

from jsonschema import Draft202012Validator

from .budget import to_json
from .contracts import Field, FieldSpec, Output
from .errors import ConfigurationError, ErrorCode, ToolFailure
from .paths import MISSING, Path, parse_path
from .ports import TokenEstimator

REDACTED = "[REDACTED]"
ELLIPSIS = "…"
_MAX_BUDGET_STEPS = 400
_MIN_STRING = 32
#: Upper bound on bytes serialized while trimming one result. Past it the call
#: fails with ``result_too_large`` instead of burning CPU.
_MAX_TRIM_WORK = 64 * 1024 * 1024

#: Every token pattern starts only at the beginning of a token-character run
#: (negative lookbehind) and uses possessive, bounded quantifiers, so matching is
#: linear in the input. Private-key blocks are handled by ``_redact_pem`` with
#: plain string searches, never with a lazy ``[\s\S]*?`` scan.
_T = r"(?<![A-Za-z0-9_\-])"
_SECRET_PATTERN = re.compile(
    # One shared lookbehind in front of the alternation lets the engine dispatch on
    # the first character; it is faster than per-branch anchors and stays linear.
    _T
    + "(?:"
    + "|".join(
        [
            r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])",
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,4096}+",
            r"github_pat_[A-Za-z0-9_]{22,4096}+",
            r"xox[abposr]-[A-Za-z0-9-]{10,4096}+",
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,4096}+",
            r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,4096}+",
            r"AIza[0-9A-Za-z_-]{35}",
            r"eyJ[A-Za-z0-9_-]{8,4096}+\.eyJ[A-Za-z0-9_-]{8,4096}+\.[A-Za-z0-9_-]{8,4096}+",
        ]
    )
    + r")|(?i:(?<![A-Za-z0-9])bearer[ \t]{1,8}+[A-Za-z0-9._~+/-]{16,4096}+=*+)"
)


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _join(value: Any) -> Any:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return value


def _count(value: Any) -> Any:
    return len(value) if isinstance(value, list | str | dict) else value


BUILTIN_TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "lower": lambda v: v.lower() if isinstance(v, str) else v,
    "upper": lambda v: v.upper() if isinstance(v, str) else v,
    "strip": lambda v: v.strip() if isinstance(v, str) else v,
    "count": _count,
    "first": _first,
    "join": _join,
    "bool": bool,
    "str": lambda v: v if v is None else str(v),
}


# --------------------------------------------------------------------------- reports


@dataclass(slots=True)
class Omission:
    """Something left out of the result. ``count`` = items dropped or values cut."""

    path: str
    reason: str
    count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": self.reason, "count": self.count}


@dataclass(slots=True)
class ShapeReport:
    omitted: dict[tuple[str, str], Omission] = field(default_factory=dict)
    redacted: int = 0
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: ShapeReport) -> None:
        for omission in other.omitted.values():
            self.omit(omission.path, omission.reason, omission.count)
        self.redacted += other.redacted
        self.warnings.extend(w for w in other.warnings if w not in self.warnings)

    def omit(self, path: str, reason: str, count: int = 1) -> None:
        key = (path or "$", reason)
        if key in self.omitted:
            self.omitted[key].count += count
        else:
            self.omitted[key] = Omission(path or "$", reason, count)

    @property
    def truncated(self) -> bool:
        return any(o.reason != "missing" for o in self.omitted.values())

    def omissions(self) -> list[Omission]:
        return list(self.omitted.values())


@dataclass(slots=True)
class ShapeResult:
    data: Any
    report: ShapeReport
    total_items: int | None = None
    next_offset: int | None = None
    estimated_tokens: int = 0


# --------------------------------------------------------------------------- compile


@dataclass(frozen=True, slots=True)
class CompiledField:
    key: str
    path: Path
    max_chars: int | None
    max_items: int | None
    transform: Callable[[Any], Any] | None
    default: Any
    shape: dict[str, CompiledField] | None
    #: Lower-cased last key of the source path ("" when it ends in an index).
    source_key: str = ""


@dataclass(frozen=True, slots=True)
class CompiledOutput:
    spec: Output
    root: Path
    shape: dict[str, CompiledField] | None
    error_shape: dict[str, CompiledField] | None
    required: frozenset[str]
    redact_keys: frozenset[str]
    validator: Draft202012Validator | None
    #: The longest string any field may keep (global or per-field ``max_chars``).
    max_string_chars: int = 4000

    @property
    def selectable_fields(self) -> list[str]:
        return list(self.shape) if self.shape else []


def compile_output(
    output: Output,
    transforms: Mapping[str, Callable[[Any], Any]] | None = None,
) -> CompiledOutput:
    """Parse paths and resolve transforms once, at registration time."""
    registry = {**BUILTIN_TRANSFORMS, **(transforms or {})}
    validator = None
    if output.schema is not None:
        try:
            Draft202012Validator.check_schema(dict(output.schema))
        except Exception as exc:
            raise ConfigurationError(f"invalid output schema: {exc}") from exc
        validator = Draft202012Validator(dict(output.schema))
    return CompiledOutput(
        spec=output,
        root=parse_path(output.root),
        shape=_compile_shape(output.shape, registry) if output.shape is not None else None,
        error_shape=(
            _compile_shape(output.error_shape, registry) if output.error_shape is not None else None
        ),
        required=frozenset(output.required),
        redact_keys=frozenset(normalize_key(k) for k in output.redact_keys),
        validator=validator,
        max_string_chars=max([output.max_chars, *_field_limits(output.shape)]),
    )


def _field_limits(shape: Mapping[str, FieldSpec] | None) -> list[int]:
    limits: list[int] = []
    for spec in (shape or {}).values():
        if isinstance(spec, Field):
            if spec.max_chars is not None:
                limits.append(spec.max_chars)
            limits.extend(_field_limits(spec.shape))
    return limits


def _compile_shape(
    shape: Mapping[str, FieldSpec], registry: Mapping[str, Callable[[Any], Any]]
) -> dict[str, CompiledField]:
    if not shape:
        raise ConfigurationError("shape must contain at least one field")
    compiled: dict[str, CompiledField] = {}
    for key, spec in shape.items():
        if not isinstance(key, str) or not key:
            raise ConfigurationError("shape keys must be non-empty strings")
        fspec = Field(spec) if isinstance(spec, str) else spec
        if not isinstance(fspec, Field):
            raise ConfigurationError(f"shape field {key!r} must be a path string or Field")
        transform: Callable[[Any], Any] | None
        if fspec.transform is None:
            transform = None
        elif callable(fspec.transform):
            transform = fspec.transform
        elif fspec.transform in registry:
            transform = registry[fspec.transform]
        else:
            raise ConfigurationError(f"shape field {key!r}: unknown transform {fspec.transform!r}")
        if fspec.max_chars is not None and fspec.max_chars < 1:
            raise ConfigurationError(f"shape field {key!r}: max_chars must be >= 1")
        if fspec.max_items is not None and fspec.max_items < 1:
            raise ConfigurationError(f"shape field {key!r}: max_items must be >= 1")
        compiled[key] = CompiledField(
            key=key,
            path=parse_path(fspec.source),
            max_chars=fspec.max_chars,
            max_items=fspec.max_items,
            transform=transform,
            default=fspec.default,
            shape=_compile_shape(fspec.shape, registry) if fspec.shape is not None else None,
            source_key=_last_key(fspec.source),
        )
    return compiled


def _last_key(source: str) -> str:
    name = source.rsplit(".", 1)[-1].split("[", 1)[0]
    return normalize_key(name)


# --------------------------------------------------------------------------- pipeline


def process(
    compiled: CompiledOutput,
    value: Any,
    *,
    estimator: TokenEstimator,
    offset: int = 0,
    selected: Sequence[str] | None = None,
    secrets: Sequence[str] = (),
) -> ShapeResult:
    """Run the full output pipeline. Raises :class:`ToolFailure` on hard failures."""
    spec = compiled.spec
    report = ShapeReport()

    data = compiled.root.get(value)
    if data is MISSING:
        _schema_problem(compiled, report, f"root path {compiled.root} not found in response")
        data = None
    if compiled.validator is not None and data is not None:
        error = next(iter(compiled.validator.iter_errors(data)), None)
        if error is not None:
            where = ".".join(str(p) for p in error.absolute_path) or "$"
            _schema_problem(compiled, report, f"response does not match schema at {where}")

    total_items: int | None = None
    selected_keys = None if selected is None else set(selected) | compiled.required
    secret_values = _secret_values(secrets)

    if isinstance(data, list) and spec.transform is None:
        # Per-item reports, so omissions are only reported for items actually returned.
        total_items = len(data)
        data = data[offset:]
        root_dropped = 0
        if len(data) > spec.max_items:
            root_dropped = len(data) - spec.max_items
            report.omit("$", "max_items", root_dropped)
            data = data[: spec.max_items]
        items: list[Any] = []
        item_reports: list[ShapeReport] = []
        raw_index: list[int] = []  # position of each kept item in the sliced upstream list
        not_objects = 0
        for position, raw in enumerate(data):
            item_report = ShapeReport()
            item = raw
            if compiled.shape is not None:
                if not isinstance(raw, dict):
                    not_objects += 1
                    continue
                item = _apply_shape(compiled.shape, raw, "[]", item_report, compiled, selected_keys)
            item = _redact(item, "[]", compiled, item_report, secret_values)
            item = _limit(item, "[]", spec.max_items, spec.max_chars, item_report, root=False)
            items.append(item)
            item_reports.append(item_report)
            raw_index.append(position)
        if not_objects:
            report.omit("$", "not_object", not_objects)
        budget_report = ShapeReport()
        fitted, budget_dropped, tokens = _fit_budget(items, compiled, estimator, budget_report)
        for item_report in item_reports[: len(fitted)]:
            report.merge(item_report)
        for item_report in item_reports[len(fitted) :]:
            report.warnings.extend(w for w in item_report.warnings if w not in report.warnings)
        report.merge(budget_report)
        next_offset = None
        if root_dropped or budget_dropped:
            # Resume at the first upstream element that was not returned.
            consumed = raw_index[len(fitted)] if len(fitted) < len(raw_index) else len(data)
            next_offset = offset + consumed
        return ShapeResult(fitted, report, total_items, next_offset, tokens)

    if isinstance(data, list):
        total_items = len(data)
        data = data[offset:]
    if compiled.shape is not None and data is not None:
        if isinstance(data, list):
            data = [
                _apply_shape(compiled.shape, item, "[]", report, compiled, selected_keys)
                for item in data
                if isinstance(item, dict)
            ]
        elif isinstance(data, dict):
            data = _apply_shape(compiled.shape, data, "", report, compiled, selected_keys)
        else:
            _schema_problem(compiled, report, "response root is not an object or list")

    if spec.transform is not None:
        data = spec.transform(data)

    data = _redact(data, "", compiled, report, secret_values)

    root_dropped = 0
    if isinstance(data, list) and len(data) > spec.max_items:
        root_dropped = len(data) - spec.max_items
        report.omit("$", "max_items", root_dropped)
        data = data[: spec.max_items]
    data = _limit(data, "", spec.max_items, spec.max_chars, report, root=True)

    data, budget_dropped, tokens = _fit_budget(data, compiled, estimator, report)

    next_offset = None
    if isinstance(data, list) and (root_dropped or budget_dropped):
        next_offset = offset + len(data)
    return ShapeResult(data, report, total_items, next_offset, tokens)


def shape_error_body(compiled: CompiledOutput, body: Any, *, secrets: Sequence[str] = ()) -> Any:
    """Apply ``error_shape`` to an upstream error body, tightly bounded."""
    if compiled.error_shape is None or not isinstance(body, dict):
        return None
    report = ShapeReport()
    shaped = _apply_shape(compiled.error_shape, body, "", report, compiled, None, check=False)
    shaped = _redact(shaped, "", compiled, report, _secret_values(secrets))
    return _limit(shaped, "", 5, 300, report, root=False)


def _schema_problem(compiled: CompiledOutput, report: ShapeReport, message: str) -> None:
    if compiled.spec.schema_mode == "strict":
        raise ToolFailure(ErrorCode.UPSTREAM_SCHEMA_MISMATCH, message, retryable=False)
    report.warnings.append(message)


def _apply_shape(
    shape: Mapping[str, CompiledField],
    obj: Any,
    prefix: str,
    report: ShapeReport,
    compiled: CompiledOutput,
    selected: set[str] | None,
    *,
    check: bool = True,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out
    for key, fld in shape.items():
        if selected is not None and key not in selected:
            continue
        path = f"{prefix}.{key}" if prefix else key
        value = fld.path.get(obj)
        # Renaming a sensitive source field must not bypass key-based redaction.
        if (
            value is not MISSING
            and fld.source_key in compiled.redact_keys
            and value not in (None, "")
        ):
            report.redacted += 1
            out[key] = REDACTED
            continue
        if value is MISSING:
            if fld.default is not MISSING:
                out[key] = fld.default
                continue
            if check and key in compiled.required and prefix in ("", "[]"):
                _schema_problem(compiled, report, f"required field {path!r} missing upstream")
            report.omit(path, "missing")
            continue
        if fld.shape is not None:
            if isinstance(value, list):
                value = [
                    _apply_shape(fld.shape, item, f"{path}[]", report, compiled, None, check=False)
                    for item in value
                    if isinstance(item, dict)
                ]
            elif isinstance(value, dict):
                value = _apply_shape(fld.shape, value, path, report, compiled, None, check=False)
        if fld.transform is not None:
            value = fld.transform(value)
        if fld.max_items is not None and isinstance(value, list) and len(value) > fld.max_items:
            report.omit(path, "max_items", len(value) - fld.max_items)
            value = value[: fld.max_items]
        if fld.max_chars is not None and isinstance(value, str) and len(value) > fld.max_chars:
            report.omit(path, "max_chars")
            value = _cut(value, fld.max_chars)
        out[key] = value
    return out


_PEM_BEGIN = "-----BEGIN "
_PEM_LABEL = re.compile(r"[A-Z0-9 ]{0,40}PRIVATE KEY-----")
_PEM_END = "-----END "
#: Extra characters kept beyond the string limit while redacting, so a secret that
#: straddles the cut is still seen whole before the final truncation.
_REDACT_MARGIN = 4096


def _redact_pem(text: str) -> tuple[str, int]:
    """Replace private-key blocks in linear time. An unterminated block is redacted
    to the end of the string (a partial key is still a secret)."""
    if _PEM_BEGIN not in text:
        return text, 0
    out: list[str] = []
    count = 0
    pos = 0
    while True:
        start = text.find(_PEM_BEGIN, pos)
        if start < 0:
            out.append(text[pos:])
            break
        label_end = start + len(_PEM_BEGIN)
        match = _PEM_LABEL.match(text, label_end)
        if match is None:
            out.append(text[pos:label_end])
            pos = label_end
            continue
        out.append(text[pos:start])
        out.append(REDACTED)
        count += 1
        end = text.find(_PEM_END, match.end())
        if end < 0:
            break
        tail = _PEM_LABEL.match(text, end + len(_PEM_END))
        pos = tail.end() if tail is not None else end + len(_PEM_END)
    return "".join(out), count


def _secret_values(secrets: Sequence[str]) -> tuple[str, ...]:
    """Credential values plus the encodings in which an upstream may echo them."""
    variants: set[str] = set()
    for secret in secrets:
        variants.update(
            {
                secret,
                quote(secret, safe=""),
                quote_plus(secret),
                json.dumps(secret)[1:-1],
                base64.b64encode(secret.encode()).decode(),
                base64.urlsafe_b64encode(secret.encode()).decode(),
            }
        )
    # Only redact values long enough not to collide with ordinary text.
    return tuple(sorted({v for v in variants if len(v) >= 8}, key=len, reverse=True))


def normalize_key(key: str) -> str:
    """``X-Api-Key`` / ``api_key`` / ``apiKey`` all become ``apikey``."""
    return key.lower().replace("-", "").replace("_", "")


def _redact(
    value: Any,
    path: str,
    compiled: CompiledOutput,
    report: ShapeReport,
    secrets: tuple[str, ...],
) -> Any:
    spec = compiled.spec
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            clean = key
            if isinstance(key, str) and len(key) >= 8 and _key_holds_secret(key, compiled, secrets):
                clean = f"{REDACTED}#{len(out)}"  # a credential used as a key: hide the key
                report.redacted += 1
            if (
                isinstance(key, str)
                and normalize_key(key) in compiled.redact_keys
                and item not in (None, "")
            ):
                out[clean] = REDACTED
                report.redacted += 1
            else:
                out[clean] = _redact(item, child, compiled, report, secrets)
        return out
    if isinstance(value, list):
        return [_redact(item, f"{path}[]", compiled, report, secrets) for item in value]
    if isinstance(value, str):
        value = _redact_text(value, compiled, report, secrets)
    for hook in spec.redactors:
        value = hook(path or "$", value)
    return value


def _key_holds_secret(key: str, compiled: CompiledOutput, secrets: tuple[str, ...]) -> bool:
    if any(secret in key for secret in secrets):
        return True
    # Ordinary keys are short identifiers; only long ones can hold a token pattern.
    return (
        compiled.spec.redact_secrets
        and len(key) >= 20
        and (_SECRET_PATTERN.search(key) is not None or _PEM_BEGIN in key)
    )


def _redact_text(
    text: str, compiled: CompiledOutput, report: ShapeReport, secrets: tuple[str, ...]
) -> str:
    # Nothing past the longest allowed string (plus a margin) can reach the model,
    # so never spend work on it. The final cut happens in ``_limit``.
    window = compiled.max_string_chars + _REDACT_MARGIN
    if len(text) > window:
        text = text[:window]
    for secret in secrets:
        if secret in text:
            report.redacted += text.count(secret)
            text = text.replace(secret, REDACTED)
    if compiled.spec.redact_secrets:
        text, n = _redact_pem(text)
        report.redacted += n
        text, n = _SECRET_PATTERN.subn(REDACTED, text)
        report.redacted += n
    return text


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + ELLIPSIS


def _limit(
    value: Any, path: str, max_items: int, max_chars: int, report: ShapeReport, *, root: bool
) -> Any:
    if isinstance(value, dict):
        return {
            k: _limit(
                v, f"{path}.{k}" if path else str(k), max_items, max_chars, report, root=False
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        if not root and len(value) > max_items:
            report.omit(path, "max_items", len(value) - max_items)
            value = value[:max_items]
        return [_limit(v, f"{path}[]", max_items, max_chars, report, root=False) for v in value]
    if isinstance(value, str) and len(value) > max_chars:
        report.omit(path, "max_chars")
        return _cut(value, max_chars)
    return value


# --------------------------------------------------------------------------- budget


def _fit_budget(
    data: Any,
    compiled: CompiledOutput,
    estimator: TokenEstimator,
    report: ShapeReport,
) -> tuple[Any, int, int]:
    """Return (data, root items dropped, estimated tokens)."""
    spec = compiled.spec
    tokens = estimator.count(to_json(data))
    if spec.max_tokens is None or tokens <= spec.max_tokens:
        return data, 0, tokens
    if spec.overflow == "reject":
        raise ToolFailure(
            ErrorCode.RESULT_TOO_LARGE,
            f"result needs ~{tokens} tokens but the budget is {spec.max_tokens}; "
            "narrow the request (filters, fields, or a smaller page)",
            retryable=False,
        )
    budget = spec.max_tokens
    dropped = 0
    if isinstance(data, list) and len(data) > 1:
        lo, hi = 1, len(data)
        while lo < hi:  # largest prefix that fits
            mid = (lo + hi + 1) // 2
            if estimator.count(to_json(data[:mid])) <= budget:
                lo = mid
            else:
                hi = mid - 1
        if lo < len(data):
            dropped = len(data) - lo
            report.omit("$", "budget", dropped)
            data = data[:lo]
        tokens = estimator.count(to_json(data))
        if tokens <= budget:
            return data, dropped, tokens

    data = json.loads(to_json(data))  # one private, JSON-safe copy, trimmed in place
    work = 0
    for _ in range(_MAX_BUDGET_STEPS):
        candidates = _trimmable(data, compiled.required)
        if not candidates:
            break
        if tokens > 2 * budget:
            # Far over budget: halve every value at least half as large as the
            # largest in one step, so the number of steps grows with log(size).
            largest = candidates[0][0]
            batch = [c for c in candidates if c[0] * 2 > largest]
        else:
            batch = candidates[:1]
        # Deepest first, so halving a list never invalidates a later location.
        for _size, path_key, size_path in sorted(batch, key=lambda c: -len(c[2])):
            data = _halve_at(data, size_path)
            report.omit(path_key, "budget")
        text = to_json(data)
        work += len(text)
        tokens = estimator.count(text)
        if tokens <= budget:
            return data, dropped, tokens
        if work > _MAX_TRIM_WORK:
            raise ToolFailure(
                ErrorCode.RESULT_TOO_LARGE,
                f"result is far over the {budget}-token budget; narrow the request "
                "(filters, fields, or a smaller page)",
                retryable=False,
            )
    raise ToolFailure(
        ErrorCode.RESULT_TOO_LARGE,
        f"result cannot fit the {budget}-token budget even after trimming (required "
        "fields and object keys are never removed); narrow the request",
        retryable=False,
    )


def _trimmable(data: Any, required: frozenset[str]) -> list[tuple[int, str, tuple[str | int, ...]]]:
    """Every value that may be halved, largest first (ties by path, deterministic)."""
    found: list[tuple[int, str, tuple[str | int, ...]]] = []

    def visit(node: Any, norm: str, loc: tuple[str | int, ...]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key in required and _record_level(loc):
                    continue
                visit(child, f"{norm}.{key}" if norm else key, (*loc, key))
            return
        if isinstance(node, list):
            if len(node) > 1 and loc:
                found.append((len(to_json(node)), norm or "$", loc))
            for i, child in enumerate(node):
                visit(child, f"{norm}[]", (*loc, i))
            return
        if isinstance(node, str) and len(node) > _MIN_STRING:
            found.append((len(node.encode()), norm or "$", loc))

    visit(data, "", ())
    found.sort(key=lambda c: (-c[0], c[1], [str(p) for p in c[2]]))
    return found


def _record_level(loc: tuple[str | int, ...]) -> bool:
    # A top-level object (loc == ()) or an element of the root list (loc == (i,)).
    return len(loc) == 0 or (len(loc) == 1 and isinstance(loc[0], int))


def _halve_at(data: Any, loc: tuple[str | int, ...]) -> Any:
    """Halve the value at ``loc`` in place (``data`` is a private copy)."""
    if not loc:
        return _halve(data)
    parent = data
    for step in loc[:-1]:
        parent = parent[step]
    parent[loc[-1]] = _halve(parent[loc[-1]])
    return data


def _halve(value: Any) -> Any:
    if isinstance(value, list):
        return value[: max(1, len(value) // 2)]
    if isinstance(value, str):
        return _cut(value, max(_MIN_STRING, len(value) // 2))
    return value
