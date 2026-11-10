"""Output pipeline: projection, limits, redaction, budgets, determinism, Unicode."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolbound import ByteEstimator, ConfigurationError, ErrorCode, Field, Output, ToolFailure
from toolbound.core.budget import to_json
from toolbound.core.paths import MISSING, parse_path
from toolbound.core.shaping import compile_output, process

EST = ByteEstimator()


def run(output: Output, value, **kw):
    return process(compile_output(output), value, estimator=EST, **kw)


# ------------------------------------------------------------------ paths


@pytest.mark.parametrize(
    ("path", "doc", "expected"),
    [
        ("$", {"a": 1}, {"a": 1}),
        ("a", {"a": 1}, 1),
        ("a.b", {"a": {"b": 2}}, 2),
        ("a[].b", {"a": [{"b": 1}, {"c": 2}, {"b": 3}]}, [1, 3]),
        ("a[1]", {"a": [1, 2]}, 2),
        ("[].id", [{"id": 1}, {"id": 2}], [1, 2]),
        ("a[][].x", {"a": [[{"x": 1}], [{"x": 2}]]}, [[1], [2]]),
        ("missing", {"a": 1}, MISSING),
        ("a.b", {"a": [1]}, MISSING),
        ("a[5]", {"a": [1]}, MISSING),
        ("user-name", {"user-name": "x"}, "x"),
    ],
)
def test_paths(path, doc, expected):
    assert parse_path(path).get(doc) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "a..b",
        "a.",
        ".a",
        "a[x]",
        "a[-1]",
        "a b",
        "a.__class__()",
        "x" * 300,
        ".".join("a" * 40),
    ],
)
def test_bad_paths(bad):
    with pytest.raises(ConfigurationError):
        parse_path(bad)


def test_paths_never_evaluate_code():
    class Evil(dict):
        def __getattr__(self, name):  # pragma: no cover - must never be called
            raise AssertionError("attribute access attempted")

    assert parse_path("__class__").get(Evil()) is MISSING


# ------------------------------------------------------------------ projection & limits


def test_allowlist_projection_drops_everything_else():
    out = run(Output(shape={"id": "id"}), {"id": 1, "ssn": "123-45-6789", "nested": {"x": 1}})
    assert out.data == {"id": 1}


def test_missing_fields_reported_not_invented():
    out = run(Output(shape={"id": "id", "email": "contact.email"}), {"id": 1})
    assert out.data == {"id": 1}
    assert [(o.path, o.reason) for o in out.report.omissions()] == [("email", "missing")]
    assert out.report.truncated is False  # missing upstream is not truncation


def test_default_used_for_missing():
    out = run(Output(shape={"state": Field("state", default="unknown")}), {})
    assert out.data == {"state": "unknown"}


def test_root_list_shaping_and_limits():
    items = [{"id": i, "body": "x" * 100} for i in range(10)]
    out = run(
        Output(root="items", shape={"id": "id", "body": "body"}, max_items=3, max_chars=20),
        {"items": items},
    )
    assert [i["id"] for i in out.data] == [0, 1, 2]
    assert all(len(i["body"]) == 20 and i["body"].endswith("…") for i in out.data)
    reasons = {(o.path, o.reason): o.count for o in out.report.omissions()}
    assert reasons[("$", "max_items")] == 7
    assert reasons[("[].body", "max_chars")] == 3
    assert out.total_items == 10
    assert out.next_offset == 3


def test_offset_skips_items():
    out = run(Output(), list(range(10)), offset=7)
    assert out.data == [7, 8, 9] and out.next_offset is None


def test_builtin_transforms():
    shape = {
        "lower": Field("t", transform="lower"),
        "count": Field("tags", transform="count"),
        "joined": Field("tags", transform="join"),
        "first": Field("tags", transform="first"),
    }
    out = run(Output(shape=shape), {"t": "ABC", "tags": ["a", "b"]})
    assert out.data == {"lower": "abc", "count": 2, "joined": "a, b", "first": "a"}


def test_custom_transform_and_unknown_transform():
    out = process(
        compile_output(
            Output(shape={"x": Field("x", transform="cents")}), {"cents": lambda v: round(v * 100)}
        ),
        {"x": 1.5},
        estimator=EST,
    )
    assert out.data == {"x": 150}
    with pytest.raises(ConfigurationError):
        compile_output(Output(shape={"x": Field("x", transform="nope")}))


def test_custom_redactor_hook():
    def mask_email(path, value):
        if isinstance(value, str) and "@" in value:
            return "[EMAIL]"
        return value

    out = run(Output(redactors=(mask_email,)), {"a": "x@y.com", "b": "ok"})
    assert out.data == {"a": "[EMAIL]", "b": "ok"}


# ------------------------------------------------------------------ Unicode / RTL


def test_persian_text_truncates_on_code_points():
    text = "قرارداد اجاره میان طرفین منعقد شد و " * 20
    out = run(Output(shape={"t": "t"}, max_chars=50), {"t": text})
    assert len(out.data["t"]) == 50
    out.data["t"].encode("utf-8")  # valid
    assert out.data["t"].startswith("قرارداد")


def test_rtl_and_emoji_survive_json():
    value = {"t": "שלום ‫RTL‬ 👍🏽 سلام"}
    out = run(Output(), value)
    assert out.data == value
    assert "سلام" in to_json(out.data)


# ------------------------------------------------------------------ budget


def test_budget_drops_items_and_reports():
    items = [{"id": i, "text": "word " * 40} for i in range(40)]
    out = run(
        Output(shape={"id": "id", "text": "text"}, required=("id",), max_tokens=500, max_items=100),
        items,
    )
    assert EST.count(to_json(out.data)) <= 500
    assert out.estimated_tokens <= 500
    assert any(o.reason == "budget" for o in out.report.omissions())
    assert out.next_offset == len(out.data)


def test_budget_shrinks_long_strings_but_keeps_required():
    doc = {"citation": "Case No. 2024/118", "text": "x" * 20000}
    out = run(
        Output(
            shape={"citation": "citation", "text": "text"},
            required=("citation",),
            max_tokens=200,
            max_chars=50000,
        ),
        doc,
    )
    assert out.data["citation"] == "Case No. 2024/118"
    assert len(out.data["text"]) < 20000
    assert EST.count(to_json(out.data)) <= 200


def test_reject_mode_never_returns_partial_data():
    doc = {"text": "x" * 5000}
    with pytest.raises(ToolFailure) as info:
        run(Output(shape={"text": "text"}, max_tokens=100, overflow="reject", max_chars=10000), doc)
    assert info.value.code is ErrorCode.RESULT_TOO_LARGE


def test_required_fields_too_large_fail_instead_of_silent_loss():
    doc = {"id": "y" * 5000}
    with pytest.raises(ToolFailure) as info:
        run(Output(shape={"id": "id"}, required=("id",), max_tokens=100, max_chars=10000), doc)
    assert info.value.code is ErrorCode.RESULT_TOO_LARGE


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=300),
    lambda children: (
        st.lists(children, max_size=8)
        | st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=6)
    ),
    max_leaves=60,
)


@settings(max_examples=150, deadline=None)
@given(value=json_values, budget=st.integers(min_value=16, max_value=400))
def test_property_budget_is_respected_or_fails_closed(value, budget):
    output = Output(
        max_tokens=budget, max_items=20, max_chars=500, redact_secrets=False, redact_keys=()
    )
    try:
        out = run(output, value)
    except ToolFailure as failure:
        code = failure.code
    else:
        assert EST.count(to_json(out.data)) <= budget
        return
    assert code is ErrorCode.RESULT_TOO_LARGE


@settings(max_examples=100, deadline=None)
@given(value=json_values)
def test_property_deterministic(value):
    output = Output(max_tokens=64, max_items=5, max_chars=40)
    try:
        a = run(output, value)
        b = run(output, value)
    except ToolFailure:
        return
    assert to_json(a.data) == to_json(b.data)
    assert [o.to_dict() for o in a.report.omissions()] == [
        o.to_dict() for o in b.report.omissions()
    ]


@settings(max_examples=100, deadline=None)
@given(
    items=st.lists(
        st.dictionaries(st.sampled_from(["id", "a", "b"]), st.integers(), min_size=1), max_size=30
    )
)
def test_property_projection_only_emits_allowlisted_keys(items):
    out = run(Output(shape={"id": "id", "a": "a"}, max_items=100, max_tokens=None), items)
    for item in out.data:
        assert set(item) <= {"id", "a"}


def test_output_validation():
    with pytest.raises(ConfigurationError):
        Output(required=("id",))  # needs shape
    with pytest.raises(ConfigurationError):
        Output(shape={"a": "a"}, required=("b",))
    with pytest.raises(ConfigurationError):
        Output(max_tokens=1)
    with pytest.raises(ConfigurationError):
        Output(overflow="summarize")  # type: ignore[arg-type]
