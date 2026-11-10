"""H1: write methods can never silently become read tools."""

from __future__ import annotations

import pytest

from toolbound import (
    ConfigurationError,
    Effect,
    ErrorCode,
    MockResponse,
    Operation,
    PythonTool,
    Service,
)
from toolbound.loaders import parse_contract

SVC = Service(name="api", base_url="https://api.example.com")


@pytest.mark.parametrize(
    ("method", "effect"),
    [
        ("GET", Effect.READ),
        ("HEAD", Effect.READ),
        ("OPTIONS", Effect.READ),
        ("POST", Effect.WRITE),
        ("PUT", Effect.WRITE),
        ("PATCH", Effect.WRITE),
        ("DELETE", Effect.DESTRUCTIVE),
    ],
)
def test_h1_effect_inferred_from_method(method, effect):
    op = Operation(name="op", description="d", service=SVC, method=method, path="/x")
    assert op.effect is effect


def test_h1_delete_cannot_be_declared_read():
    with pytest.raises(ConfigurationError, match="DELETE"):
        Operation(
            name="op", description="d", service=SVC, method="DELETE", path="/x", effect="read"
        )


def test_h1_read_only_post_must_be_explicit():
    op = Operation(
        name="search", description="d", service=SVC, method="POST", path="/s", effect="read"
    )
    assert op.effect is Effect.READ


def test_h1_python_tools_must_declare_effect():
    with pytest.raises(ConfigurationError, match="must declare effect"):
        PythonTool(name="wipe", description="d", handler=lambda: None)


def test_h1_decorator_requires_effect(make_gateway):
    gw = make_gateway()
    with pytest.raises(ConfigurationError, match="must declare effect"):

        @gw.tool
        def wipe() -> dict:
            """Wipe."""
            return {}


def test_h1_yaml_contract_defaults_follow_method():
    tools = parse_contract(
        {
            "version": 1,
            "service": {"name": "api", "base_url": "https://api.example.com"},
            "operations": [
                {
                    "name": "drop",
                    "description": "d",
                    "method": "DELETE",
                    "path": "/x/{id}",
                    "input": {"id": {"type": "integer"}},
                },
                {"name": "make", "description": "d", "method": "POST", "path": "/x"},
            ],
        }
    )
    effects = {t.name: t.effect for t in tools}
    assert effects == {"drop": Effect.DESTRUCTIVE, "make": Effect.WRITE}


async def test_h1_undeclared_delete_requires_approval_and_dedupes(make_gateway, mock, ctx):
    """The original failure: DELETE ran with no approval and ran twice for one call id."""
    mock.route("DELETE", "https://api.example.com/users/{id}", MockResponse(204))
    op = Operation(
        name="del_user",
        description="d",
        service=SVC,
        method="DELETE",
        path="/users/{id}",
        input={"id": {"type": "integer"}},
    )
    gw = make_gateway().register(op)
    first = await gw.call("del_user", {"id": 1}, ctx=ctx, call_id="x")
    assert first.error.code is ErrorCode.APPROVAL_REQUIRED
    assert mock.requests == []
    done = await gw.resume(first.approval, ctx=ctx, approved_by="alice", call_id="x")
    assert done.ok
    again = await gw.resume(first.approval, ctx=ctx, approved_by="alice", call_id="x")
    assert not again.ok
    assert len(mock.requests) == 1


async def test_h1_undeclared_post_gets_call_id_replay_protection(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/things", {"id": 1})
    op = Operation(name="make", description="d", service=SVC, method="POST", path="/things")
    gw = make_gateway().register(op)
    assert (await gw.call("make", {}, ctx=ctx, call_id="c")).ok
    dup = await gw.call("make", {}, ctx=ctx, call_id="c")
    assert dup.error.code is ErrorCode.DUPLICATE_CALL
    assert len(mock.requests) == 1
