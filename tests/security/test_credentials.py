"""Credential isolation: secrets never reach the model, logs, events or reprs."""

from __future__ import annotations

import logging

from toolbound import (
    ApiKeyAuth,
    BasicAuth,
    BearerAuth,
    EnvCredentials,
    ExecutionContext,
    Operation,
    Output,
    Service,
    StaticCredentials,
)
from toolbound.transport.mock import MockResponse

from ..conftest import SECRET


class Recorder:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


def _op(service, **kw):
    kw.setdefault("name", "op")
    kw.setdefault("description", "d")
    kw.setdefault("path", "/x")
    return Operation(service=service, **kw)


async def test_upstream_echo_of_credential_is_scrubbed(make_gateway, mock, ctx, caplog):
    service = Service(name="s", base_url="https://api.example.com", auth=BearerAuth("github_token"))
    mock.route(
        "GET",
        "https://api.example.com/x",
        lambda r: {
            "debug": f"received header Authorization: {dict(r.headers)['Authorization']}",
            "nested": [{"value": SECRET}],
        },
    )
    recorder = Recorder()
    gw = make_gateway(observer=recorder).register(_op(service))
    with caplog.at_level(logging.DEBUG, logger="toolbound"):
        result = await gw.call("op", {}, ctx=ctx)
    assert result.ok
    text = result.to_json()
    assert SECRET not in text
    assert result.meta.redacted >= 2
    assert SECRET not in caplog.text
    assert all(SECRET not in repr(e) for e in recorder.events)


async def test_credential_echo_in_error_body_is_scrubbed(make_gateway, mock, ctx):
    service = Service(
        name="s", base_url="https://api.example.com", auth=ApiKeyAuth("key", header="X-Key")
    )
    value = "plain-value-with-no-known-format-123"
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(403, json={"message": f"key {value} is revoked"}),
    )
    gw = make_gateway(credentials=StaticCredentials({"key": value})).register(
        _op(service, output=Output(error_shape={"message": "message"}))
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert not result.ok
    assert value not in result.to_json()
    assert "[REDACTED]" in result.to_json()


async def test_basic_auth_value_scrubbed(make_gateway, mock, ctx):
    service = Service(name="s", base_url="https://api.example.com", auth=BasicAuth("basic"))
    mock.route(
        "GET", "https://api.example.com/x", lambda r: {"echo": dict(r.headers)["Authorization"]}
    )
    gw = make_gateway(credentials=StaticCredentials({"basic": "user:p4ssw0rd!!"})).register(
        _op(service)
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert "dXNlcjpwNHNzdzByZCEh" not in result.to_json()


async def test_sensitive_keys_redacted_in_passthrough(make_gateway, mock, ctx):
    service = Service(name="s", base_url="https://api.example.com")
    mock.route(
        "GET",
        "https://api.example.com/x",
        {
            "user": "bob",
            "password": "hunter2",
            "Access_Token": "abc",
            "profile": {"api_key": "k"},
            "note": "AKIAIOSFODNN7EXAMPLE is a key",
        },
    )
    gw = make_gateway().register(_op(service))
    data = (await gw.call("op", {}, ctx=ctx)).data
    assert data["password"] == data["Access_Token"] == data["profile"]["api_key"] == "[REDACTED]"
    assert "AKIA" not in data["note"]
    assert data["user"] == "bob"


async def test_credentials_are_not_in_definitions_or_reprs(make_gateway, ctx):
    service = Service(name="s", base_url="https://api.example.com", auth=BearerAuth("github_token"))
    gw = make_gateway().register(_op(service))
    assert SECRET not in str([d.to_dict() for d in gw.definitions(ctx)])
    assert SECRET not in repr(StaticCredentials({"github_token": SECRET}))
    assert "github_token" not in str(gw.definitions(ctx))


def test_context_repr_hides_attribute_values():
    ctx = ExecutionContext(actor="a", attributes={"session_token": "very-secret-value"})
    assert "very-secret-value" not in repr(ctx)


def test_env_credentials(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    monkeypatch.setenv("APP_STRIPE_KEY", "s")
    ctx = ExecutionContext(actor="a")
    assert EnvCredentials().get("github_token", ctx) == "from-env"
    assert EnvCredentials(prefix="APP_").get("stripe_key", ctx) == "s"
    assert EnvCredentials({"x": "GITHUB_TOKEN"}).get("x", ctx) == "from-env"
    assert EnvCredentials().get("missing", ctx) is None


def test_secret_value_cannot_be_used_as_credential_name():
    import pytest

    from toolbound import ConfigurationError

    with pytest.raises(ConfigurationError):
        Service(name="s", base_url="https://a.example.com", auth=BearerAuth("has spaces"))


async def test_static_auth_headers_cannot_be_set(make_gateway):
    import pytest

    from toolbound import ConfigurationError

    for header in ("Authorization", "Host", "Cookie", "Proxy-Authorization"):
        with pytest.raises(ConfigurationError):
            Service(name="s", base_url="https://a.example.com", headers={header: "x"})
    with pytest.raises(ConfigurationError):
        Service(name="s", base_url="https://a.example.com", headers={"X-A": "v\r\nInjected: 1"})


async def test_credential_with_newline_rejected(make_gateway, mock, ctx):
    service = Service(name="s", base_url="https://api.example.com", auth=BearerAuth("t"))
    gw = make_gateway(credentials=StaticCredentials({"t": "abc\r\nX-Evil: 1"})).register(
        _op(service)
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert not result.ok and mock.requests == []


async def test_per_user_credentials_from_context(make_gateway, mock, ctx):
    class PerUser:
        def get(self, name, ctx):
            return {"alice": "alice-oauth-token"}.get(ctx.actor)

    service = Service(name="s", base_url="https://api.example.com", auth=BearerAuth("user_oauth"))
    mock.route("GET", "https://api.example.com/x", {"ok": 1})
    gw = make_gateway(credentials=PerUser()).register(_op(service))
    assert (await gw.call("op", {}, ctx=ctx)).ok
    assert ("Authorization", "Bearer alice-oauth-token") in mock.requests[0].headers
    other = await gw.call("op", {}, ctx=ExecutionContext(actor="bob"))
    assert not other.ok
