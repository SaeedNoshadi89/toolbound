from __future__ import annotations

import json

import pytest

from toolbound import (
    ApiKeyAuth,
    Effect,
    ErrorCode,
    Field,
    HttpResponse,
    Limits,
    NetworkPolicy,
    NoAuth,
    Operation,
    Output,
    Pagination,
    RateLimit,
    RetryPolicy,
    Service,
    StaticCredentials,
)
from toolbound.transport.mock import MockResponse

from .conftest import SECRET

BASE = "https://api.example.com"


def svc(**kw):
    kw.setdefault("name", "example")
    kw.setdefault("base_url", BASE)
    return Service(**kw)


def op(**kw):
    kw.setdefault("name", "op")
    kw.setdefault("description", "test operation")
    kw.setdefault("service", svc())
    return Operation(**kw)


async def test_get_query_placement_and_defaults(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/search", lambda r: {"url": r.url})
    gw = make_gateway().register(
        op(
            path="/search",
            input={
                "q": {"type": "string", "maxLength": 50},
                "limit": {"type": "integer", "default": 10, "maximum": 50},
                "tags": {"type": "array", "items": {"type": "string"}, "default": []},
            },
        )
    )
    result = await gw.call("op", {"q": "hello world", "tags": ["a", "b"]}, ctx=ctx)
    assert result.ok
    assert mock.requests[0].url == f"{BASE}/search?q=hello+world&limit=10&tags=a&tags=b"


async def test_post_json_body_and_bound_tenant(make_gateway, mock, ctx):
    mock.route("POST", f"{BASE}/tenants/{{t}}/notes", lambda r: MockResponse(201, json={"id": 7}))
    gw = make_gateway().register(
        op(
            method="POST",
            effect="write",
            path="/tenants/{tenant}/notes",
            input={
                "text": {"type": "string"},
                "meta": {"type": "object", "properties": {"pinned": {"type": "boolean"}}},
            },
            bind={"tenant": "ctx.tenant"},
            output=Output(shape={"id": "id"}),
        )
    )
    result = await gw.call("op", {"text": "hi", "meta": {"pinned": True}}, ctx=ctx)
    assert result.ok and result.data == {"id": 7}
    sent = mock.requests[0]
    assert sent.url == f"{BASE}/tenants/acme/notes"
    assert json.loads(sent.body) == {"text": "hi", "meta": {"pinned": True}}
    assert ("Content-Type", "application/json") in sent.headers


async def test_nested_unknown_property_rejected(make_gateway, ctx):
    gw = make_gateway().register(
        op(
            method="POST",
            effect="write",
            path="/x",
            input={"meta": {"type": "object", "properties": {"a": {"type": "string"}}}},
        )
    )
    result = await gw.call("op", {"meta": {"a": "1", "evil": True}}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_form_body(make_gateway, mock, ctx):
    mock.route("POST", f"{BASE}/form", {"ok": True})
    gw = make_gateway().register(
        op(
            method="POST",
            effect="write",
            path="/form",
            body_format="form",
            input={"a": {"type": "string"}},
        )
    )
    assert (await gw.call("op", {"a": "x y"}, ctx=ctx)).ok
    assert mock.requests[0].body == b"a=x+y"


async def test_explicit_query_on_post(make_gateway, mock, ctx):
    mock.route("POST", f"{BASE}/p", {"ok": True})
    gw = make_gateway().register(
        op(
            method="POST",
            effect="write",
            path="/p",
            query=("dry_run",),
            input={"dry_run": {"type": "boolean"}, "name": {"type": "string"}},
        )
    )
    assert (await gw.call("op", {"dry_run": True, "name": "n"}, ctx=ctx)).ok
    sent = mock.requests[0]
    assert sent.url.endswith("/p?dry_run=true")
    assert json.loads(sent.body) == {"name": "n"}


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        (400, ErrorCode.UPSTREAM_ERROR, False),
        (401, ErrorCode.UPSTREAM_ERROR, False),
        (404, ErrorCode.UPSTREAM_ERROR, False),
        (429, ErrorCode.RATE_LIMITED, True),
        (500, ErrorCode.UPSTREAM_ERROR, True),
    ],
)
async def test_error_mapping(make_gateway, mock, ctx, status, code, retryable):
    mock.route("GET", f"{BASE}/e", MockResponse(status, json={"message": "boom", "secret": "s"}))
    gw = make_gateway().register(
        op(
            path="/e",
            service=svc(retry=RetryPolicy(max_attempts=1)),
            output=Output(error_shape={"message": "message"}),
        )
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert not result.ok and result.error
    assert result.error.code is code
    assert result.error.retryable is retryable
    assert result.error.details["upstream"] == {"message": "boom"}
    assert result.http_status == status


async def test_retry_get_on_503_then_success(make_gateway, mock, ctx):
    responses = [MockResponse(503), MockResponse(503), MockResponse(200, json={"v": 1})]
    mock.route("GET", f"{BASE}/r", lambda r: responses.pop(0))
    gw = make_gateway().register(op(path="/r"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok and result.data == {"v": 1}
    assert len(mock.requests) == 3


async def test_post_is_never_retried_without_idempotency(make_gateway, mock, ctx):
    mock.route("POST", f"{BASE}/w", MockResponse(503))
    gw = make_gateway().register(op(method="POST", effect="write", path="/w"))
    result = await gw.call("op", {}, ctx=ctx)
    assert not result.ok
    assert len(mock.requests) == 1


async def test_post_with_idempotency_key_retries_with_same_key(make_gateway, mock, ctx):
    responses = [MockResponse(503), MockResponse(201, json={"id": 1})]
    mock.route("POST", f"{BASE}/w", lambda r: responses.pop(0))
    gw = make_gateway().register(
        op(method="POST", effect="write", path="/w", idempotency_header="Idempotency-Key")
    )
    result = await gw.call("op", {}, ctx=ctx, call_id="call_1")
    assert result.ok
    keys = [dict(r.headers)["Idempotency-Key"] for r in mock.requests]
    assert len(keys) == 2 and keys[0] == keys[1]


async def test_retry_after_too_long_returns_rate_limited(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/r", MockResponse(429, headers={"Retry-After": "120"}))
    gw = make_gateway().register(op(path="/r"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.RATE_LIMITED
    assert result.error.retry_after == pytest.approx(120)
    assert len(mock.requests) == 1


async def test_retry_after_is_respected(make_gateway, mock, ctx):
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    responses = [MockResponse(429, headers={"Retry-After": "2"}), MockResponse(json={"a": 1})]
    mock.route("GET", f"{BASE}/r", lambda r: responses.pop(0))
    gw = make_gateway(sleep=sleep).register(op(path="/r"))
    assert (await gw.call("op", {}, ctx=ctx)).ok
    assert slept == [2.0]


async def test_redirects_disabled_by_default(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/old", MockResponse(302, headers={"Location": f"{BASE}/new"}))
    gw = make_gateway().register(op(path="/old"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.UPSTREAM_ERROR
    assert "redirect" in result.error.message


async def test_same_origin_redirect_followed_when_enabled(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/old", MockResponse(301, headers={"Location": "/new"}))
    mock.route("GET", f"{BASE}/new", {"moved": True})
    service = svc(network=NetworkPolicy(follow_redirects=True))
    gw = make_gateway().register(op(path="/old", service=service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok and result.data == {"moved": True}


async def test_unsupported_content_type(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/f",
        MockResponse(body=b"%PDF-1.7", headers={"Content-Type": "application/pdf"}),
    )
    gw = make_gateway().register(op(path="/f"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.UNSUPPORTED_CONTENT_TYPE


async def test_text_accepted_when_enabled(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/t",
        MockResponse(body="سلام دنیا".encode(), headers={"Content-Type": "text/plain"}),
    )
    gw = make_gateway().register(op(path="/t", output=Output(accept_text=True)))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok and result.data == "سلام دنیا"


async def test_malformed_json(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/j",
        MockResponse(body=b"{not json", headers={"Content-Type": "application/json"}),
    )
    gw = make_gateway().register(op(path="/j"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.UPSTREAM_SCHEMA_MISMATCH


async def test_no_content(make_gateway, mock, ctx):
    mock.route("DELETE", f"{BASE}/d", MockResponse(204))
    gw = make_gateway().register(op(method="DELETE", path="/d", effect="write"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok and result.data is None


async def test_upstream_schema_strict_and_warn(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/s", {"id": "not-an-int"})
    schema = {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}
    gw = make_gateway().register(
        op(name="strict", path="/s", output=Output(schema=schema)),
        op(name="warn", path="/s", output=Output(schema=schema, schema_mode="warn")),
    )
    strict = await gw.call("strict", {}, ctx=ctx)
    assert strict.error and strict.error.code is ErrorCode.UPSTREAM_SCHEMA_MISMATCH
    warn = await gw.call("warn", {}, ctx=ctx)
    assert warn.ok and warn.meta.warnings


async def test_required_field_missing_upstream_is_schema_error(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/s", {"title": "no id"})
    gw = make_gateway().register(
        op(path="/s", output=Output(shape={"id": "id", "title": "title"}, required=("id",)))
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.UPSTREAM_SCHEMA_MISMATCH


async def test_api_key_in_query_is_not_leaked(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/q", lambda r: {"echo": r.url})
    service = svc(auth=ApiKeyAuth("key", header=None, query="api_key"))
    gw = make_gateway(credentials=StaticCredentials({"key": "supersecretvalue123"})).register(
        op(path="/q", service=service)
    )
    result = await gw.call("op", {}, ctx=ctx)
    assert "api_key=supersecretvalue123" in mock.requests[0].url
    assert "supersecretvalue123" not in result.to_json()


async def test_cursor_pagination(make_gateway, mock, ctx):
    pages = {None: {"items": [1, 2], "next": "abc"}, "abc": {"items": [3], "next": None}}

    def handler(request):
        token = request.url.split("page_token=")[1] if "page_token=" in request.url else None
        return pages[token]

    mock.route("GET", f"{BASE}/list", handler)
    gw = make_gateway().register(
        op(
            path="/list",
            output=Output(root="items"),
            pagination=Pagination(type="cursor", param="page_token", next_path="next"),
        )
    )
    first = await gw.call("op", {}, ctx=ctx)
    assert first.data == [1, 2] and first.meta.next_cursor
    assert "abc" not in first.meta.next_cursor.split(".")[0]
    second = await gw.call("op", {"cursor": first.meta.next_cursor}, ctx=ctx)
    assert second.data == [3] and second.meta.next_cursor is None


async def test_link_pagination_rejects_foreign_origin(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/items",
        MockResponse(
            json=[{"id": 1}],
            headers={"Link": '<https://evil.example.net/items?page=2>; rel="next"'},
        ),
    )
    gw = make_gateway().register(op(path="/items", pagination=Pagination(type="link")))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok and result.meta.next_cursor is None


async def test_link_pagination_same_origin(make_gateway, mock, ctx):
    def handler(request):
        if "page=2" in request.url:
            return [{"id": 2}]
        return MockResponse(
            json=[{"id": 1}], headers={"Link": f'<{BASE}/items?page=2>; rel="next"'}
        )

    mock.route("GET", f"{BASE}/items", handler)
    gw = make_gateway().register(op(path="/items", pagination=Pagination(type="link")))
    first = await gw.call("op", {}, ctx=ctx)
    second = await gw.call("op", {"cursor": first.meta.next_cursor}, ctx=ctx)
    assert second.data == [{"id": 2}]


async def test_page_pagination(make_gateway, mock, ctx):
    def handler(request):
        page = int(request.url.split("page=")[1])
        return [page] * (2 if page < 3 else 1)

    mock.route("GET", f"{BASE}/p", handler)
    gw = make_gateway().register(
        op(path="/p", pagination=Pagination(type="page", param="page", page_size=2))
    )
    seen, cursor = [], None
    for _ in range(5):
        result = await gw.call("op", {"cursor": cursor} if cursor else {}, ctx=ctx)
        seen.extend(result.data)
        cursor = result.meta.next_cursor
        if cursor is None:
            break
    assert seen == [1, 1, 2, 2, 3]


async def test_local_continuation_resumes_without_loss(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/many", [{"id": i, "text": "t" * 50} for i in range(10)])
    gw = make_gateway().register(
        op(
            path="/many",
            output=Output(shape={"id": "id", "text": "text"}, max_items=4, continuation=True),
        )
    )
    ids, cursor = [], None
    while True:
        result = await gw.call("op", {"cursor": cursor} if cursor else {}, ctx=ctx)
        ids.extend(item["id"] for item in result.data)
        cursor = result.meta.next_cursor
        if not cursor:
            break
    assert ids == list(range(10))


async def test_selectable_fields(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/i", {"id": 1, "title": "t", "body": "b"})
    gw = make_gateway().register(
        op(
            path="/i",
            output=Output(
                shape={"id": "id", "title": "title", "body": "body"},
                required=("id",),
                selectable=True,
            ),
        )
    )
    result = await gw.call("op", {"fields": ["title"]}, ctx=ctx)
    assert result.data == {"id": 1, "title": "t"}
    bad = await gw.call("op", {"fields": ["user.password"]}, ctx=ctx)
    assert bad.error and bad.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_rate_limit_per_actor(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/rl", {"ok": True})
    gw = make_gateway().register(op(path="/rl", rate_limit=RateLimit(calls=2, per_seconds=60)))
    assert (await gw.call("op", {}, ctx=ctx)).ok
    assert (await gw.call("op", {}, ctx=ctx)).ok
    third = await gw.call("op", {}, ctx=ctx)
    assert third.error and third.error.code is ErrorCode.RATE_LIMITED


async def test_request_body_limit(make_gateway, ctx):
    service = svc(limits=Limits(max_request_bytes=100))
    gw = make_gateway().register(
        op(
            method="POST",
            effect="write",
            path="/b",
            service=service,
            input={"text": {"type": "string"}},
        )
    )
    result = await gw.call("op", {"text": "x" * 500}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_request_id_provenance(make_gateway, mock, ctx):
    mock.route("GET", f"{BASE}/p", MockResponse(json={"a": 1}, headers={"X-Request-Id": "req-1"}))
    gw = make_gateway().register(op(path="/p"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.meta.source == {
        "service": "example",
        "operation": "op",
        "status": 200,
        "request_id": "req-1",
    }


async def test_missing_credentials_fail_safely(make_gateway, ctx, service):
    gw = make_gateway(credentials=StaticCredentials({})).register(op(path="/x", service=service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INTERNAL_ERROR
    assert SECRET not in result.to_json()


async def test_http_response_passthrough(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/raw",
        lambda r: HttpResponse(
            status=200, headers={"content-type": "application/json"}, body=b'{"x":1}', url=r.url
        ),
    )
    gw = make_gateway().register(op(path="/raw", service=svc(auth=NoAuth())))
    assert (await gw.call("op", {}, ctx=ctx)).data == {"x": 1}


async def test_nested_projection_and_field_limits(make_gateway, mock, ctx):
    mock.route(
        "GET",
        f"{BASE}/n",
        {
            "id": 1,
            "labels": [{"name": "bug"}, {"name": "p1"}, {"name": "ui"}],
            "comments": [{"user": {"login": "a"}, "body": "x" * 100, "secret_note": "hidden"}],
        },
    )
    shape = {
        "id": "id",
        "labels": Field("labels[].name", max_items=2),
        "comments": Field(
            "comments", shape={"author": "user.login", "body": Field("body", max_chars=10)}
        ),
        "first_label": Field("labels", transform="first", shape={"name": "name"}),
    }
    gw = make_gateway().register(op(path="/n", output=Output(shape=shape)))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.data["labels"] == ["bug", "p1"]
    assert result.data["comments"] == [{"author": "a", "body": "x" * 9 + "…"}]
    assert result.data["first_label"] == {"name": "bug"}
    assert "hidden" not in result.to_json()
    reasons = {(o.path, o.reason) for o in result.meta.omitted}
    assert ("labels", "max_items") in reasons
    assert ("comments[].body", "max_chars") in reasons
    assert result.meta.truncated


async def test_effect_write_has_no_cursor(make_gateway, ctx):
    gw = make_gateway().register(
        op(method="POST", path="/w", effect=Effect.WRITE, output=Output(continuation=True))
    )
    schema = gw.definitions(ctx)[0].input_schema
    assert "cursor" not in schema["properties"]
