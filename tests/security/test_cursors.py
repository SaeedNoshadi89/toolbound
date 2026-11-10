"""M1: cursors are encrypted, bound, and never carry credentials."""

from __future__ import annotations

import base64

from toolbound import (
    ApiKeyAuth,
    ErrorCode,
    ExecutionContext,
    MockResponse,
    Operation,
    Output,
    Pagination,
    Service,
    StaticCredentials,
    from_ctx,
)

SVC = Service(name="api", base_url="https://api.example.com")


def _decode(token: str) -> bytes:
    return base64.urlsafe_b64decode(token.split(".", 1)[1] + "==")


async def test_m1_cursor_payload_is_not_readable(make_gateway, mock):
    """The original failure: base64-decoding the cursor revealed the upstream token."""
    mock.route(
        "GET",
        "https://api.example.com/orgs/{org}/items",
        {"items": [{"id": 1}], "next": "SECRET-UPSTREAM-TOKEN-abc"},
    )
    op = Operation(
        name="items",
        description="d",
        service=SVC,
        path="/orgs/{org}/items",
        bind={"org": from_ctx("tenant")},
        pagination=Pagination(type="cursor", param="page_token", next_path="next"),
        output=Output(root="items"),
    )
    gw = make_gateway().register(op)
    ctx = ExecutionContext(actor="a", tenant="acme-internal-id")
    result = await gw.call("items", {}, ctx=ctx)
    cursor = result.meta.next_cursor
    assert cursor.startswith("tbc2.")
    raw = _decode(cursor)
    assert b"SECRET-UPSTREAM-TOKEN" not in raw
    assert b"acme-internal-id" not in raw
    assert b"items" not in raw
    # ...but it still works for the same caller.
    mock.route(
        "GET", "https://api.example.com/orgs/{org}/items", {"items": [{"id": 2}], "next": None}
    )
    second = await gw.call("items", {"cursor": cursor}, ctx=ctx)
    assert second.ok
    assert "page_token=SECRET-UPSTREAM-TOKEN-abc" in mock.requests[-1].url


async def test_m1_tampered_or_legacy_cursor_rejected(make_gateway, mock, ctx):
    mock.route("GET", "https://api.example.com/items", [{"id": 1}])
    op = Operation(
        name="items",
        description="d",
        service=SVC,
        path="/items",
        pagination=Pagination(type="page", param="page"),
    )
    gw = make_gateway().register(op)
    cursor = (await gw.call("items", {}, ctx=ctx)).meta.next_cursor
    head, body = cursor.split(".", 1)
    tampered = f"{head}.{body[:-3]}{'A' if body[-3] != 'A' else 'B'}{body[-2:]}"
    for bad in (tampered, "tbc1.e30.AAAA", "tbc2." + "A" * 40, "tba2." + body):
        result = await gw.call("items", {"cursor": bad}, ctx=ctx)
        assert result.error.code is ErrorCode.INVALID_CURSOR, bad


async def test_m1_query_api_key_never_stored_in_link_cursor(make_gateway, mock, ctx):
    svc = Service(
        name="keyed",
        base_url="https://api.example.com",
        auth=ApiKeyAuth("k", header=None, query="api_key"),
    )
    mock.route(
        "GET",
        "https://api.example.com/items",
        MockResponse(
            200,
            json=[{"id": 1}],
            headers={
                "Link": '<https://api.example.com/items?page=2&api_key=SUPERSECRET1>; rel="next"'
            },
        ),
    )
    op = Operation(
        name="items",
        description="d",
        service=svc,
        path="/items",
        pagination=Pagination(type="link"),
    )
    gw = make_gateway(credentials=StaticCredentials({"k": "SUPERSECRET1"})).register(op)
    result = await gw.call("items", {}, ctx=ctx)
    second = await gw.call("items", {"cursor": result.meta.next_cursor}, ctx=ctx)
    assert second.ok
    assert mock.requests[-1].url.count("api_key=") == 1  # re-added once, from the provider
