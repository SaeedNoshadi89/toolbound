"""The FastAPI example: auth-derived context, human-only approvals, isolation."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from .conftest import BASE, deletes

pytestmark = pytest.mark.security

AGENT_ALICE = {"Authorization": "Bearer agent-key-alice"}
AGENT_BOB = {"Authorization": "Bearer agent-key-bob"}
CSRF_ALICE = {"X-CSRF-Token": "csrf-alice"}
CSRF_BOB = {"X-CSRF-Token": "csrf-bob"}


def _app(upstream, approvals=None):
    from _tracker import build_gateway
    from fastapi_app import create_app

    return create_app(
        lambda: build_gateway(BASE, secret=b"s" * 32, transport=upstream), approvals=approvals
    )


@pytest.fixture
def client(upstream):
    with TestClient(_app(upstream)) as test_client:
        yield test_client


def _delete(client, headers=AGENT_ALICE, call_id="toolu_1", comment_id=7):
    return client.post(
        "/tools/delete_comment",
        json={"arguments": {"comment_id": comment_id}, "call_id": call_id},
        headers=headers,
    ).json()


def _decide(client, approval_id, approve=True, session="session-alice", headers=CSRF_ALICE):
    client.cookies.set("session", session)
    try:
        return client.post(f"/approvals/{approval_id}", json={"approve": approve}, headers=headers)
    finally:
        client.cookies.clear()


def test_requires_authentication(client):
    assert client.get("/tools").status_code == 401
    assert client.post("/tools/list_issues", json={}).status_code == 401


def test_tools_follow_scopes(client):
    def names(h):
        return [t["name"] for t in client.get("/tools", headers=h).json()]

    assert names(AGENT_ALICE) == ["list_issues", "delete_comment"]
    assert names(AGENT_BOB) == ["list_issues"]
    assert _delete(client, AGENT_BOB)["result"]["error"]["code"] == "unknown_tool"


def test_tenant_comes_from_auth_not_body(client, upstream):
    body = {"arguments": {"owner": "globex"}}
    forged = client.post("/tools/list_issues", json=body, headers=AGENT_ALICE).json()
    assert forged["result"]["error"]["code"] == "invalid_arguments"
    client.post("/tools/list_issues", json={}, headers=AGENT_ALICE)
    client.post("/tools/list_issues", json={}, headers=AGENT_BOB)
    paths = [r.url.split("?")[0] for r in upstream.requests]
    assert paths == [BASE + "/repos/acme/widgets/issues", BASE + "/repos/globex/widgets/issues"]


def test_agent_never_receives_the_approval_token(client):
    first = _delete(client)
    assert first["result"]["error"]["code"] == "approval_required"
    assert set(first) == {"result", "approval_id"}
    assert "tbr1." not in str(first)


def test_agent_cannot_approve_its_own_request(client, upstream):
    approval_id = _delete(client)["approval_id"]
    as_agent = client.post(f"/approvals/{approval_id}", json={"approve": True}, headers=AGENT_ALICE)
    assert as_agent.status_code == 401
    assert deletes(upstream) == []


def test_csrf_token_required(client, upstream):
    approval_id = _delete(client)["approval_id"]
    assert _decide(client, approval_id, headers={}).status_code == 403
    assert _decide(client, approval_id, headers=CSRF_BOB).status_code == 403
    assert deletes(upstream) == []


def test_human_approval_runs_exactly_once(client, upstream):
    approval_id = _delete(client)["approval_id"]
    client.cookies.set("session", "session-alice")
    shown = client.get("/approvals", headers=CSRF_ALICE).json()
    client.cookies.clear()
    assert shown[0]["target"]["url"].endswith("/repos/acme/widgets/issues/comments/7")
    assert "token" not in shown[0]
    done = _decide(client, approval_id).json()
    assert done["result"]["ok"] is True
    assert _decide(client, approval_id).status_code == 404  # gone after use
    assert len(deletes(upstream)) == 1


def test_other_user_cannot_see_or_approve(client, upstream):
    approval_id = _delete(client)["approval_id"]
    client.cookies.set("session", "session-bob")
    assert client.get("/approvals", headers=CSRF_BOB).json() == []
    client.cookies.clear()
    assert _decide(client, approval_id, session="session-bob", headers=CSRF_BOB).status_code == 404
    assert deletes(upstream) == []


def test_rejection_is_final(upstream):
    """A rejected token can never be granted, even if someone kept a copy."""
    store: dict = {}
    with TestClient(_app(upstream, store)) as client:
        approval_id = _delete(client)["approval_id"]
        token = store[approval_id]["token"]
        _decide(client, approval_id, approve=False)
        gateway = client.app.state.gateway
        from toolbound import ExecutionContext

        ctx = ExecutionContext(
            actor="alice",
            tenant="acme",
            scopes=frozenset({"issues:write"}),
            attributes={"repo": "widgets"},
        )
        result = client.portal.call(
            lambda: gateway.resume(token, ctx=ctx, approved_by="alice", call_id="other")
        )
        assert result.error.code.value == "approval_invalid"
    assert deletes(upstream) == []


def test_pending_approvals_survive_restart_and_new_event_loops(upstream):
    """Each TestClient runs its own loop and lifespan; tokens survive via secret=."""
    store: dict = {}
    with TestClient(_app(upstream, store)) as first:
        approval_id = _delete(first)["approval_id"]
    with TestClient(_app(upstream, store)) as second:  # "after a restart"
        assert _decide(second, approval_id).json()["result"]["ok"] is True
    assert len(deletes(upstream)) == 1
