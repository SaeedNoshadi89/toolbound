# requires: fastapi
"""FastAPI: a tool-execution API for an agent backend, with human approval on a separate channel.

Two kinds of callers, with different credentials:

* the **agent backend** calls ``POST /tools/{name}`` with an agent API key that acts
  for one user. It gets the model-visible result and, for a destructive call, only an
  opaque ``approval_id``. It never receives the approval token, so the agent (or a
  prompt-injected model) cannot approve its own request;
* the **human** reviews ``GET /approvals`` and decides with ``POST /approvals/{id}``,
  authenticated by a browser session cookie **and** a CSRF token. Agent keys are not
  accepted there. A rejection is recorded with ``gateway.deny()``, so the request can
  never be approved later.

Also shown: the Gateway is created once per app in ``lifespan``; every request builds its
own ``ExecutionContext`` from authentication, never from the body or model output; the
model's tool-call id is passed as ``call_id`` so a write runs at most once.

Run the scripted demo: ``python examples/fastapi_app.py``.
"""

from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import AsyncIterator, Callable, MutableMapping
from contextlib import asynccontextmanager
from typing import Annotated, Any

from _tracker import build_gateway
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from toolbound import ApprovalInvalid, ExecutionContext, Gateway

# Demo identities. In production: verify a JWT / API key for agents, and a real
# session (with CSRF protection) for humans.
USERS = {
    "alice": ("acme", {"issues:read", "issues:write"}),
    "bob": ("globex", {"issues:read"}),
}
AGENT_KEYS = {"agent-key-alice": "alice", "agent-key-bob": "bob"}
SESSIONS = {"session-alice": ("alice", "csrf-alice"), "session-bob": ("bob", "csrf-bob")}


def _context(actor: str) -> ExecutionContext:
    tenant, scopes = USERS[actor]
    return ExecutionContext(
        actor=actor, tenant=tenant, scopes=frozenset(scopes), attributes={"repo": "widgets"}
    )


def agent_context(authorization: Annotated[str | None, Header()] = None) -> ExecutionContext:
    """The agent backend, acting for one user."""
    actor = AGENT_KEYS.get((authorization or "").removeprefix("Bearer ").strip())
    if actor is None:
        raise HTTPException(status_code=401, detail="agent not authenticated")
    return _context(actor)


def human_context(
    session: Annotated[str | None, Cookie()] = None,
    x_csrf_token: Annotated[str | None, Header()] = None,
) -> ExecutionContext:
    """A signed-in human in a browser. Requires the session cookie and its CSRF token."""
    found = SESSIONS.get(session or "")
    if found is None:
        raise HTTPException(status_code=401, detail="sign in to review approvals")
    actor, csrf = found
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, csrf):
        raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
    return _context(actor)


def current_gateway(request: Request) -> Gateway:
    return request.app.state.gateway  # type: ignore[no-any-return]


def pending_store(request: Request) -> MutableMapping[str, dict[str, Any]]:
    return request.app.state.approvals  # type: ignore[no-any-return]


AgentCtx = Annotated[ExecutionContext, Depends(agent_context)]
HumanCtx = Annotated[ExecutionContext, Depends(human_context)]
Gw = Annotated[Gateway, Depends(current_gateway)]
Pending = Annotated[MutableMapping[str, dict[str, Any]], Depends(pending_store)]


class ToolCall(BaseModel):
    arguments: dict[str, Any] = {}
    call_id: str | None = None


class Decision(BaseModel):
    approve: bool


def create_app(
    make_gateway: Callable[[], Gateway] | None = None,
    approvals: MutableMapping[str, dict[str, Any]] | None = None,
) -> FastAPI:
    """``approvals`` stands in for a database table of pending requests."""

    def default_gateway() -> Gateway:
        secret = os.environ.get("TOOLBOUND_SECRET", "").encode() or secrets.token_bytes(32)
        return build_gateway(os.environ.get("TRACKER_URL", "http://127.0.0.1:8001"), secret=secret)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.gateway = (make_gateway or default_gateway)()
        app.state.approvals = approvals if approvals is not None else {}
        async with app.state.gateway:
            yield

    app = FastAPI(title="Toolbound tool API", lifespan=lifespan)

    @app.get("/tools")
    async def list_tools(ctx: AgentCtx, gw: Gw) -> list[dict[str, Any]]:
        """Tool definitions this user may use (send these to the model)."""
        return [
            {"name": d.name, "description": d.description, "input_schema": d.input_schema}
            for d in gw.definitions(ctx)
        ]

    @app.post("/tools/{name}")
    async def call_tool(
        name: str, body: ToolCall, ctx: AgentCtx, gw: Gw, store: Pending
    ) -> dict[str, Any]:
        """Execute one model tool call. ``result`` is what the model may see."""
        result = await gw.call(name, body.arguments, ctx=ctx, call_id=body.call_id)
        response: dict[str, Any] = {"result": result.to_model()}
        if result.approval is not None:
            # The token stays on the server; the agent only learns an opaque id.
            store[result.approval.id] = {
                "token": result.approval.token,
                "actor": ctx.actor,
                "call_id": body.call_id,
            }
            response["approval_id"] = result.approval.id
        return response

    @app.get("/approvals")
    async def my_approvals(ctx: HumanCtx, gw: Gw, store: Pending) -> list[dict[str, Any]]:
        """What the signed-in human is asked to decide: exactly what would run."""
        shown = []
        for approval_id, item in list(store.items()):
            if item["actor"] != ctx.actor:
                continue
            try:
                pending = gw.pending_approval(item["token"])
            except ApprovalInvalid:  # expired
                store.pop(approval_id, None)
                continue
            view = pending.to_dict()
            view.pop("token")
            shown.append(view)
        return shown

    @app.post("/approvals/{approval_id}")
    async def decide(
        approval_id: str, body: Decision, ctx: HumanCtx, gw: Gw, store: Pending
    ) -> dict[str, Any]:
        item = store.get(approval_id)
        if item is None or item["actor"] != ctx.actor:
            raise HTTPException(status_code=404, detail="no such approval")
        store.pop(approval_id)
        if not body.approve:
            await gw.deny(item["token"])  # can never be approved afterwards
            return {"result": {"ok": False, "error": {"code": "approval_denied"}}}
        result = await gw.resume(
            item["token"], ctx=ctx, approved_by=ctx.actor, call_id=item["call_id"]
        )
        return {"result": result.to_model()}

    return app


app = create_app()


def demo() -> None:
    from _demo_api import run_demo_api
    from fastapi.testclient import TestClient

    agent = {"Authorization": "Bearer agent-key-alice"}
    alice = {"X-CSRF-Token": "csrf-alice"}
    with run_demo_api() as base_url:
        demo_app = create_app(lambda: build_gateway(base_url, secret=secrets.token_bytes(32)))
        with TestClient(demo_app) as client:
            names = [t["name"] for t in client.get("/tools", headers=agent).json()]
            print("tools the model gets for alice:", names)
            listed = client.post("/tools/list_issues", json={}, headers=agent).json()
            print("list_issues:", listed["result"]["data"][:2])

            first = client.post(
                "/tools/delete_comment",
                json={"arguments": {"comment_id": 7}, "call_id": "toolu_1"},
                headers=agent,
            ).json()
            print("model sees:", first["result"]["error"]["code"], "| agent gets only an id")
            approval_id = first["approval_id"]

            agent_try = client.post(
                f"/approvals/{approval_id}", json={"approve": True}, headers=agent
            )
            print("agent tries to approve itself:", agent_try.status_code)

            client.cookies.set("session", "session-alice")
            shown = client.get("/approvals", headers=alice).json()
            print("alice is asked:", shown[0]["summary"])
            done = client.post(f"/approvals/{approval_id}", json={"approve": True}, headers=alice)
            print("alice approves:", done.json()["result"]["ok"])


if __name__ == "__main__":
    demo()
