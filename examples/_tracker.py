"""Shared tool contracts for the FastAPI and LangGraph examples.

An issue tracker with one read tool and one destructive tool. The repository
owner comes from the tenant and the repository name from the trusted session,
so a model can never point a call at another customer's data.
"""

from __future__ import annotations

from toolbound import (
    AuthorizationRequest,
    Decision,
    Gateway,
    NetworkPolicy,
    Operation,
    Output,
    Service,
    Transport,
    from_ctx,
)


def tracker_service(base_url: str) -> Service:
    port = int(base_url.rsplit(":", 1)[1]) if base_url.count(":") == 2 else 443
    local = base_url.startswith("http://127.0.0.1")
    return Service(
        name="tracker",
        base_url=base_url,
        network=NetworkPolicy(
            allow_http=local,
            allow_ports=(port,),
            allow_networks=("127.0.0.1/32",) if local else (),
        ),
    )


def tracker_tools(base_url: str) -> list[Operation]:
    svc = tracker_service(base_url)
    repo = {"owner": from_ctx("tenant"), "repo": from_ctx("attributes.repo")}
    return [
        Operation(
            name="list_issues",
            description="List issues in the current repository.",
            service=svc,
            path="/repos/{owner}/{repo}/issues",
            bind=repo,
            input={"per_page": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5}},
            output=Output(
                shape={"number": "number", "title": "title", "state": "state"},
                required=("number",),
                max_tokens=600,
            ),
            required_scopes=("issues:read",),
        ),
        Operation(
            name="delete_comment",
            description="Delete an issue comment permanently.",
            service=svc,
            method="DELETE",  # effect inferred: destructive, so it needs human approval
            path="/repos/{owner}/{repo}/issues/comments/{comment_id}",
            bind=repo,
            input={"comment_id": {"type": "integer", "minimum": 1}},
            idempotency_header="Idempotency-Key",
            required_scopes=("issues:write",),
        ),
    ]


def policy(request: AuthorizationRequest) -> Decision:
    """Business rule beyond scopes: suspended users may only read."""
    if request.ctx.attributes.get("suspended") and request.tool.effect.value != "read":
        return Decision.deny("your account is suspended")
    return Decision.allow()


def build_gateway(base_url: str, *, secret: bytes, transport: Transport | None = None) -> Gateway:
    return Gateway(authorize=policy, secret=secret, transport=transport).register(
        *tracker_tools(base_url)
    )
