# requires: offline
"""Unsafe requests that Toolbound refuses, and why. Runs against a local demo API."""

import asyncio

from _demo_api import run_demo_api

from toolbound import (
    ExecutionContext,
    Gateway,
    NetworkPolicy,
    Operation,
    Output,
    Service,
    allow_all,
)


def build(base_url: str, port: int) -> list[Operation]:
    trusted = Service(  # an internal service, explicitly trusted
        name="tracker",
        base_url=base_url,
        network=NetworkPolicy(
            allow_http=True,
            allow_hosts=("127.0.0.1",),
            allow_ports=(port,),
            allow_networks=("127.0.0.1/32",),
            follow_redirects=True,
        ),
    )
    untrusted = Service(  # same address, but without explicit trust
        name="untrusted",
        base_url=base_url,
        network=NetworkPolicy(allow_http=True, allow_hosts=("127.0.0.1",), allow_ports=(port,)),
    )
    shape = Output(shape={"number": "number", "title": "title"})
    return [
        Operation(
            name="get_issue",
            description="Get an issue.",
            service=trusted,
            path="/repos/{owner}/{repo}/issues/{number}",
            input={"number": {"type": "integer"}},
            bind={"owner": "ctx.tenant", "repo": "ctx.attributes.repo"},
            output=shape,
        ),
        Operation(
            name="follow_moved",
            description="Fetch a moved resource.",
            service=trusted,
            path="/moved",
        ),
        Operation(
            name="untrusted_get",
            description="Same API without trust.",
            service=untrusted,
            path="/repos/acme/widgets/issues/1",
            output=shape,
        ),
    ]


async def main() -> None:
    ctx = ExecutionContext(actor="alice", tenant="acme", attributes={"repo": "widgets"})
    with run_demo_api() as base_url:
        port = int(base_url.rsplit(":", 1)[1])
        async with Gateway(authorize=allow_all).register(*build(base_url, port)) as gw:
            attempts = [
                ("normal request", "get_issue", {"number": 7}),
                ("model adds a URL", "get_issue", {"number": 7, "url": "http://evil.example"}),
                ("model forges tenant", "get_issue", {"number": 7, "owner": "other-tenant"}),
                ("type confusion", "get_issue", {"number": "7; DROP TABLE"}),
                ("redirect to cloud metadata", "follow_moved", {}),
                ("private address not trusted", "untrusted_get", {}),
                ("tool that does not exist", "delete_everything", {}),
            ]
            for label, tool, args in attempts:
                result = await gw.call(tool, args, ctx=ctx)
                outcome = "OK     " if result.ok else "BLOCKED"
                detail = result.data if result.ok else result.error.to_dict()
                print(f"{outcome} {label:28} -> {detail}")


if __name__ == "__main__":
    asyncio.run(main())
