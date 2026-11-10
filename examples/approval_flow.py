# requires: offline
"""Destructive actions need a human approval bound to the exact call."""

import asyncio

from _demo_api import run_demo_api

from toolbound import ExecutionContext, Gateway, NetworkPolicy, Operation, Service, allow_all


async def main() -> None:
    with run_demo_api() as base_url:
        port = int(base_url.rsplit(":", 1)[1])
        tracker = Service(
            name="tracker",
            base_url=base_url,
            network=NetworkPolicy(
                allow_http=True,
                allow_hosts=("127.0.0.1",),
                allow_ports=(port,),
                allow_networks=("127.0.0.1/32",),
            ),
        )
        delete_comment = Operation(
            name="delete_comment",
            description="Delete an issue comment permanently.",
            service=tracker,
            method="DELETE",
            effect="destructive",
            path="/repos/acme/widgets/issues/comments/{comment_id}",
            input={"comment_id": {"type": "integer", "minimum": 1}},
            idempotency_header="Idempotency-Key",
        )
        ctx = ExecutionContext(actor="alice", tenant="acme")
        async with Gateway(authorize=allow_all, secret=b"x" * 32).register(delete_comment) as gw:
            # 1. The model asks to delete. Nothing is sent upstream yet.
            first = await gw.call("delete_comment", {"comment_id": 42}, ctx=ctx, call_id="toolu_01")
            print("model sees:", first.to_json())
            pending = first.approval
            print("host shows the user:", pending.summary)

            # 2. The user approves in your UI; host code issues a single-use grant.
            grant = gw.grant(pending, approved_by="alice")
            done = await gw.call(
                "delete_comment", {"comment_id": 42}, ctx=ctx, call_id="toolu_01", approval=grant
            )
            print("after approval:", done.to_json())

            # 3. Replaying the grant, or reusing it for different arguments, fails.
            replay = await gw.call("delete_comment", {"comment_id": 42}, ctx=ctx, approval=grant)
            print("replay:", replay.error.to_dict())
            pending2 = (await gw.call("delete_comment", {"comment_id": 1}, ctx=ctx)).approval
            swapped = await gw.call(
                "delete_comment",
                {"comment_id": 2},
                ctx=ctx,
                approval=gw.grant(pending2, approved_by="alice"),
            )
            print("swapped arguments:", swapped.error.to_dict())


if __name__ == "__main__":
    asyncio.run(main())
