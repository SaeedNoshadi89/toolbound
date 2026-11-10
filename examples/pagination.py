# requires: offline
"""Upstream Link-header pagination plus token budgets, with opaque signed cursors."""

import asyncio

from _demo_api import run_demo_api

from toolbound import (
    ExecutionContext,
    Gateway,
    NetworkPolicy,
    Operation,
    Output,
    Pagination,
    Service,
    allow_all,
)


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
        list_issues = Operation(
            name="list_issues",
            description="List issues, 25 per upstream page.",
            service=tracker,
            path="/repos/acme/widgets/issues",
            input={"per_page": {"const": 25, "default": 25}},
            pagination=Pagination(type="link"),
            output=Output(
                shape={"number": "number", "title": "title"}, required=("number",), max_tokens=400
            ),
        )
        ctx = ExecutionContext(actor="alice")
        async with Gateway(authorize=allow_all).register(list_issues) as gw:
            cursor, calls, numbers = None, 0, []
            while True:
                result = await gw.call("list_issues", {"cursor": cursor} if cursor else {}, ctx=ctx)
                calls += 1
                numbers.extend(item["number"] for item in result.data)
                print(
                    f"call {calls}: {len(result.data)} items, ~{result.meta.estimated_tokens} "
                    f"tokens, omitted={[o.to_dict() for o in result.meta.omitted]}"
                )
                cursor = result.meta.next_cursor
                if not cursor:
                    break
            assert numbers == list(range(1, 61)), "every issue exactly once, in order"
            print(f"all {len(numbers)} issues retrieved in {calls} budgeted calls, none lost")

            tampered = cursor or result.meta.next_cursor or "tbc2.AAAA"
            bad = await gw.call("list_issues", {"cursor": tampered[:-2] + "xx"}, ctx=ctx)
            print("tampered cursor:", bad.error.to_dict() if bad.error else bad.data)


if __name__ == "__main__":
    asyncio.run(main())
