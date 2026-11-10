# requires: network
"""Two unrelated public APIs from declarative contracts, no core changes needed."""

import asyncio
from pathlib import Path

from toolbound import ExecutionContext, Gateway, allow_all
from toolbound.adapters import anthropic

CONTRACTS = Path(__file__).parent / "contracts"


async def main() -> None:
    ctx = ExecutionContext(actor="demo", attributes={"owner": "python", "repo": "cpython"})
    async with Gateway(authorize=allow_all).load(CONTRACTS) as gateway:
        print("tools:", [t["name"] for t in anthropic.tools(gateway, ctx)])
        print("grouped:", [t["name"] for t in anthropic.tools(gateway, ctx, strategy="grouped")])

        weather = await gateway.call(
            "current_weather", {"latitude": 35.7, "longitude": 51.4}, ctx=ctx
        )
        print(weather.to_json())

        issues = await gateway.call("list_issues", {"per_page": 3, "state": "closed"}, ctx=ctx)
        print(issues.to_json()[:600])
        if issues.meta.next_cursor:
            more = await gateway.call(
                "list_issues",
                {"per_page": 3, "state": "closed", "cursor": issues.meta.next_cursor},
                ctx=ctx,
            )
            print("next page:", [i["number"] for i in more.data])


if __name__ == "__main__":
    asyncio.run(main())
