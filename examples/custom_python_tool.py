# requires: offline
"""A trusted Python function as a tool: same validation, policy, approval and budgets.

Toolbound does NOT sandbox this code; it runs with your application's privileges.
"""

import asyncio
from typing import Annotated, Literal

from toolbound import Decision, ExecutionContext, Gateway, Output

ORDERS = [
    {
        "order_id": f"SO-{i:04d}",
        "tenant": "acme" if i % 2 else "globex",
        "status": s,
        "total_cents": 1000 + i * 37,
        "customer_email": f"buyer{i}@example.com",
        "notes": "Deliver to the loading dock on the north side. " * 5,
    }
    for i, s in enumerate(["paid", "shipped", "refunded", "paid"] * 10)
]


def policy(request) -> bool | Decision:
    # Business rule from trusted code: support agents cannot see refunds.
    refunds = request.tool.name == "search_orders" and request.arguments.get("status") == "refunded"
    if refunds and "finance" not in request.ctx.scopes:
        return Decision.deny("refunded orders are visible to finance only")
    return True


gateway = Gateway(authorize=policy)


@gateway.tool(
    effect="read",
    bind={"tenant": "ctx.tenant"},  # tenant comes from the session, never from the model
    output=Output(
        shape={
            "order_id": "order_id",
            "status": "status",
            "total_cents": "total_cents",
            "notes": "notes",
        },
        required=("order_id",),
        max_items=50,
        max_tokens=250,
        continuation=True,
    ),
)
def search_orders(
    tenant: str,
    status: Literal["paid", "shipped", "refunded"] | None = None,
    limit: Annotated[int, "Maximum orders", {"minimum": 1, "maximum": 100}] = 20,
) -> list[dict]:
    """Search orders of the current customer account."""
    rows = [
        o for o in ORDERS if o["tenant"] == tenant and (status is None or o["status"] == status)
    ]
    return rows[:limit]


async def main() -> None:
    support = ExecutionContext(actor="agent-7", tenant="acme", scopes=frozenset({"support"}))
    print(gateway.definitions(support)[0].input_schema)

    page = await gateway.call("search_orders", {"status": "paid"}, ctx=support)
    print("first page:", [o["order_id"] for o in page.data], page.meta.to_dict()["omitted"])
    more = await gateway.call(
        "search_orders", {"status": "paid", "cursor": page.meta.next_cursor}, ctx=support
    )
    print("next page:", [o["order_id"] for o in more.data])

    denied = await gateway.call("search_orders", {"status": "refunded"}, ctx=support)
    print("denied:", denied.error.to_dict())
    forged = await gateway.call("search_orders", {"tenant": "globex"}, ctx=support)
    print("forged tenant:", forged.error.to_dict())


if __name__ == "__main__":
    asyncio.run(main())
