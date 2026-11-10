# requires: offline
"""Evidence-preserving retrieval of Persian court rulings (domain logic lives here, not in
the library). Citation ids are required fields: they are never dropped to save tokens."""

import asyncio

from _demo_api import run_demo_api

from toolbound import (
    ExecutionContext,
    Field,
    Gateway,
    NetworkPolicy,
    Operation,
    Output,
    Service,
    allow_all,
)


async def main() -> None:
    with run_demo_api() as base_url:
        port = int(base_url.rsplit(":", 1)[1])
        legal = Service(
            name="rulings",
            base_url=base_url,
            network=NetworkPolicy(
                allow_http=True,
                allow_hosts=("127.0.0.1",),
                allow_ports=(port,),
                allow_networks=("127.0.0.1/32",),
            ),
        )
        output = Output(
            root="results",
            shape={
                "doc_id": "doc_id",  # citation id: required
                "court": "court",
                "date": "date",
                "title": "title",
                "excerpt": Field("text", max_chars=400),
            },
            required=("doc_id", "date"),
            max_items=10,
            max_tokens=900,
            continuation=True,
        )
        search = Operation(
            name="search_rulings",
            description="Search court rulings (Persian).",
            service=legal,
            path="/legal/search",
            input={"q": {"type": "string", "minLength": 2, "maxLength": 80}},
            output=output,
        )
        strict = Operation(
            name="search_rulings_strict",
            description="Search; refuse rather than truncate.",
            service=legal,
            path="/legal/search",
            input={"q": {"type": "string", "minLength": 2, "maxLength": 80}},
            output=Output(
                root="results",
                shape={"doc_id": "doc_id", "text": "text"},
                required=("doc_id",),
                overflow="reject",
                max_tokens=900,
                max_chars=20000,
            ),
        )
        ctx = ExecutionContext(actor="lawyer-1")
        async with Gateway(authorize=allow_all).register(search, strict) as gw:
            result = await gw.call("search_rulings", {"q": "اجاره"}, ctx=ctx)
            print("returned:", [d["doc_id"] for d in result.data])
            print("meta:", result.meta.to_dict())
            print("the internal reviewer email never appears:", "reviewer@" not in result.to_json())
            refused = await gw.call("search_rulings_strict", {"q": "اجاره"}, ctx=ctx)
            print("strict mode:", refused.error.to_dict())


if __name__ == "__main__":
    asyncio.run(main())
