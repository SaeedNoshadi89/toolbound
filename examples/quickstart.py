# requires: network
"""Quickstart: one safe, shaped tool over the public GitHub REST API (no token needed)."""

import asyncio

from toolbound import ExecutionContext, Gateway, Operation, Output, Service, allow_all, from_ctx

github = Service(
    name="github",
    base_url="https://api.github.com",
    headers={"Accept": "application/vnd.github+json"},
)

get_issue = Operation(
    name="get_issue",
    description="Get one issue from the current repository by number.",
    service=github,
    path="/repos/{owner}/{repo}/issues/{issue_number}",
    input={"issue_number": {"type": "integer", "minimum": 1}},  # all the model can set
    bind={"owner": from_ctx("attributes.owner"), "repo": from_ctx("attributes.repo")},
    output=Output(
        shape={
            "number": "number",
            "title": "title",
            "state": "state",
            "author": "user.login",
            "labels": "labels[].name",
        },
        required=("number", "title"),
        max_tokens=300,
    ),
)


async def main() -> None:
    ctx = ExecutionContext(actor="demo-user", attributes={"owner": "python", "repo": "cpython"})
    async with Gateway(authorize=allow_all).register(get_issue) as gateway:
        print(gateway.definitions(ctx)[0].input_schema)  # what the model sees

        ok = await gateway.call("get_issue", {"issue_number": 1}, ctx=ctx)
        print(ok.to_json())  # {"ok":true,"data":{"number":1,"title":...},"meta":{...}}

        blocked = await gateway.call(
            "get_issue", {"issue_number": 1, "url": "http://169.254.169.254/"}, ctx=ctx
        )
        print(blocked.to_json())  # {"ok":false,"error":{"code":"invalid_arguments",...}}


if __name__ == "__main__":
    asyncio.run(main())
