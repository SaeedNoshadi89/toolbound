from __future__ import annotations

import json

from toolbound import Operation, Output, from_ctx

from .conftest import SECRET


def issue_op(service, **kw):
    defaults = {
        "name": "get_issue",
        "description": "Get one issue from the current repository.",
        "service": service,
        "path": "/repos/{owner}/{repo}/issues/{issue_number}",
        "input": {"issue_number": {"type": "integer", "minimum": 1}},
        "bind": {
            "owner": from_ctx("attributes.repo_owner"),
            "repo": from_ctx("attributes.repo_name"),
        },
        "output": Output(
            shape={"number": "number", "title": "title", "author": "user.login"},
            required=("number", "title"),
        ),
    }
    defaults.update(kw)
    return Operation(**defaults)


async def test_get_issue(make_gateway, mock, service, ctx):
    mock.route(
        "GET",
        "https://api.github.com/repos/acme/widgets/issues/{n}",
        {
            "number": 42,
            "title": "Bug",
            "user": {"login": "bob"},
            "body": "x" * 9000,
            "token": SECRET,
        },
    )
    gw = make_gateway().register(issue_op(service))
    result = await gw.call("get_issue", {"issue_number": 42}, ctx=ctx)
    assert result.ok, result.error
    assert result.data == {"number": 42, "title": "Bug", "author": "bob"}
    sent = mock.requests[0]
    assert sent.url == "https://api.github.com/repos/acme/widgets/issues/42"
    assert ("Authorization", f"Bearer {SECRET}") in sent.headers
    assert SECRET not in result.to_json()
    assert json.loads(result.to_json())["ok"] is True
