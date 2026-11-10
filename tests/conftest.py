from __future__ import annotations

import pytest

from toolbound import (
    BearerAuth,
    ExecutionContext,
    Gateway,
    MockTransport,
    Service,
    StaticCredentials,
    allow_all,
)

SECRET = "ghp_" + "A" * 36  # looks like a GitHub token so pattern redaction also applies
HMAC_KEY = b"k" * 32


@pytest.fixture
def ctx() -> ExecutionContext:
    return ExecutionContext(
        actor="alice",
        tenant="acme",
        scopes=frozenset({"issues:read"}),
        attributes={"repo_owner": "acme", "repo_name": "widgets"},
    )


@pytest.fixture
def mock() -> MockTransport:
    return MockTransport()


@pytest.fixture
def service() -> Service:
    return Service(
        name="github",
        base_url="https://api.github.com",
        auth=BearerAuth("github_token"),
    )


async def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def make_gateway(mock: MockTransport):
    def factory(**kwargs):
        kwargs.setdefault("authorize", allow_all)
        kwargs.setdefault("credentials", StaticCredentials({"github_token": SECRET}))
        kwargs.setdefault("transport", mock)
        kwargs.setdefault("secret", HMAC_KEY)
        kwargs.setdefault("sleep", _no_sleep)
        return Gateway(**kwargs)

    return factory
