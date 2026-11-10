"""Integration tests import the example apps from ``examples/``."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from toolbound import MockResponse, MockTransport

EXAMPLES = Path(__file__).parents[2] / "examples"
if str(EXAMPLES) not in sys.path:
    sys.path.insert(0, str(EXAMPLES))

BASE = "https://tracker.example.com"


@pytest.fixture
def upstream() -> MockTransport:
    mock = MockTransport()
    mock.route(
        "GET",
        BASE + "/repos/{owner}/{repo}/issues",
        lambda request: [{"number": 1, "title": request.url.split("/")[4], "state": "open"}],
    )
    mock.route("DELETE", BASE + "/repos/{owner}/{repo}/issues/comments/{id}", MockResponse(204))
    return mock


def deletes(mock: MockTransport) -> list[str]:
    return [r.url for r in mock.requests if r.method == "DELETE"]
