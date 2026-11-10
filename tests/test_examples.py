"""Run the examples (offline ones always; network ones when enabled) and check the README."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EXAMPLES = sorted(p for p in (ROOT / "examples").glob("*.py") if not p.name.startswith("_"))


def _requirement(path: Path) -> str:
    match = re.match(r"# requires: (\w+)", path.read_text())
    return match.group(1) if match else "offline"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_runs(path):
    requirement = _requirement(path)
    if requirement == "network" and os.environ.get("TOOLBOUND_NETWORK_TESTS") != "1":
        pytest.skip("network example; set TOOLBOUND_NETWORK_TESTS=1")
    if requirement == "anthropic":
        pytest.skip("calls the paid Anthropic API; run manually")
    out = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=ROOT,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "Traceback" not in out.stderr


def test_examples_compile():
    for path in (ROOT / "examples").glob("*.py"):
        compile(path.read_text(), str(path), "exec")


def test_readme_quickstart_matches_example():
    readme = (ROOT / "README.md").read_text()
    quickstart = (ROOT / "examples" / "quickstart.py").read_text()
    body = quickstart.split('"""', 2)[2].strip()
    assert body in readme, "README quickstart drifted from examples/quickstart.py"


def _block(text: str, after: str, lang: str) -> str:
    start = text.index(f"```{lang}\n", text.index(after)) + len(lang) + 4
    return text[start : text.index("```", start)]


def test_readme_complete_example_runs(tmp_path, monkeypatch, capsys):
    from toolbound import MockTransport
    from toolbound.transport.mock import MockResponse

    readme = (ROOT / "README.md").read_text()
    yaml_text = _block(readme, "## A complete example", "yaml")
    code = _block(readme, "…or in Python", "python")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "crm.yaml").write_text(yaml_text)
    monkeypatch.setenv("CRM_API_TOKEN", "crm-secret-token-value")

    mock = MockTransport()
    mock.route(
        "GET",
        "https://crm.example.com/api/tenants/acme/customers",
        {
            "data": [
                {
                    "id": "cus_1",
                    "full_name": "Ada",
                    "contact": {"email": "ada@example.com"},
                    "subscription": {"plan": {"name": "pro"}},
                    "tickets": [1, 2],
                    "ssn": "x",
                }
            ]
        },
    )
    mock.route(
        "DELETE", "https://crm.example.com/api/tenants/acme/customers/{id}", MockResponse(204)
    )
    patched = code.replace("gateway = Gateway(\n", "gateway = Gateway(\n        transport=mock,\n")
    patched = patched.replace(
        'gateway.load("contracts/")', f'gateway.load(r"{tmp_path / "contracts"}")'
    )
    assert patched != code
    exec(compile(patched, "README.md", "exec"), {"mock": mock, "__name__": "readme"})
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("[{'id': 'cus_1', 'name': 'Ada'")
    assert "'open_tickets': 2" in out[0] and "ssn" not in out[0]
    assert out[1:] == ["invalid_arguments", "approval_required", "True"]
    assert ("Authorization", "Bearer crm-secret-token-value") in mock.requests[0].headers
    assert mock.requests[-1].method == "DELETE"
