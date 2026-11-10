"""Architecture rules: the core stays framework- and transport-neutral."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

CORE = Path(__file__).parents[1] / "src" / "toolbound" / "core"
FORBIDDEN = {
    "httpx",
    "anthropic",
    "openai",
    "mcp",
    "langchain",
    "langchain_core",
    "langgraph",
    "yaml",
    "tiktoken",
    "requests",
    "aiohttp",
    "pydantic",
}
# Lazy, function-level imports of sibling adapters used only for default wiring.
ALLOWED_LAZY = {"toolbound.transport.http", "toolbound.loaders"}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node, alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node, node.module


def test_core_has_no_framework_or_http_imports():
    offenders = []
    for path in CORE.glob("*.py"):
        top_level = set(ast.parse(path.read_text(encoding="utf-8")).body)
        for node, module in _imports(path):
            root = module.split(".")[0]
            if root in FORBIDDEN:
                offenders.append(f"{path.name}: {module}")
            external = module.startswith("toolbound.") and not module.startswith("toolbound.core")
            if external and (node in top_level or module not in ALLOWED_LAZY):
                offenders.append(f"{path.name}: top-level import of {module}")
    assert offenders == []


def test_core_imports_without_httpx_installed():
    code = (
        "import sys; sys.modules['httpx'] = None\n"
        "from toolbound.core.gateway import Gateway, allow_all\n"
        "from toolbound.core.shaping import process\n"
        "from toolbound.adapters import anthropic, openai\n"
        "print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_adapters_do_not_import_provider_sdks():
    adapters = Path(__file__).parents[1] / "src" / "toolbound" / "adapters"
    for path in adapters.glob("*.py"):
        for _, module in _imports(path):
            assert module.split(".")[0] not in {"anthropic", "openai", "mcp", "langchain"}, path
