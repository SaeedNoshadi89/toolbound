"""``toolbound`` command line: validate contracts and preview tool definitions."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from toolbound.core.budget import ByteEstimator
from toolbound.core.context import ExecutionContext
from toolbound.core.errors import ConfigurationError
from toolbound.core.gateway import Gateway, allow_all
from toolbound.loaders import CONTRACT_SCHEMA


def _gateway(path: str) -> Gateway:
    return Gateway(authorize=allow_all).load(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="toolbound", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate contract files")
    validate.add_argument("path")
    show = sub.add_parser("tools", help="print model-visible tool definitions")
    show.add_argument("path")
    show.add_argument("--format", choices=["anthropic", "openai", "neutral"], default="neutral")
    show.add_argument("--strategy", choices=["direct", "grouped"], default="direct")
    show.add_argument(
        "--scope",
        action="append",
        default=[],
        help="treat the viewer as having this scope (repeatable)",
    )
    sub.add_parser("schema", help="print the JSON Schema of contract files")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(json.dumps(CONTRACT_SCHEMA, indent=2))
        return 0
    try:
        gateway = _gateway(args.path)
    except (ConfigurationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.command == "validate":
        print(f"ok: {len(gateway.tool_names)} tool(s): {', '.join(gateway.tool_names)}")
        return 0
    ctx = ExecutionContext(actor="cli", scopes=frozenset(args.scope))
    if args.format == "anthropic":
        from toolbound.adapters import anthropic

        payload: object = anthropic.tools(gateway, ctx, strategy=args.strategy)
    elif args.format == "openai":
        from toolbound.adapters import openai

        payload = openai.tools(gateway, ctx, strategy=args.strategy)
    else:
        payload = [d.to_dict() for d in gateway.definitions(ctx, strategy=args.strategy)]
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    print(text)
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    print(f"# ~{ByteEstimator().count(compact)} tokens (byte estimate)", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
