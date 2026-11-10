"""Adapters, grouped exposure, YAML/JSON loader, CLI, sync wrapper."""

from __future__ import annotations

import json
import textwrap
from types import SimpleNamespace

import pytest

from toolbound import ConfigurationError, ErrorCode, Gateway, Operation, Service, allow_all
from toolbound.adapters import anthropic as tb_anthropic
from toolbound.adapters import openai as tb_openai
from toolbound.cli import main as cli_main
from toolbound.loaders import load_contracts, parse_contract
from toolbound.sync import SyncGateway

SERVICE = Service(name="s", base_url="https://api.example.com")


def ops():
    return [
        Operation(
            name="get_item",
            description="Get an item.",
            service=SERVICE,
            path="/items/{id}",
            input={"id": {"type": "integer"}},
            group="items",
        ),
        Operation(
            name="list_items",
            description="List items.",
            service=SERVICE,
            path="/items",
            input={"q": {"type": "string", "default": ""}},
            group="items",
        ),
        Operation(name="ping", description="Ping.", service=SERVICE, path="/ping"),
    ]


@pytest.fixture
def gw(make_gateway, mock):
    mock.route("GET", "https://api.example.com/items/{id}", lambda r: {"id": r.url.rsplit("/")[-1]})
    mock.route("GET", "https://api.example.com/ping", {"pong": True})
    return make_gateway().register(*ops())


def test_anthropic_definitions_match_core(gw, ctx):
    tools = tb_anthropic.tools(gw, ctx)
    core = gw.definitions(ctx)
    assert [t["name"] for t in tools] == [d.name for d in core]
    assert tools[0]["input_schema"] == core[0].input_schema
    assert set(tools[0]) == {"name", "description", "input_schema"}


def test_openai_definitions(gw, ctx):
    chat = tb_openai.tools(gw, ctx)
    responses = tb_openai.tools(gw, ctx, api="responses")
    assert chat[0] == {
        "type": "function",
        "function": {
            "name": "get_item",
            "description": "Get an item.",
            "parameters": gw.definitions(ctx)[0].input_schema,
        },
    }
    assert responses[0]["name"] == "get_item" and "parameters" in responses[0]


async def test_anthropic_run_tool_calls_with_objects_and_dicts(gw, ctx):
    message = SimpleNamespace(
        content=[
            SimpleNamespace(type="text", text="calling"),
            SimpleNamespace(type="tool_use", id="toolu_1", name="get_item", input={"id": 3}),
            {"type": "tool_use", "id": "toolu_2", "name": "nope", "input": {}},
        ]
    )
    batch = await tb_anthropic.run_tool_calls(gw, message, ctx)
    assert batch.message["role"] == "user"
    first, second = batch.message["content"]
    assert first["tool_use_id"] == "toolu_1" and "is_error" not in first
    assert json.loads(first["content"])["data"] == {"id": "3"}
    assert second["is_error"] is True
    assert json.loads(second["content"])["error"]["code"] == "unknown_tool"


async def test_openai_chat_and_responses_calls(gw, ctx):
    chat = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "get_item", "arguments": '{"id": 1}'}},
                        {"id": "c2", "function": {"name": "get_item", "arguments": "{not json"}},
                    ]
                }
            }
        ]
    }
    batch = await tb_openai.run_tool_calls(gw, chat, ctx)
    assert [b["tool_call_id"] for b in batch.blocks] == ["c1", "c2"]
    assert json.loads(batch.blocks[1]["content"])["error"]["code"] == "invalid_arguments"
    responses = SimpleNamespace(
        output=[
            SimpleNamespace(type="reasoning"),
            SimpleNamespace(type="function_call", call_id="f1", name="ping", arguments="{}"),
        ]
    )
    batch = await tb_openai.run_tool_calls(gw, responses, ctx, parallel=True)
    assert batch.blocks[0]["type"] == "function_call_output" and batch.blocks[0]["call_id"] == "f1"


def test_grouped_strategy(gw, ctx):
    grouped = gw.definitions(ctx, strategy="grouped")
    names = sorted(d.name for d in grouped)
    assert names == ["items", "ping"]
    items = next(d for d in grouped if d.name == "items")
    assert items.input_schema["properties"]["action"]["enum"] == ["get_item", "list_items"]


async def test_grouped_dispatch_still_validates(gw, ctx):
    ok = await gw.call("items", {"action": "get_item", "arguments": {"id": 9}}, ctx=ctx)
    assert ok.ok and ok.data == {"id": "9"}
    bad = await gw.call("items", {"action": "get_item", "arguments": {"id": "x"}}, ctx=ctx)
    assert bad.error and bad.error.code is ErrorCode.INVALID_ARGUMENTS
    unknown = await gw.call("items", {"action": "delete_all", "arguments": {}}, ctx=ctx)
    assert unknown.error and unknown.error.code is ErrorCode.INVALID_ARGUMENTS


def test_tag_filtering(make_gateway, ctx):
    gw = make_gateway().register(
        Operation(name="a", description="a", service=SERVICE, path="/a", tags=("support",)),
        Operation(name="b", description="b", service=SERVICE, path="/b", tags=("billing",)),
    )
    assert [d.name for d in gw.definitions(ctx, tags={"support"})] == ["a"]
    assert [d.name for d in gw.definitions(ctx, names={"b"})] == ["b"]


CONTRACT = textwrap.dedent(
    """
    version: 1
    service:
      name: weather
      base_url: https://api.open-meteo.com
      network: {allow_hosts: [api.open-meteo.com]}
    operations:
      - name: current_weather
        description: Current weather for a coordinate.
        path: /v1/forecast
        input:
          latitude: {type: number, minimum: -90, maximum: 90}
          longitude: {type: number, minimum: -180, maximum: 180}
        output:
          root: current
          shape:
            temperature_c: temperature_2m
            wind_kmh: {from: wind_speed_10m, transform: str}
          max_tokens: 200
    """
)


def test_yaml_loader(tmp_path):
    (tmp_path / "weather.yaml").write_text(CONTRACT)
    (tmp_path / "ignored.txt").write_text("nope")
    operations = load_contracts(tmp_path)
    assert [o.name for o in operations] == ["current_weather"]
    assert operations[0].output.max_tokens == 200
    gw = Gateway(authorize=allow_all).load(tmp_path)
    assert gw.tool_names == ["current_weather"]


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"status": "draft"}, "draft"),
        ({"version": 2}, "version"),
        ({"unknown_key": 1}, "unknown_key"),
    ],
)
def test_loader_rejects_bad_documents(patch, message):
    import yaml

    document = yaml.safe_load(CONTRACT)
    document.update(patch)
    with pytest.raises(ConfigurationError, match=message):
        parse_contract(document)


def test_loader_rejects_semantic_errors():
    import yaml

    document = yaml.safe_load(CONTRACT)
    document["service"]["base_url"] = "https://evil.com"
    with pytest.raises(ConfigurationError, match="allow_hosts"):
        parse_contract(document)
    document = yaml.safe_load(CONTRACT)
    document["operations"][0]["output"]["shape"]["x"] = {"from": "a..b"}
    with pytest.raises(ConfigurationError, match="path"):
        parse_contract(document)


def test_cli(tmp_path, capsys):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT)
    assert cli_main(["validate", str(path)]) == 0
    assert "current_weather" in capsys.readouterr().out
    assert cli_main(["tools", str(path), "--format", "anthropic"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)[0]["name"] == "current_weather"
    assert "tokens" in out.err
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\n")
    assert cli_main(["validate", str(bad)]) == 1
    assert cli_main(["schema"]) == 0


def test_sync_gateway(make_gateway, mock, ctx):
    mock.route("GET", "https://api.example.com/ping", {"pong": True})
    gw = make_gateway().register(*ops())
    with SyncGateway(gw) as sync:
        assert sync.call("ping", {}, ctx=ctx).data == {"pong": True}
    assert mock.closed is False  # transport supplied by caller is not closed
