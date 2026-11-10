"""SSRF regression tests: URL policy, IP policy, path injection, redirects, DNS."""

from __future__ import annotations

import ipaddress

import pytest

from toolbound import (
    ConfigurationError,
    ErrorCode,
    NetworkBlocked,
    NetworkPolicy,
    Operation,
    Pagination,
    Service,
)
from toolbound.core.network import build_url, check_ip, check_url, encode_path_param
from toolbound.core.ports import HttpRequest
from toolbound.transport import SecureTransport
from toolbound.transport.mock import MockResponse

POLICY = NetworkPolicy(allow_hosts=("api.example.com",), allow_ports=(443,))


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/x",  # plain http
        "ftp://api.example.com/x",
        "file:///etc/passwd",
        "gopher://api.example.com/",
        "https://evil.com/x",
        "https://api.example.com.evil.com/x",
        "https://evil.com#@api.example.com/",
        "https://api.example.com@evil.com/",
        "https://user:pass@api.example.com/",
        "https://api.example.com:8443/x",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://169.254.169.254/latest/meta-data/",
        "https://2130706433/",  # decimal 127.0.0.1
        "https://0x7f.1/",
        "https://017700000001/",
        "https://api.example.com\\@evil.com/",
        "https://api.example.com/\r\nHost: evil",
        "https://api.exa mple.com/",
        "https:///nohost",
    ],
)
def test_check_url_blocks(url):
    with pytest.raises(NetworkBlocked):
        check_url(url, POLICY)


def test_check_url_allows_exact_host_and_normalizes():
    target = check_url("https://API.example.com./v1/x?y=1", POLICY)
    assert target.host == "api.example.com"
    assert target.port == 443


def test_wildcard_subdomain_policy():
    policy = NetworkPolicy(allow_hosts=("*.example.com",), allow_ports=(443,))
    assert check_url("https://a.b.example.com/", policy).host == "a.b.example.com"
    with pytest.raises(NetworkBlocked):
        check_url("https://example.com/", policy)
    with pytest.raises(NetworkBlocked):
        check_url("https://badexample.com/", policy)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",  # AWS IPv6 metadata
        "fc00::1",
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
        "2002:7f00:1::",  # 6to4 of 127.0.0.1
        "::127.0.0.1",  # IPv4-compatible (deprecated)
        "ff02::1",
    ],
)
def test_check_ip_blocks_non_public(ip):
    with pytest.raises(NetworkBlocked):
        check_ip(ip, POLICY)


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_check_ip_allows_public(ip):
    check_ip(ip, POLICY)


def test_allow_networks_is_explicit_and_narrow():
    policy = NetworkPolicy(allow_hosts=("internal",), allow_networks=("10.1.0.0/16",))
    check_ip("10.1.2.3", policy)
    with pytest.raises(NetworkBlocked):
        check_ip("10.2.0.1", policy)
    with pytest.raises(NetworkBlocked):
        check_ip("169.254.169.254", policy)


@pytest.mark.parametrize(
    "value",
    [
        "../admin",
        "..",
        ".",
        "a/b",
        "a\\b",
        "x?y=1",
        "x#frag",
        "%2e%2e",
        "a%2Fb",
        "line\nbreak",
        "",
        True,
        None,
        {"a": 1},
        [1],
    ],
)
def test_path_parameter_injection_rejected(value):
    from toolbound import ToolFailure

    with pytest.raises(ToolFailure):
        encode_path_param("p", value)


def test_path_parameter_encoding():
    assert encode_path_param("p", "hello world") == "hello%20world"
    assert encode_path_param("p", "ا ب") == "%D8%A7%20%D8%A8"
    assert encode_path_param("p", 42) == "42"


def test_build_url_cannot_escape_base():
    url = build_url("https://api.example.com/v1", "/items/{id}", {"id": "a b"}, [("q", "x&y=1")])
    assert url == "https://api.example.com/v1/items/a%20b?q=x%26y%3D1"


def test_service_rejects_dangerous_base_urls():
    with pytest.raises(ConfigurationError):
        Service(name="s", base_url="http://api.example.com")  # http without allow_http
    with pytest.raises(ConfigurationError):
        Service(name="s", base_url="https://u:p@api.example.com")
    with pytest.raises(ConfigurationError):
        Service(
            name="s",
            base_url="https://api.example.com",
            network=NetworkPolicy(allow_hosts=("other.com",)),
        )
    with pytest.raises(ConfigurationError):
        Service(name="s", base_url="https://api.example.com?x=1")


def _op(service, **kw):
    kw.setdefault("name", "op")
    kw.setdefault("description", "d")
    kw.setdefault("path", "/x")
    return Operation(service=service, **kw)


async def test_model_cannot_supply_url_or_host(make_gateway, ctx):
    service = Service(name="s", base_url="https://api.example.com")
    gw = make_gateway().register(_op(service, input={"id": {"type": "string"}}, path="/i/{id}"))
    for args in (
        {"id": "1", "url": "https://evil.com"},
        {"id": "1", "host": "evil.com"},
        {"id": "1", "headers": {"Host": "evil"}},
    ):
        result = await gw.call("op", args, ctx=ctx)
        assert result.error and result.error.code is ErrorCode.INVALID_ARGUMENTS
    result = await gw.call("op", {"id": "../../admin"}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_redirect_to_private_address_blocked(make_gateway, mock, ctx):
    service = Service(
        name="s",
        base_url="https://api.example.com",
        network=NetworkPolicy(follow_redirects=True, allow_hosts=("api.example.com",)),
    )
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(302, headers={"Location": "https://169.254.169.254/latest"}),
    )
    gw = make_gateway().register(_op(service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.NETWORK_BLOCKED


async def test_redirect_to_other_host_blocked(make_gateway, mock, ctx):
    service = Service(
        name="s", base_url="https://api.example.com", network=NetworkPolicy(follow_redirects=True)
    )
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(307, headers={"Location": "https://evil.example.net/steal"}),
    )
    gw = make_gateway().register(_op(service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.NETWORK_BLOCKED
    assert len(mock.requests) == 1


async def test_cross_origin_redirect_drops_credentials(make_gateway, mock, ctx):
    from toolbound import BearerAuth

    service = Service(
        name="s",
        base_url="https://api.example.com",
        auth=BearerAuth("github_token"),
        network=NetworkPolicy(
            follow_redirects=True, allow_hosts=("api.example.com", "cdn.example.com")
        ),
    )
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(302, headers={"Location": "https://cdn.example.com/blob"}),
    )
    mock.route("GET", "https://cdn.example.com/blob", {"ok": True})
    gw = make_gateway().register(_op(service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.ok
    first, second = mock.requests
    assert any(k == "Authorization" for k, _ in first.headers)
    assert not any(k.lower() == "authorization" for k, _ in second.headers)


async def test_redirect_loop_bounded(make_gateway, mock, ctx):
    service = Service(
        name="s",
        base_url="https://api.example.com",
        network=NetworkPolicy(follow_redirects=True, max_redirects=2),
    )
    mock.route("GET", "https://api.example.com/x", MockResponse(302, headers={"Location": "/x"}))
    gw = make_gateway().register(_op(service))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.UPSTREAM_ERROR
    assert len(mock.requests) == 3


async def test_forged_link_cursor_rejected(make_gateway, mock, ctx):
    service = Service(name="s", base_url="https://api.example.com")
    mock.route("GET", "https://api.example.com/x", [{"id": 1}])
    gw = make_gateway().register(_op(service, pagination=Pagination(type="link")))
    forged = gw._signer.sign("tbc1", {"u": "https://169.254.169.254/", "o": 0}, 60)
    result = await gw.call("op", {"cursor": forged}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INVALID_CURSOR
    tampered = await gw.call("op", {"cursor": "tbc1.eyJ1IjoiaHR0cDovL2V2aWwifQ.AAAA"}, ctx=ctx)
    assert tampered.error and tampered.error.code is ErrorCode.INVALID_CURSOR


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = 0

    async def resolve(self, host, port):
        self.calls += 1
        return self.answers[min(self.calls - 1, len(self.answers) - 1)]


def _request(url, policy=POLICY):
    return HttpRequest(
        method="GET",
        url=url,
        headers=(),
        body=None,
        network=policy,
        timeout=2,
        connect_timeout=1,
        max_response_bytes=1000,
    )


async def test_transport_blocks_host_resolving_to_private_ip():
    transport = SecureTransport(resolver=FakeResolver([["10.0.0.5"]]))
    with pytest.raises(NetworkBlocked):
        await transport.send(_request("https://api.example.com/x"))
    await transport.aclose()


async def test_transport_blocks_if_any_resolved_address_is_private():
    transport = SecureTransport(resolver=FakeResolver([["93.184.216.34", "127.0.0.1"]]))
    with pytest.raises(NetworkBlocked):
        await transport.send(_request("https://api.example.com/x"))
    await transport.aclose()


async def test_transport_blocks_mapped_ipv6_answer():
    transport = SecureTransport(resolver=FakeResolver([["::ffff:169.254.169.254"]]))
    with pytest.raises(NetworkBlocked):
        await transport.send(_request("https://api.example.com/x"))
    await transport.aclose()


def test_ipaddress_assumptions_hold():
    # Guards against stdlib changes weakening our classification.
    assert not ipaddress.ip_address("100.64.0.1").is_global
    assert not ipaddress.ip_address("fd00:ec2::254").is_global
