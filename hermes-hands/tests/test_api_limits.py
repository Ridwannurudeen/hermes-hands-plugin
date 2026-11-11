import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("hermes_cli.dashboard_auth")

from starlette.requests import Request  # noqa: E402

from hands import relay  # noqa: E402
from hands_fakes import LOCAL, load_plugin_api  # noqa: E402


@pytest.mark.parametrize("advertised", [None, b"1", b"9"])
def test_relay_route_caps_streamed_body_before_dispatch(monkeypatch, advertised):
    api = load_plugin_api()
    monkeypatch.setattr(api, "MAX_REQUEST_BODY_BYTES", 8, raising=False)
    calls = []

    async def handler(*args):
        calls.append(args)
        return relay.Reply(200)

    hands = SimpleNamespace(relay=SimpleNamespace(
        serve=lambda *args, **kwargs: SimpleNamespace(local_state=handler), Reply=relay.Reply
    ))
    monkeypatch.setattr(api, "_plugin", lambda: (SimpleNamespace(keys=None), hands))
    chunks = iter([b"12345", b"6789", b"unread"])
    read = []

    async def receive():
        chunk = next(chunks)
        read.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": chunk != b"unread"}

    request = Request({
        "type": "http", "method": "POST", "path": relay.API + "/local/state",
        "headers": [] if advertised is None else [(b"content-length", advertised)],
        "app": SimpleNamespace(state=SimpleNamespace()),
    }, receive)
    response = asyncio.run(api._relay_call(request, "local_state"))
    assert response.status_code == 413
    assert b"request_too_large" in response.body
    assert calls == []
    assert len(read) == (0 if advertised == b"9" else 2)


def test_relay_route_preserves_exact_body_at_cap(monkeypatch):
    api = load_plugin_api()
    monkeypatch.setattr(api, "MAX_REQUEST_BODY_BYTES", 8, raising=False)
    bodies = []

    async def handler(principal, headers, path, body):
        bodies.append(body)
        return relay.Reply(204)

    hands = SimpleNamespace(relay=SimpleNamespace(
        serve=lambda *args, **kwargs: SimpleNamespace(local_state=handler), Reply=relay.Reply
    ))
    monkeypatch.setattr(api, "_plugin", lambda: (SimpleNamespace(keys=None), hands))

    async def receive():
        return {"type": "http.request", "body": b"12345678", "more_body": False}

    request = Request({
        "type": "http", "method": "POST", "path": relay.API + "/local/state",
        "headers": [], "app": SimpleNamespace(state=SimpleNamespace()),
    }, receive)
    response = asyncio.run(api._relay_call(request, "local_state"))
    assert response.status_code == 204
    assert bodies == [b"12345678"]


def test_exec_route_allows_a_full_size_job(monkeypatch):
    api = load_plugin_api()
    monkeypatch.setattr(api, "MAX_REQUEST_BODY_BYTES", 8)
    bodies = []

    async def handler(principal, headers, path, body):
        bodies.append(body)
        return relay.Reply(204)

    hands = SimpleNamespace(relay=SimpleNamespace(
        serve=lambda *args, **kwargs: SimpleNamespace(local_exec=handler), Reply=relay.Reply, MAX_JOB_TEXT=1,
        SCOPE_LOCAL=relay.SCOPE_LOCAL, _has=relay._has,
    ))
    monkeypatch.setattr(api, "_plugin", lambda: (SimpleNamespace(keys=None), hands))

    async def receive():
        return {"type": "http.request", "body": b"x" * 20, "more_body": False}

    request = Request({
        "type": "http", "method": "POST", "path": relay.API + "/local/exec",
        "headers": [], "app": SimpleNamespace(state=SimpleNamespace()), "state": {"token_principal": LOCAL},
    }, receive)
    assert asyncio.run(api._relay_call(request, "local_exec")).status_code == 204
    assert bodies == [b"x" * 20]
