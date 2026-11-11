import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("hermes_cli.dashboard_auth")

from starlette.requests import Request  # noqa: E402

from hands import relay  # noqa: E402
from hands_fakes import Principal, load_plugin_api  # noqa: E402


@pytest.mark.parametrize("scope", [relay.SCOPE_DEVICE, relay.SCOPE_REVOKED, relay.SCOPE_PAIR])
def test_exec_allowance_is_only_for_the_local_principal(monkeypatch, scope):
    """A device, a revoked key or a pairing code holder can never queue a job, so /local/exec reads at
    most the ordinary cap from them before refusing."""
    api = load_plugin_api()
    monkeypatch.setattr(api, "MAX_REQUEST_BODY_BYTES", 8)
    calls = []

    async def handler(*args):
        calls.append(args)
        return relay.Reply(204)

    hands = SimpleNamespace(
        relay=SimpleNamespace(
            serve=lambda *args, **kwargs: SimpleNamespace(local_exec=handler),
            Reply=relay.Reply,
            MAX_JOB_TEXT=1,
            SCOPE_LOCAL=relay.SCOPE_LOCAL,
            _has=relay._has,
        )
    )
    monkeypatch.setattr(api, "_plugin", lambda: (SimpleNamespace(keys=None), hands))
    chunks = iter([b"12345", b"6789", b"0123456789", b"unread"])
    read = []

    async def receive():
        chunk = next(chunks)
        read.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": chunk != b"unread"}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": relay.API + "/local/exec",
            "headers": [],
            "app": SimpleNamespace(state=SimpleNamespace()),
            "state": {"token_principal": Principal("device", scopes=(scope,))},
        },
        receive,
    )
    response = asyncio.run(api._relay_call(request, "local_exec"))
    assert response.status_code == 413
    assert calls == []
    assert sum(map(len, read)) <= 8 + len(b"6789")
    assert read == [b"12345", b"6789"]

