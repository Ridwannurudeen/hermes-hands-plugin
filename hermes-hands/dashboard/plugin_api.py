"""Hermes Hands relay routes, mounted at ``/api/plugins/hermes-hands/`` (``manifest.json`` ``api``).

The dashboard imports this file on its own (``hermes_cli/web_server_dashboard.py:1233-1246``), not as
part of the plugin package, so it reaches the plugin through the token provider ``register()``
installed: that provider's package holds the seed-derived keys, and importing a second copy would
hold none. The gateway mounts these routes too (``gateway/run_api.py:128-162``); only the dashboard
process, where ``app.state.gateway_runner`` is None, serves as the relay.

Token routes (``relay.TOKEN_ROUTES``) are authenticated by the token seam before a handler runs;
``/ui/*`` are ordinary dashboard routes behind the session gate. Handlers are ``async`` and keep
blocking work on worker threads (the dashboard event loop is shared).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import sys

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from hermes_cli.dashboard_auth import get_provider
from hermes_cli.plugin_events import broadcast_plugin_event

router = APIRouter()
logger = logging.getLogger(__name__)

_PROVIDER = "hermes-hands"
_NOT_LOADED = "hands: Hermes Hands is not loaded in this process."


def _plugin():
    """``(token provider, hands package)`` of the plugin loaded in this process, or None: also when
    the registered provider is not ours in this process (another class under the name, or a proxy
    under ``plugins.isolation: host`` whose package is not importable here)."""
    try:
        provider = get_provider(_PROVIDER)
        if provider is None:
            return None
        hands = sys.modules.get(type(provider).__module__.rpartition(".")[0])
        ours = (
            hands is not None
            and provider.name == _PROVIDER
            and hasattr(hands, "relay")
            and hasattr(provider, "keys")
        )
    except Exception:
        logger.warning("hermes-hands: plugin routes cannot reach the loaded plugin", exc_info=True)
        return None
    if not ours:
        logger.warning(
            "hermes-hands: the %r token provider here is %s, not this plugin's",
            _PROVIDER,
            type(provider).__qualname__,
        )
        return None
    return provider, hands


def _in_gateway(request: Request) -> bool:
    return getattr(request.app.state, "gateway_runner", None) is not None


def _response(reply) -> Response:
    return Response(
        content=reply.body,
        status_code=reply.status,
        headers=reply.headers,
        media_type="application/json" if reply.body else None,
    )


async def _relay_call(request: Request, handler: str, **extra) -> Response:
    plugin = _plugin()
    if plugin is None:
        return JSONResponse({"error": "not_loaded", "detail": _NOT_LOADED}, status_code=503)
    provider, hands = plugin
    served = hands.relay.serve(provider.keys, here=not _in_gateway(request))
    if isinstance(served, hands.relay.Reply):
        return _response(served)
    principal = getattr(request.state, "token_principal", None)
    body = await request.body()
    try:
        reply = await getattr(served, handler)(
            principal, request.headers, request.url.path, body, **extra
        )
    except sqlite3.Error:
        logger.warning("hermes-hands: the relay could not use its store", exc_info=True)
        return JSONResponse(
            {"error": "store_down", "detail": hands.messages.RELAY_STORE_DOWN}, status_code=503
        )
    if reply.devices_changed is not None:
        # Best effort: the pane's 2 s /ui/state poll is the main path (plugin_events.py:66-88).
        broadcast_plugin_event(_PROVIDER, "devices.changed", reply.devices_changed)
    return _response(reply)


def _peer(request: Request) -> str:
    """The client address, as core's auth audit takes it (``request_utils.py:20-27``): the ASGI peer,
    which the server rewrites from X-Forwarded-For only for its trusted proxies."""
    return request.client.host if request.client else ""


@router.post("/pair")
async def pair(request: Request) -> Response:
    return await _relay_call(request, "pair")


@router.post("/device/poll")
async def device_poll(request: Request) -> Response:
    return await _relay_call(request, "device_poll", peer=_peer(request))


@router.post("/device/result")
async def device_result(request: Request) -> Response:
    return await _relay_call(request, "device_result", peer=_peer(request))


@router.post("/device/heartbeat")
async def device_heartbeat(request: Request) -> Response:
    return await _relay_call(request, "device_heartbeat", peer=_peer(request))


@router.post("/device/help")
async def device_help(request: Request) -> Response:
    return await _relay_call(request, "device_help", peer=_peer(request))


@router.post("/local/exec")
async def local_exec(request: Request) -> Response:
    return await _relay_call(request, "local_exec")


@router.post("/local/output")
async def local_output(request: Request) -> Response:
    return await _relay_call(request, "local_output")


@router.post("/local/cancel")
async def local_cancel(request: Request) -> Response:
    return await _relay_call(request, "local_cancel")


@router.post("/local/state")
async def local_state(request: Request) -> Response:
    return await _relay_call(request, "local_state")


@router.get("/ui/state")
async def ui_state(request: Request) -> Response:
    """Desktop pane data. In the gateway's copy it is fetched from the relay over the local route."""
    plugin = _plugin()
    if plugin is None:
        return JSONResponse({"relay": False, "devices": [], "detail": _NOT_LOADED}, status_code=503)
    provider, hands = plugin
    if _in_gateway(request):
        try:
            return JSONResponse(await asyncio.to_thread(hands.client.state))
        except hands.client.HandsError as exc:
            return JSONResponse({"relay": False, "devices": [], "detail": str(exc)})
    served = hands.relay.serve(provider.keys, here=True)
    if isinstance(served, hands.relay.Reply):
        return _response(served)
    return JSONResponse(await served.state())
