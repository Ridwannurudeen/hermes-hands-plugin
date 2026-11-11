"""Hands screenshot and device tools."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid

from . import client, messages, store, targets

logger = logging.getLogger(__name__)

SCREENSHOT_MAX_AGE_SECONDS = 24 * 60 * 60


def _cleanup_screenshots(directory, now=None) -> None:
    cutoff = (time.time() if now is None else now) - SCREENSHOT_MAX_AGE_SECONDS
    if directory.is_symlink():
        return
    try:
        entries = os.scandir(directory)
    except OSError:
        return
    with entries:
        for entry in entries:
            if not entry.name.endswith(".png") or not entry.is_file(follow_symlinks=False):
                continue
            try:
                if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    from pathlib import Path

                    Path(entry.path).unlink()
            except OSError:
                continue


def register_tools(ctx) -> None:
    def screenshot(_arguments: dict) -> str:
        try:
            if ctx.current_cron_execution() is not None:
                return json.dumps({"error": "Screenshots are unavailable in cron."})
            from gateway.session_context import get_session_env

            session_key = get_session_env("HERMES_SESSION_KEY", "")
            target = targets.resolve_target(
                session_key=session_key,
                in_cron=False,
                default_target=ctx.get_config("default_target", default="server"),
            )
            if target == "server":
                return json.dumps({"error": "Select a device with /hands use before requesting a screenshot."})
            if store.get_device(target) is None:
                return json.dumps({"error": f"No paired device named {target}."})
            png = client.request_screenshot(target)
            from hermes_constants import get_hermes_home

            output = get_hermes_home() / "cache" / "hermes-hands" / f"{uuid.uuid4()}.png"
            output.parent.mkdir(parents=True, exist_ok=True)
            _cleanup_screenshots(output.parent)
            output.write_bytes(png)
            path = str(output.resolve())
            return json.dumps({"text": f"Screenshot saved. Include this exact line in your reply and call vision_analyze on the path.\nMEDIA:{path}"})
        except client.HandsError as exc:
            return json.dumps({"error": str(exc)})
        except Exception:
            logger.warning("hermes-hands: hands_screenshot failed", exc_info=True)
            return json.dumps({"error": messages.SCREENSHOT_GATEWAY_FAILED})

    def devices(_arguments: dict) -> str:
        try:
            return json.dumps({"devices": store.list_devices()})
        except Exception:
            logger.warning("hermes-hands: hands_devices failed", exc_info=True)
            return json.dumps({"error": messages.DEVICES_GATEWAY_FAILED})

    def checkup(_arguments: dict) -> str:
        try:
            if ctx.current_cron_execution() is not None:
                return json.dumps({"error": "Checkups are unavailable in cron."})
            from gateway.session_context import get_session_env

            session_key = get_session_env("HERMES_SESSION_KEY", "")
            target = targets.resolve_target(
                session_key=session_key,
                in_cron=False,
                default_target=ctx.get_config("default_target", default="server"),
            )
            if target == "server":
                return json.dumps(
                    {"error": "Select a device with /hands use before requesting a checkup."}
                )
            if store.get_device(target) is None:
                return json.dumps({"error": f"No paired device named {target}."})
            return json.dumps(client.request_checkup(target), ensure_ascii=False, indent=2)
        except client.HandsError as exc:
            return json.dumps({"error": str(exc)})
        except Exception:
            logger.warning("hermes-hands: hands_checkup failed", exc_info=True)
            return json.dumps({"error": messages.CHECKUP_GATEWAY_FAILED})

    ctx.register_tool(
        name="hands_screenshot",
        toolset="hands",
        schema={
            "name": "hands_screenshot",
            "description": "Capture a screenshot from the selected paired device.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        handler=screenshot,
    )
    ctx.register_tool(
        name="hands_devices",
        toolset="hands",
        schema={
            "name": "hands_devices",
            "description": "List paired Hands devices and their status.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        handler=devices,
    )
    ctx.register_tool(
        name="hands_checkup",
        toolset="hands",
        schema={
            "name": "hands_checkup",
            "description": (
                "For any request to run a checkup, perform a health check, or diagnose why a laptop is slow, "
                "call hands_checkup first. This built-in read-only device report separates observed facts "
                "from inferences. On a witness device, every tool call that reaches the device needs "
                "the helper's approval, this checkup included. Shell composition and known script "
                "interpreters are blocked there. Every other command, including ones that can start "
                "programs, needs the helper's approval, and each screenshot also asks the person at "
                "the computer. "
                "When the user requests only observed facts and unavailable items, "
                "report only those without unsolicited causal claims or repair advice. "
                "Do not infer that a reboot marker causes memory pressure or slowness, or guarantee "
                "that a restart clears it, from checkup facts alone. "
                "An empty inferences list does not establish a cause."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        handler=checkup,
    )
