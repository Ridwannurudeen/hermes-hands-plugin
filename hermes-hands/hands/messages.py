"""Every user-facing string of the gateway half, in one place."""

from __future__ import annotations

import re

UPGRADE = "pipx install hermes-hands==0.1.0"
_DEVICE_ERROR_CODE = re.compile(r"[^A-Za-z0-9_.-]+")
_DEVICE_ERROR_CODE_LIMIT = 64

RELAY_DOWN = (
    "hands: the relay (the hermes dashboard on the gateway host) is not reachable, so nothing ran on the device. "
    "Start the dashboard, or send /hands use server."
)
NOT_SET_UP = (
    "hands: the relay seed is missing, so no device can be reached. "
    "Run hermes hands setup on the gateway host, then restart the gateway and the dashboard."
)
RELAY_ELSEWHERE = (
    "hands: this process does not host the relay; it runs in the hermes dashboard process "
    "(dashboard_url in the hermes-hands settings)."
)
RELAY_LOST = (
    "hands: the relay restarted and lost this command; whether it ran on the device is unknown."
)
FORWARDED = "hands: local relay routes refuse proxied requests."
UNAUTHENTICATED = "hands: this request is not signed by a paired device."
UNKNOWN_DEVICE_WIRE = (
    "hands: this device was revoked on the gateway. Pair it again with a new /hands pair code."
)
POLICY_CHANGED_WIRE = (
    "hands: the device deny-list changed since pairing; the owner must run /hands accept-policy."
)
BAD_REQUEST = "hands: malformed request body."
SCREENSHOT_TOO_LARGE = "hands: the screenshot is larger than 2 MiB; nothing was saved."
SCREENSHOT_FAILED = "hands: the device did not send a screenshot."
PAIR_BAD_CODE = "hands: this pairing code is unknown, expired or already used. Ask the owner for a new /hands pair code."
PAIR_NAME_RESERVED = (
    "hands: server is the name of the gateway host's own target, so no device can use it. "
    "Pick another device name."
)
PAIR_BAD_SIGNATURE = "hands: the pairing request is not signed by the public key it carries."
TARGET_NOTE_SERVER = "hands: now on server (the gateway host)"
WITNESS_APPROVAL = (
    "Hands witness approval required: tool={tool}; device={device}; {details}. "
    "Review the request before approving."
)
WITNESS_COMMAND_BLOCKED = (
    "Hermes Hands blocks shell composition, scripts, redirects, malformed commands, and unsupported "
    "flags during an active witness session."
)
WITNESS_EXECUTE_CODE_BLOCKED = "Hermes Hands blocks execute_code during an active witness session."
WITNESS_TARGET_BLOCKED = (
    "Hermes Hands could not verify the active device and owner, so it blocked this tool call."
)
STORE_DOWN = (
    "hands: the Hermes Hands store (plugin-data/hermes-hands/hands.db) is unreadable, so this "
    "conversation's target is unknown and nothing ran anywhere. See the gateway log."
)
REPLAYED = "hands: this request was already used once."
JOB_TOO_LARGE = (
    "hands: the command or its input is longer than 16 million characters, so nothing ran."
)
BAD_SCRIPT_ENCODING = (
    "hands: the command contains characters that cannot be encoded as UTF-8, so nothing ran."
)
STORE_SPLIT = (
    "hands: the relay answers but uses a different store from this gateway, so pairing codes and "
    "devices do not reach it. Run the gateway and the dashboard with the same HERMES_HOME."
)
USE_DIRECT_ONLY = (
    "Hands: everyone in this chat shares one session, so a device target set here would let all of "
    "them run commands on that device. Send /hands use <device> in a direct chat with the bot; "
    "here only /hands use server is allowed."
)
PAIR_DIRECT_ONLY = (
    "Hands: a pairing code is a secret that anyone who sees it can use to pair their own machine. "
    "Send /hands pair in a direct chat with the bot."
)
RELAY_STORE_DOWN = (
    "hands: the relay cannot read the Hermes Hands store (plugin-data/hermes-hands/hands.db) "
    "and refused this request. See the dashboard log."
)


def relay_refused(status: int) -> str:
    return (
        f"hands: the dashboard at dashboard_url answered HTTP {status}, so nothing ran on the device. "
        f"Either it has not loaded hermes-hands, or it runs with a different relay seed or HERMES_HOME "
        f"than this gateway; restart both after hermes hands setup and run hermes hands doctor."
    )


def offline(name: str) -> str:
    return (
        f"hands: {name} is offline, so nothing ran. Start hermes-hands serve on it, "
        f"or send /hands use server to run on the server."
    )


def unknown_device(name: str) -> str:
    return (
        f"hands: no paired device is named {name} (revoked or never paired), so nothing ran. "
        f"Send /hands use server, or pair it again with /hands pair {name}."
    )


def policy_changed(name: str) -> str:
    return (
        f"hands: the deny-list on {name} changed since it was paired, so the relay refuses it and nothing ran. "
        f"If you changed it yourself, run /hands accept-policy {name}."
    )


def policy_changed_while_running(name: str) -> str:
    return (
        f"hands: the deny-list on {name} changed since it was paired, so the relay stopped the "
        f"command, which may have partly run there; any output above is partial. If you changed "
        f"it yourself, run /hands accept-policy {name}."
    )


def went_offline(name: str) -> str:
    return f"hands: {name} went offline before the command finished; any output above is partial."


def revoked(name: str) -> str:
    return (
        f"hands: {name} was revoked while the command ran; the device stops it at its next request."
    )


def cancelled(name: str) -> str:
    return f"hands: the command on {name} was cancelled."


def agent_restarted(name: str) -> str:
    return (
        f"hands: the device agent on {name} restarted while the command ran, so it may have partly "
        f"run there and any output above is partial. Check {name} before running it again."
    )


def queue_unknown(name: str) -> str:
    return (
        f"hands: the relay stopped answering after the command was sent to it, so it may have been "
        f"queued and may run on {name}. Check {name} before running it again."
    )


def contact_lost(name: str) -> str:
    return (
        f"hands: contact with the relay was lost after the command started on {name}, so it may "
        f"still be running there and any output above is partial. Check {name} before running it "
        f"again."
    )


def ambiguous_pid(pid: int, targets: list[str]) -> str:
    return (
        f"hands: background jobs with pid {pid} run on {' and '.join(targets)}, so Hermes "
        f"Hands cannot tell which one to stop and stopped neither. Stop it with a terminal "
        f"command on the right target."
    )


def pair_name_taken(name: str) -> str:
    return f"hands: a device named {name} is already paired. Revoke it first with /hands revoke {name}."


def pair_name_mismatch(minted: str) -> str:
    return f"hands: this pairing code was minted for a device named {minted}; pair with --name {minted}."


def protocol_mismatch(protocol: str) -> str:
    return f"hands: the device speaks {protocol}; this gateway needs a matching device agent: {UPGRADE}"


def target_note(name: str, device_os: str | None, home: str | None) -> str:
    """One line prefixed to the first terminal result on a device, so the model uses its paths."""
    if not device_os:
        return f"hands: now on {name}"
    if device_os.lower().startswith("windows"):
        return f"hands: now on {name} ({device_os}, Git Bash, home {home}; use /c/... paths)"
    return f"hands: now on {name} ({device_os}, home {home})"


def output_omitted(omitted: int, job_id: str | None) -> str:
    return (
        f"[hands: {omitted} bytes of output omitted here (inline_output_limit_bytes); the full output "
        f"is in ~/.hermes-hands/out/{job_id}.log on the device, which the device deny-list keeps "
        f"from the agent]"
    )


def device_result_error(error: str, device: str) -> str:
    """Turn a final device error code into a fixed model-facing sentence."""
    if error == "screenshot_declined":
        return (
            f"The person at {device} said no to this screenshot. Nothing was captured. "
            "Do not guess a reason or retry."
        )
    if error == "stopped_by_person":
        return (
            f"The person at {device} stopped the session. Nothing else will run. "
            "Do not guess a reason or retry."
        )
    if error == "session_timeout":
        return (
            f"The 30 minute session on {device} ended. Nothing else will run. "
            "Do not guess a reason or retry."
        )
    if error == "unknown_job_type":
        return "The device rejected this job type. Nothing ran. Do not guess a reason or retry."
    if error.startswith("hands:"):
        return error
    code = _DEVICE_ERROR_CODE.sub("_", error).strip("_.-")[:_DEVICE_ERROR_CODE_LIMIT]
    code = code.rstrip("_.-") or "unknown"
    return f"The device reported: {code}. Do not guess a reason or retry."


def alerts(devices: list[dict]) -> list[str]:
    """What /hands status and the Desktop pane show for devices the relay refuses. Hermes has no public
    way for a plugin to message the owner unprompted, so the alert waits to be looked at."""
    return [policy_changed(device["name"]) for device in devices if not device["policy_ok"]]
