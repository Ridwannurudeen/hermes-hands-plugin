"""Every user-facing string of the gateway half, in one place."""

from __future__ import annotations

import re

UPGRADE = (
    "Update the Hermes Hands device agent on that computer to the version that matches this plugin. "
    "The install command is in the plugin README."
)
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
SCREENSHOT_GATEWAY_FAILED = "hands: the screenshot failed on the gateway. See the gateway log."
DEVICES_GATEWAY_FAILED = "hands: the device list could not be read on the gateway. See the gateway log."
CHECKUP_GATEWAY_FAILED = "hands: the checkup failed on the gateway. See the gateway log."
PAIR_BAD_CODE = "hands: this pairing code is unknown, expired or already used. Ask the owner for a new /hands pair code."
PAIR_NAME_RESERVED = (
    "hands: server is the name of the gateway host's own target, so no device can use it. "
    "Pick another device name."
)
PAIR_BAD_SIGNATURE = "hands: the pairing request is not signed by the public key it carries."
TARGET_NOTE_SERVER = "hands: now on server (the gateway host)"
DEVICE_RG_UNAVAILABLE = (
    "hands: this search names an absolute rg executable from another target, so nothing ran. "
    "Use a terminal command with grep on the selected device instead."
)
WITNESS_APPROVAL = (
    "Hands witness approval required: tool={tool}; device={device}; {details}. "
    "Review the request before approving."
)
WITNESS_COMMAND_BLOCKED = (
    "Hermes Hands blocks shell composition, scripts, programs that run other commands, sed scripts that "
    "write or run, redirects, malformed commands, and unsupported flags during an active witness session. It also refuses the symbols ; & | < > ` $ ( ) { } * ? "
    "[ ] ~ # ! % anywhere in a command, even inside quotes, so a folder name with one of them needs "
    "the manual steps instead."
)
WITNESS_TARGET_BLOCKED = (
    "Hermes Hands could not verify the active device and owner, so it blocked this tool call."
)
WITNESS_TOOL_BLOCKED = "Hermes Hands blocks this tool during an active witness session."
WITNESS_ARGUMENTS_LONG = (
    "Hermes Hands cannot show this request in full on the approval card, so it blocked it. "
    "Shorten the {argument} argument."
)
WITNESS_SHORTER_PATH = (
    "For a file on the device, a ~/ path such as ~/Desktop/notes.txt is shorter than the full path."
)
WITNESS_ARGUMENTS_BLOCKED = (
    "Hermes Hands blocks malformed arguments, control characters and patch directives during a witness session."
)
WITNESS_ARGUMENT_TYPES_BLOCKED = (
    "Hermes Hands blocks arguments that are not already their declared type during a witness session, "
    "such as \"true\" for background or \"50\" for limit: the approval card would show another value "
    "than the one that runs. Send booleans and numbers as JSON values."
)
WITNESS_CONTROL_CHARACTERS_BLOCKED = (
    "Hermes Hands blocks hidden and control characters in arguments during a witness session. "
    "Line breaks are allowed only in file content."
)
WITNESS_MARKDOWN_BLOCKED = (
    "Hermes Hands cannot show these formatting characters literally on this approval surface, "
    "so it blocked the call. Use the manual steps instead."
)
WITNESS_PATCH_DIRECTIVE_BLOCKED = (
    "Hermes Hands blocks patch directives such as *** Begin Patch in any argument during a "
    "witness session. Use a plain replace with old_string and new_string."
)
WITNESS_PATCH_MODE_BLOCKED = (
    "Hermes Hands allows only replace mode patches during a witness session."
)
WITNESS_PATH_REQUIRED = (
    "Hermes Hands needs a file path for a write or a patch during a witness session."
)
WITNESS_ABSOLUTE_PATH_REQUIRED = (
    "Hermes Hands needs the full path for a write or a patch during a witness session, such as "
    "/home/sam/notes.txt, ~/notes.txt or /c/Users/sam/notes.txt on Windows. Hermes can place a "
    "relative path in more than one folder, so the approval card could not say which file changes."
)
WITNESS_SECRET_BLOCKED = (
    "Hermes Hands blocked this call because an argument looks like a secret, such as a key, "
    "token or password. Do not send secrets to the device."
)
WITNESS_SECRET_HIDDEN = (
    WITNESS_SECRET_BLOCKED + " The approval card would hide part of this text, so it could show "
    "something different from what runs."
)
WITNESS_AUTOSTART_BLOCKED = (
    "Hermes Hands blocks startup persistence during a witness session: writes to startup and "
    "autostart folders, systemd user units and login folders, shell profiles and cron, registry Run "
    "keys, registry imports and scheduled tasks. These would keep running after the 30 minute "
    "session ends."
)
WITNESS_NOT_APPROVED = (
    "hands: nothing ran on the device because nobody answered the approval prompt for this call. "
    "A witness session needs a person to approve every device call, so approvals must be on and "
    "yolo mode and unattended approval off."
)
WITNESS_CALLS_OVERLAP = (
    "hands: nothing ran on the device because Hermes ran several device calls at once, so Hands "
    "could not tell which approval belongs to this one. Ask for one device step at a time."
)
WITNESS_PATCH_NOT_EXACT = (
    "hands: nothing was written on the device because a witness patch must replace exactly one "
    "exact copy of old_string in the file as it is now. Read the file again and retry with "
    "old_string copied exactly, spaces and line breaks included, and long enough to match only once."
)
WITNESS_PATCH_ALL_NOT_EXACT = (
    "hands: nothing was written on the device because replace_all must replace every exact copy "
    "of old_string with the approved new_string. Read the file again and copy old_string exactly, "
    "including spaces and line breaks."
)
WITNESS_CALL_CHANGED = (
    "hands: nothing ran on the device because this command is not the one the helper approved. "
    "Another plugin or hook may have changed the call after the approval, or Hermes sent a step "
    "Hands cannot match to it. Ask again; if it keeps happening, turn off other plugins and hooks "
    "for this session (hermes plugins list, hermes hooks list)."
)
WITNESS_MEDIA_BLOCKED = (
    "hands: MEDIA lines never fetch files from the device during a witness session."
)
WITNESS_RESULT_KEPT = (
    "hands: large tool results are never saved on the device during a witness session."
)
BACKGROUND_JOB_ENDED = (
    "hands: this background job has ended or was started elsewhere, so nothing ran."
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
PAIR_OWNER_LABEL_REQUIRED = (
    "Hands: provide a human name with --owner-label, such as --owner-label \"Sam\". "
    "Use 1 to 80 printable characters, not an account id."
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
    return f"hands: the device speaks {protocol}. {UPGRADE}"


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


_GIT_BASH_MISSING = (
    "Git Bash is missing or did not start on {device}, so nothing ran. Install Git for Windows there, "
    "then run hermes-hands doctor on it."
)
_JOB_LIMITS_FAILED = (
    "{device} could not put this command inside its safety limits, so it stopped the command as "
    "it started. Restart hermes-hands serve there and run hermes-hands doctor."
)
# OSError text carries a variable errno prefix (executor.py raises OSError(code, message)).
_ERRNO_PREFIX = re.compile(r"^\[(?:Errno|WinError) -?\d+\] ")
# The device's free-text job errors (device screen.py, loop.py and executor.py).
_DEVICE_ERRORS = {
    "Screenshot capture requires serve --allow-screen": (
        "{device} did not take the screenshot: Screenshot capture requires serve --allow-screen. "
        "Nothing was captured."
    ),
    "Screenshot support is not available on this computer. Reinstall hermes-hands.": (
        "Screenshots are not available on {device}. Nothing was captured. The person at the "
        "computer should reinstall the Hermes Hands device agent there."
    ),
    "Screenshot exceeds 2 MiB after JPEG compression": (
        "The screenshot on {device} is larger than 2 MiB even as a JPEG, so nothing was sent."
    ),
    "Output exceeded the 64 MiB device limit": (
        "The output on {device} reached the 64 MiB device limit, so the command was stopped "
        "there and its output is cut short."
    ),
    "Output was truncated after the post-exit pipe idle limit": (
        "The command on {device} finished, but its output stayed open afterwards, so the device "
        "stopped reading and the output may be cut short."
    ),
    "Git Bash was not found or failed its probe": _GIT_BASH_MISSING,
    "Could not create Windows job object": _JOB_LIMITS_FAILED,
    "Could not set Windows job object limits": _JOB_LIMITS_FAILED,
    "Could not assign process to Windows job object": _JOB_LIMITS_FAILED,
    "Could not identify the suspended device process thread": _JOB_LIMITS_FAILED,
    "Could not open the suspended device process thread": _JOB_LIMITS_FAILED,
    "Could not resume the device process thread": _JOB_LIMITS_FAILED,
    "The device process thread was not suspended exactly once": _JOB_LIMITS_FAILED,
    "Could not establish job guardian protection": _JOB_LIMITS_FAILED,
    "The job guardian did not acknowledge protection": _JOB_LIMITS_FAILED,
    "The job guardian could not identify the protected process": _JOB_LIMITS_FAILED,
}


def device_result_error(error: str, device: str) -> str:
    """Turn a final device error code into a fixed model-facing sentence."""
    if error == "screenshot_declined":
        return (
            f"The person at {device} said no to the screenshot. Nothing was captured. "
            "Do not guess a reason or retry."
        )
    if error == "screenshot_timeout":
        return (
            f"The person at {device} did not answer in time. Nothing was captured. "
            "Do not guess a reason or retry."
        )
    if error == "screenshot_pending":
        return (
            f"The person at {device} has not answered the screenshot question yet, so no screenshot "
            "was taken. Ask again in a moment."
        )
    if error == "screenshots_disabled":
        return (
            f"The person at {device} turned off screenshots for this session. Nothing was captured. "
            "Do not guess a reason or retry."
        )
    if error == "screenshot_unavailable":
        return (
            f"{device} has no screen that screenshots can capture. Nothing was captured. "
            "Do not guess a reason or retry."
        )
    if error == "screenshot_failed":
        return f"{device} could not capture the screen right now. Nothing was captured. Try again in a minute."
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
    if error == "session_ended":
        return f"The session on {device} ended. Nothing else will run. Do not guess a reason or retry."
    if error == "unknown_job_type":
        return "The device rejected this job type. Nothing ran. Do not guess a reason or retry."
    fixed = _ERRNO_PREFIX.sub("", error, count=1)
    if fixed in _DEVICE_ERRORS:
        return f"{_DEVICE_ERRORS[fixed].format(device=device)} Do not guess a reason or retry."
    if error.startswith("hands:"):
        return error
    code = _DEVICE_ERROR_CODE.sub("_", error).strip("_.-")[:_DEVICE_ERROR_CODE_LIMIT]
    code = code.rstrip("_.-") or "unknown"
    if code == "device_error":
        return "The device ended the session because of an error. Nothing more will run."
    if code == "device_is_stopping":
        return "The person is ending the session. Nothing more will run."
    return f"The device reported: {code}. Do not guess a reason or retry."


def alerts(devices: list[dict]) -> list[str]:
    """What /hands status and the Desktop pane show for devices the relay refuses. Hermes has no public
    way for a plugin to message the owner unprompted, so the alert waits to be looked at."""
    return [policy_changed(device["name"]) for device in devices if not device["policy_ok"]]
