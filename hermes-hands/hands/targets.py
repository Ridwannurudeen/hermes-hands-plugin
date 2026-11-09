"""Resolve the execution target for one terminal call."""

from . import store

SERVER = "server"
LOCAL = "local"  # the caller is at the gateway host itself (CLI, TUI, Desktop)
_LOCAL_SURFACES = frozenset({"", "cli", "tui", "desktop", "local"})


def caller_id(platform: str, user_id: str) -> str:
    """Who is asking: ``local`` at the gateway host, ``<platform>:<user id>`` in a chat, else ``""``.
    Core binds the same platform value to a command (``run_inbound_hooks.py:291``) and to the turn's
    tool calls (``run.py:3971-3976``), so both sides name one person the same way."""
    platform = str(platform or "").strip().lower()
    if platform in _LOCAL_SURFACES:
        return LOCAL
    return f"{platform}:{user_id}" if user_id else ""


def current_caller() -> str:
    from gateway.session_context import get_session_env

    return caller_id(
        get_session_env("HERMES_SESSION_PLATFORM", ""),
        get_session_env("HERMES_SESSION_USER_ID", ""),
    )


def target_for(*, session_key: str, caller: str, default_target: str) -> str:
    """A device applies only to the person who chose it with /hands use (owner only, direct chats
    only), and a device ``default_target`` only at the gateway host itself. Everyone else, in
    every shared chat, gets the server."""
    if session_key:
        bound = store.get_session_target(session_key)
        if bound is not None:
            target, owner = bound
            return target if target == SERVER or (owner and owner == caller) else SERVER
    return default_target if caller == LOCAL else SERVER


def resolve_target(*, session_key: str, in_cron: bool, default_target: str) -> str:
    """This tool call's target; cron always runs on the server."""
    if in_cron:
        return SERVER
    return target_for(
        session_key=session_key, caller=current_caller(), default_target=default_target
    )

_target_changed = None

def bind_target_changed(callback) -> None:
    """environment.target_changed registers here. Importing it needs Hermes, which /hands does not."""
    global _target_changed
    _target_changed = callback

def notify_target_changed(session_key: str) -> None:
    """/hands use: drop what the file tools cached about the previous target."""
    if _target_changed is not None:
        _target_changed(session_key)
