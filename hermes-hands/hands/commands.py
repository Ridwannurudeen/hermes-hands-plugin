"""Owner-gated Hands slash commands."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import unicodedata
from urllib.parse import urlparse

from . import client, messages, store, targets

DEFAULT_DASHBOARD_URL = "http://127.0.0.1:9119"
MAX_OWNER_LABEL_LENGTH = 80
# Reject characters core refuses in dashboard.public_url (hermes_cli/dashboard_auth/prefix.py:24).
_REJECT_CHARS = frozenset(('"', "'", "<", ">", " ", "\n", "\r", "\t"))
# Unexpanded shell text core replaces with a random per-process key (plugins/dashboard_auth/basic/__init__.py:199).
_UNEXPANDED_SHELL_MARKERS = ("$(", "`", "openssl rand")
# Phone keyboards turn straight quotes into curly ones.
_STRAIGHT_DOUBLE_QUOTES = str.maketrans({"\u201c": '"', "\u201d": '"'})
_STRAIGHT_QUOTES = str.maketrans({"\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'"})


def _loopback(host: str) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalise_public_url(raw: str | None) -> str:
    """Cleaned http(s) URL with trailing slash stripped, else empty (prefix.py:86-99)."""
    url = raw.strip() if raw else ""
    if not url or any(char in url for char in _REJECT_CHARS):
        return ""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return url.rstrip("/")


def _parsed_http_url(url: str):
    clean = _normalise_public_url(url)
    if not clean:
        return None
    try:
        parsed = urlparse(clean)
        _ = parsed.port
    except ValueError:
        return None
    return parsed if parsed.hostname else None


def loopback_url(url: str) -> bool:
    parsed = _parsed_http_url(url)
    return parsed is not None and _loopback(parsed.hostname or "")


def https_url(url: str) -> bool:
    parsed = _parsed_http_url(url)
    return parsed is not None and parsed.scheme == "https"


def https_or_loopback(url: str) -> bool:
    """The pairing URLs the device accepts (device hermeshands_device/cli.py:_pair)."""
    parsed = _parsed_http_url(url)
    return parsed is not None and (
        parsed.scheme == "https" or (parsed.scheme == "http" and _loopback(parsed.hostname or ""))
    )


def _dashboard_config() -> dict:
    """The dashboard section of config.yaml as a dict, or {} (prefix.py:101-114, config.py:1985-1989)."""
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
    except Exception:
        return {}
    section = cfg.get("dashboard") if isinstance(cfg, dict) else None
    return section if isinstance(section, dict) else {}


def _resolve_public_url() -> tuple[str, str]:
    """Resolve the dashboard public URL and its source setting, matching core precedence:
    HERMES_DASHBOARD_PUBLIC_URL env first (blank or malformed falls through), then dashboard.public_url
    in config.yaml (hermes_cli/dashboard_auth/prefix.py:117-137). When neither normalises to a valid
    http(s) URL, return any raw value so pair and doctor refuse a typo instead of ignoring it."""
    env_raw = os.environ.get("HERMES_DASHBOARD_PUBLIC_URL", "")
    env_clean = _normalise_public_url(env_raw)
    if env_clean:
        return env_clean, "HERMES_DASHBOARD_PUBLIC_URL"
    cfg_raw = str(_dashboard_config().get("public_url") or "")
    cfg_clean = _normalise_public_url(cfg_raw)
    if cfg_clean:
        return cfg_clean, "dashboard.public_url"
    if env_raw.strip():
        return env_raw.strip(), "HERMES_DASHBOARD_PUBLIC_URL"
    if cfg_raw.strip():
        return cfg_raw.strip(), "dashboard.public_url"
    return "", "dashboard.public_url"


def _env_or_cfg(env_name: str, cfg_value: object) -> str:
    """Env wins over config; blank env falls through (plugins/dashboard_auth/_shared.py:53-56)."""
    return os.environ.get(env_name, "").strip() or str(cfg_value or "").strip()


def basic_auth_fix() -> str:
    """Empty when BasicAuthProvider will register, else the fix hint
    (plugins/dashboard_auth/basic/__init__.py:126-133, 206-285)."""
    raw_section = _dashboard_config().get("basic_auth")
    section = raw_section if isinstance(raw_section, dict) else {}
    username = _env_or_cfg("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", section.get("username"))
    password_hash = _env_or_cfg(
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH", section.get("password_hash")
    )
    password = _env_or_cfg("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", section.get("password"))
    if not username or not (password_hash or password):
        return (
            "Set dashboard.basic_auth.username with either dashboard.basic_auth.password or "
            "dashboard.basic_auth.password_hash, or set HERMES_DASHBOARD_BASIC_AUTH_USERNAME with "
            "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD or HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH. "
            "A redirect sign-in provider cannot finish on the Hands host, which serves only the "
            "device routes."
        )
    secret = _env_or_cfg("HERMES_DASHBOARD_BASIC_AUTH_SECRET", section.get("secret"))
    if (
        secret
        and not any(marker in secret for marker in _UNEXPANDED_SHELL_MARKERS)
        and len(secret.encode("utf-8")) < 16
    ):
        return (
            "Set dashboard.basic_auth.secret (or HERMES_DASHBOARD_BASIC_AUTH_SECRET) to at least 16 "
            "bytes, or leave it unset."
        )
    return ""


def _safe_owner_label(value: str) -> str | None:
    if not isinstance(value, str) or any(not char.isprintable() for char in value):
        return None
    label = value.strip()
    if label.isdecimal() or re.match(r"^[A-Za-z][A-Za-z0-9_-]*\s*:", label):
        return None
    return label if label and len(label) <= MAX_OWNER_LABEL_LENGTH else None


def pair_reply(
    ctx,
    name: str,
    *,
    has_seed: bool,
    owner_label: str | None = None,
) -> str:
    """Mint and format a pairing reply for ``name``, or refuse without minting a code."""
    if name == store.RESERVED_NAME:
        return messages.PAIR_NAME_RESERVED
    if not has_seed:
        return messages.NOT_SET_UP
    public_url, source_name = _resolve_public_url()
    if public_url:
        gateway_url = public_url
    else:
        raw_dashboard_url = str(
            ctx.get_config("dashboard_url", default=DEFAULT_DASHBOARD_URL) or ""
        ).strip()
        gateway_url = _normalise_public_url(raw_dashboard_url) or raw_dashboard_url
        source_name = "dashboard_url"
    if not https_or_loopback(gateway_url):
        if _parsed_http_url(gateway_url) is not None:
            return (
                f"{source_name} is {gateway_url}, and the device refuses a non-loopback http "
                "pairing URL. Set dashboard.public_url to the https URL of the Hands host, then run "
                "this again."
            )
        return (
            f"{source_name} is {gateway_url or 'not set'}, which is not a valid https or loopback http "
            "pairing URL. Set dashboard.public_url to the https URL of the Hands host, then run "
            "this again."
        )
    safe_owner_label = _safe_owner_label(owner_label)
    if safe_owner_label is None:
        return messages.PAIR_OWNER_LABEL_REQUIRED
    code = store.mint_pairing_code(name, owner_label=safe_owner_label)
    command = f"hermes-hands pair {gateway_url} --name {shlex.quote(name)} --code={shlex.quote(code)}"
    lines = [f"Pair code: {code}", f"Owner label: {safe_owner_label}", f"Run on the device: {command}"]
    if loopback_url(gateway_url):
        lines.append("Note: a loopback URL pairs only a device on the gateway host itself.")
    return "\n".join(lines)


def _ids(value: object) -> set[str]:
    if isinstance(value, (list, tuple, set, frozenset)):
        items = value
    elif isinstance(value, str):
        items = value.split(",")
    elif value is None:
        items = []
    else:
        items = [value]
    return {str(item).strip() for item in items if str(item).strip()}


def _platform(platform: str, source) -> str:
    value = getattr(source, "platform", None) or platform
    return str(getattr(value, "value", value) or "").lower()


def _in_shared_chat(source) -> bool:
    """A group, channel or thread: core gives its participants one session (session.py:690-725).
    Slack reports a group DM (MPIM) as chat_type dm too (slack/adapter.py:4597, 4698); only a 1:1
    IM has a channel id that starts with D (slack/adapter.py:5463)."""
    chat_type = str(getattr(source, "chat_type", "dm") or "dm").strip().lower()
    if chat_type not in {"", "dm", "direct", "private"}:
        return True
    return _platform("", source) == "slack" and not str(getattr(source, "chat_id", "") or "").startswith("D")


def _caller(platform: str, source) -> str:
    """This command's sender, named as ``targets.current_caller`` names the sender of a tool call."""
    return targets.caller_id(_platform(platform, source), str(getattr(source, "user_id", "") or ""))


def _help_origin(platform: str, source) -> dict | None:
    """A direct, owner-addressable SessionSource, in Hermes's persisted origin shape."""
    if source is None or _in_shared_chat(source):
        return None
    to_dict = getattr(source, "to_dict", None)
    if not callable(to_dict):
        return None
    try:
        origin = to_dict()
    except Exception:
        return None
    if not isinstance(origin, dict):
        return None
    source_platform = _platform(platform, source)
    callback_platform = str(getattr(platform, "value", platform) or "").lower()
    chat_id = getattr(source, "chat_id", None)
    chat_type = getattr(source, "chat_type", None)
    user_id = getattr(source, "user_id", None)
    if (
        source_platform in {"", "local", "cli", "tui", "desktop", "acp"}
        or (callback_platform and callback_platform != source_platform)
        or not isinstance(chat_id, str)
        or not chat_id.strip()
        or not isinstance(chat_type, str)
        or chat_type.strip().lower() != "dm"
        or not isinstance(user_id, str)
        or not user_id.strip()
        or origin.get("platform") != source_platform
        or origin.get("chat_id") != chat_id
        or origin.get("chat_type") != chat_type
        or origin.get("user_id") != user_id
        or any(unicodedata.category(char) == "Cc" for value in (source_platform, chat_id, user_id) for char in value)
    ):
        return None
    try:
        json.dumps(origin, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return origin


def terminal_backend() -> str:
    """The terminal backend Hermes resolves for this profile: config.yaml terminal.backend as written,
    else TERMINAL_ENV from this process's environment, else from the profile .env, else local
    (terminal_scope.py:114-130). A managed-scope pin is not seen; the answer only words /hands use
    and doctor."""
    from agent.secret_scope import load_env_file
    from hermes_cli.config import read_raw_config_readonly
    from hermes_constants import get_hermes_home

    terminal = read_raw_config_readonly().get("terminal")
    if isinstance(terminal, dict) and terminal.get("backend") is not None:
        return str(terminal["backend"])
    profile = load_env_file(get_hermes_home() / ".env")
    return os.environ.get("TERMINAL_ENV", profile.get("TERMINAL_ENV", "local"))


def _is_owner(ctx, platform: str, source) -> bool:
    if source is None and platform in {"cli", "tui", "desktop"}:
        return True
    source_platform = getattr(source, "platform", None)
    if str(getattr(source_platform, "value", source_platform)) == "local":
        return True
    user_id = getattr(source, "user_id", None)
    if not user_id:
        return False
    owners = _ids(ctx.get_config("owner_ids", default=[]))
    if owners:
        return f"{platform}:{user_id}" in owners
    try:
        from gateway.config import load_gateway_config

        config = load_gateway_config()
        platform_config = next(
            (value for key, value in config.platforms.items() if str(getattr(key, "value", key)) == platform),
            None,
        )
        extra = getattr(platform_config, "extra", {}) if platform_config else {}
        allowed = _ids(extra.get("group_allow_admin_from" if _in_shared_chat(source) else "allow_admin_from"))
        return str(user_id) in allowed
    except Exception:
        return False


def _pair_args(raw_args: str) -> list[str]:
    """Split /hands pair arguments with curly quotes read as straight ones. Curly single quotes
    are straightened only when an opening one is present, so an apostrophe inside a name stays
    as typed."""
    table = _STRAIGHT_QUOTES if "\u2018" in raw_args else _STRAIGHT_DOUBLE_QUOTES
    return shlex.split(raw_args.translate(table))


def register_commands(ctx, *, has_seed: bool) -> None:
    def handle(raw_args: str, *, session_id="", session_key="", platform="", source=None) -> str:
        words = raw_args.split(None, 1)
        try:
            args = _pair_args(raw_args) if words and words[0].lower() == "pair" else shlex.split(raw_args)
        except ValueError:
            return "Usage: /hands [status|pair|use|devices|revoke|accept-policy|setup]"
        action = args[0].lower() if args else "status"
        if action == "status":
            devices = store.list_devices()
            relay, cause = "up", []
            if not store.relay_alive():
                try:
                    client.state()
                except client.HandsError as exc:
                    relay, cause = "down", [str(exc)]
                else:
                    if not store.relay_alive():  # the relay started, so it wrote its heartbeat
                        relay, cause = "down", [messages.STORE_SPLIT]
            target = targets.target_for(
                session_key=session_key,
                caller=_caller(platform, source),
                default_target=str(ctx.get_config("default_target", default=targets.SERVER)),
            )
            status = f"Hands: relay {relay}; target {target}; {len(devices)} device(s)."
            alerts = messages.alerts(devices)
            return "\n".join([status, *cause, *alerts])
        if action == "devices" and len(args) == 1:
            devices = store.list_devices()
            if not devices:
                return "No paired devices."
            return "\n".join(f"{d['name']}: {'online' if d['online'] else 'offline'}" for d in devices)
        if action not in {"pair", "use", "revoke", "accept-policy", "setup"}:
            return "Usage: /hands [status|pair|use|devices|revoke|accept-policy|setup]"
        if not _is_owner(ctx, platform, source):
            return "Hands: owner access required."
        if action == "setup" and len(args) == 1:
            user_id = getattr(source, "user_id", None)
            owner_id = f"{platform}:{user_id}" if user_id else "local owner"
            return (
                f"Owner: {owner_id}\n"
                "Select the Hands backend with: hermes config set terminal.backend hands\n"
                "Set desktop placement with: hermes config set bot_desktop.placement gateway\n"
                "Then restart the gateway and the dashboard."
            )
        if action == "pair":
            if len(args) == 4 and args[2] == "--owner-label":
                owner_label = args[3]
            elif len(args) == 2:
                owner_label = None
            else:
                return "Usage: /hands pair <name> --owner-label <human name>"
            if _in_shared_chat(source):
                return messages.PAIR_DIRECT_ONLY
            return pair_reply(
                ctx,
                args[1],
                has_seed=has_seed,
                owner_label=owner_label,
            )
        if len(args) != 2:
            return f"Usage: /hands {action} <name>"
        name = args[1]
        if action == "use":
            if name != "server" and _in_shared_chat(source):
                return messages.USE_DIRECT_ONLY
            backend = terminal_backend()
            if name != "server" and backend != "hands":
                return (
                    f"Hands: terminal.backend is {backend or 'not set'}, not hands, so commands would still run on "
                    "this host. Run hermes config set terminal.backend hands on the gateway host, then restart "
                    "the gateway."
                )
            device = store.get_device(name)
            if name != "server" and device is None:
                return f"No paired device named {name}."
            if not session_key:
                return "Hands: no session key is available."
            owner = _caller(platform, source)
            if targets.has_run(session_id) or targets.is_pending(session_id):
                current = targets.target_for(
                    session_key=session_key,
                    caller=owner,
                    default_target=str(ctx.get_config("default_target", default=targets.SERVER)),
                )
                if name != current:
                    if not targets.has_run(session_id):
                        return "Hands: a machine tool call is still in progress. Wait for it to finish, then try /hands use again."
                    return (
                        f"Hands: this conversation already ran commands on {current}. "
                        f"Start a new conversation with /new, then /hands use {name}."
                    )
            store.set_session_target(session_key, name, owner=owner)
            if name != "server":
                origin = _help_origin(platform, source)
                if origin is not None:
                    store.set_help_origin(device["device_id"], owner, origin, session_key)
            return f"Target set to {name}; it applies from the next command."
        if action == "revoke":
            answer = ctx.ask_choice(f"Revoke {name}?", [{"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}])
            if answer != "yes":
                return "Revoke cancelled."
            return "Device revoked." if store.revoke(name) else f"No paired device named {name}."
        return "Policy accepted." if store.accept_policy(name) else f"No paired device named {name}."

    ctx.register_command("hands", handle, description="Pair and manage Hands devices", args_hint="[action]", argument_mode="mixed")
