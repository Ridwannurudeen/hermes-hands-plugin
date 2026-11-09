import shlex
import sys
import types
from enum import Enum
from pathlib import Path

import pytest

from hands import commands


class Platform(str, Enum):
    LOCAL = "local"
    TELEGRAM = "telegram"
    SLACK = "slack"


class Source:
    def __init__(self, user_id="42", platform=Platform.TELEGRAM, chat_type="dm"):
        self.user_id = user_id
        self.platform = platform
        self.chat_type = chat_type


class DirectSource(Source):
    def __init__(self, user_id="42", platform=Platform.TELEGRAM, chat_id="chat-1"):
        super().__init__(user_id=user_id, platform=platform, chat_type="dm")
        self.chat_id = chat_id

    def to_dict(self):
        return {
            "platform": self.platform.value,
            "chat_id": self.chat_id,
            "chat_type": self.chat_type,
            "user_id": self.user_id,
        }


class Context:
    def __init__(self, owner_ids=None):
        self.owner_ids = owner_ids or []
        self.handler = None
        self.config = {}
        self.choice = None

    def get_config(self, key, default=None):
        return self.config.get(key, self.owner_ids if key == "owner_ids" else default)

    def register_command(self, name, handler, **kwargs):
        self.handler = handler

    def ask_choice(self, question, choices):
        return self.choice


def install_gateway(monkeypatch, extras=None):
    gateway = types.ModuleType("gateway")
    gateway.__path__ = []
    session = types.ModuleType("gateway.session")
    session.Platform = Platform
    config = types.ModuleType("gateway.config")
    config.load_gateway_config = lambda: types.SimpleNamespace(
        platforms={Platform.TELEGRAM: types.SimpleNamespace(extra=extras or {})}
    )
    monkeypatch.setitem(sys.modules, "gateway", gateway)
    monkeypatch.setitem(sys.modules, "gateway.session", session)
    monkeypatch.setitem(sys.modules, "gateway.config", config)


def install_config(monkeypatch, config):
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    hermes_config = types.ModuleType("hermes_cli.config")
    hermes_config.load_config_readonly = lambda: config
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", hermes_config)


def setup(monkeypatch, owner_ids=None, has_seed=True):
    install_gateway(monkeypatch)
    ctx = Context(owner_ids)
    commands.register_commands(ctx, has_seed=has_seed)
    return ctx


def test_local_owner_authorized(monkeypatch):
    ctx = setup(monkeypatch)
    assert commands._is_owner(ctx, "desktop", Source(platform=Platform.LOCAL))


def test_owner_ids_authorized(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    assert commands._is_owner(ctx, "telegram", Source())


def test_platform_admin_allowlist_authorized(monkeypatch):
    install_gateway(monkeypatch, {"allow_admin_from": "7, 42"})
    assert commands._is_owner(Context(), "telegram", Source())


def test_owner_ids_alone_decide_when_set(monkeypatch):
    install_gateway(monkeypatch, {"allow_admin_from": "7"})
    ctx = Context(["telegram:42"])
    assert commands._is_owner(ctx, "telegram", Source(user_id="42"))
    assert not commands._is_owner(ctx, "telegram", Source(user_id="7"))


def test_empty_admin_list_and_falsy_user_refuse(monkeypatch):
    install_gateway(monkeypatch)
    ctx = Context()
    assert not commands._is_owner(ctx, "telegram", Source())
    assert not commands._is_owner(ctx, "telegram", Source(user_id=""))


def test_pair_reply_has_exact_device_command(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    ctx.config["dashboard_url"] = "https://gateway.example"
    install_config(monkeypatch, {"dashboard": {}})
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: "secret-code")
    result = ctx.handler("pair laptop", session_key="s", platform="telegram", source=Source())
    assert "hermes-hands pair https://gateway.example --name laptop --code=secret-code" in result


def test_pairing_label_defaults_to_owner_id_and_can_be_set_by_owner(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    ctx.config["dashboard_url"] = "https://gateway.example"
    install_config(monkeypatch, {"dashboard": {}})
    minted = []
    monkeypatch.setattr(
        commands.store,
        "mint_pairing_code",
        lambda name, *, owner_label: minted.append((name, owner_label)) or "secret-code",
    )

    default = ctx.handler("pair laptop", session_key="s", platform="telegram", source=Source())
    custom = ctx.handler(
        'pair laptop --owner-label "Ridwan"',
        session_key="s",
        platform="telegram",
        source=Source(),
    )

    assert minted == [("laptop", "telegram:42"), ("laptop", "Ridwan")]
    assert "Owner label: telegram:42" in default
    assert "Owner label: Ridwan" in custom
    assert "--owner-label" not in custom.split("Run on the device: ", 1)[1]


def test_the_device_cli_accepts_a_printed_code_that_starts_with_a_dash(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "device"))
    from hermeshands_device import cli as device_cli

    ctx = setup(monkeypatch, ["telegram:42"])
    install_config(monkeypatch, {"dashboard": {"public_url": "https://hands.example.com"}})
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: "-Q3xk_Abc")
    reply = ctx.handler("pair laptop", session_key="s", platform="telegram", source=Source())
    command = shlex.split(reply.split("Run on the device: ", 1)[1])
    calls = []
    monkeypatch.setattr(
        device_cli, "_pair", lambda *args, **kwargs: calls.append((args, kwargs)) or 0
    )
    assert command[0] == "hermes-hands"
    assert device_cli.main(command[1:]) == 0
    assert calls[0][0][0] == "https://hands.example.com"
    assert "-Q3xk_Abc" in calls[0][0]
    assert calls[0][1] == {"force": False}


def test_pair_refuses_without_a_relay_seed(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"], has_seed=False)
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: minted.append(name) or "code")
    reply = ctx.handler("pair laptop", session_key="s", platform="telegram", source=Source())
    assert reply == commands.messages.NOT_SET_UP
    assert minted == []


def test_setup_names_the_backend_and_placement_steps(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    reply = ctx.handler("setup", session_key="s", platform="telegram", source=Source())
    assert "hermes config set terminal.backend hands" in reply
    assert "hermes config set bot_desktop.placement gateway" in reply
    assert "restart the gateway" in reply


def test_use_refuses_a_device_unless_the_backend_is_hands(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "local")
    monkeypatch.setattr(commands.store, "get_device", lambda name: {"name": name})
    targets = []
    monkeypatch.setattr(commands.store, "set_session_target", lambda key, name, owner: targets.append(name))
    refused = ctx.handler("use laptop", session_key="s", platform="telegram", source=Source())
    assert "terminal.backend is local" in refused
    assert "hermes config set terminal.backend hands" in refused
    assert ctx.handler("use server", session_key="s", platform="telegram", source=Source()).startswith(
        "Target set to server"
    )
    assert targets == ["server"]
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    assert ctx.handler("use laptop", session_key="s", platform="telegram", source=Source()).startswith(
        "Target set to laptop"
    )
    assert targets == ["server", "laptop"]


def test_use_refuses_unknown_device(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(commands.store, "get_device", lambda name: None)
    assert "No paired device" in ctx.handler("use missing", session_key="s", platform="telegram", source=Source())


def test_status_appends_device_policy_alerts(monkeypatch):
    ctx = setup(monkeypatch)
    monkeypatch.setattr(commands.store, "list_devices", lambda: [{"name": "laptop", "online": True, "policy_ok": False}])
    monkeypatch.setattr(commands.store, "relay_alive", lambda: True)
    monkeypatch.setattr(commands.messages, "alerts", lambda devices: ["Policy alert: laptop"])
    result = ctx.handler("status")
    assert result == "Hands: relay up; target server; 1 device(s).\nPolicy alert: laptop"


def test_status_asks_a_relay_that_has_no_fresh_heartbeat(monkeypatch):
    ctx = setup(monkeypatch)
    monkeypatch.setattr(commands.store, "list_devices", lambda: [])
    asked = []  # the relay writes its heartbeat before it answers /local/state
    monkeypatch.setattr(commands.store, "relay_alive", lambda: bool(asked))
    monkeypatch.setattr(commands.client, "state", lambda: asked.append(True) or {"relay": True})
    assert ctx.handler("status") == "Hands: relay up; target server; 0 device(s)."
    assert asked == [True]
    monkeypatch.setattr(commands.store, "relay_alive", lambda: False)
    assert ctx.handler("status") == (  # V50: it answers, but its heartbeat is in another store
        "Hands: relay down; target server; 0 device(s).\n"
        + commands.messages.STORE_SPLIT
    )

    def refuse():
        raise commands.client.HandsError("hands: the relay is not reachable.")

    monkeypatch.setattr(commands.client, "state", refuse)
    assert ctx.handler("status") == "Hands: relay down; target server; 0 device(s).\nhands: the relay is not reachable."


def test_use_sets_a_device_only_in_a_direct_chat(monkeypatch):
    """V15: a group, channel or thread shares one session, so a device target set there would let
    every participant run commands on the owner's device."""
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(commands.store, "get_device", lambda name: {"name": name})
    targets = []
    monkeypatch.setattr(commands.store, "set_session_target", lambda key, name, owner: targets.append(name))
    for chat_type in ("group", "channel", "thread"):
        source = Source(chat_type=chat_type)
        reply = ctx.handler("use laptop", session_key="g", platform="telegram", source=source)
        assert reply == commands.messages.USE_DIRECT_ONLY
    group = Source(chat_type="group")
    assert ctx.handler("use server", session_key="g", platform="telegram", source=group).startswith(
        "Target set to server"
    )
    assert ctx.handler("use laptop", session_key="d", platform="telegram", source=Source()).startswith(
        "Target set to laptop"
    )
    assert targets == ["server", "laptop"]


def test_pair_codes_are_given_only_in_a_direct_chat(monkeypatch):
    """V51: a code posted to a group lets any member pair their own machine under that name."""
    ctx = setup(monkeypatch, ["telegram:42"])
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: minted.append(name) or "c")
    reply = ctx.handler("pair desk", session_key="g", platform="telegram", source=Source(chat_type="group"))
    assert reply == commands.messages.PAIR_DIRECT_ONLY and minted == []


def test_the_backend_is_read_the_way_hermes_resolves_it(monkeypatch, tmp_path):
    """V49: config.yaml terminal.backend wins; without it TERMINAL_ENV (the .env or the launch
    environment) selects the backend, as core's terminal_scope does."""
    pytest.importorskip("tools.terminal_scope")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text("model: x\n", encoding="utf-8")
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    assert commands.terminal_backend() == "hands"
    monkeypatch.delenv("TERMINAL_ENV")
    (tmp_path / ".env").write_text("TERMINAL_ENV=hands\n", encoding="utf-8")
    assert commands.terminal_backend() == "hands"
    (tmp_path / "config.yaml").write_text("terminal:\n  backend: local\n", encoding="utf-8")
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    assert commands.terminal_backend() == "local"


def test_use_binds_the_target_to_the_person_who_sent_it(monkeypatch):
    """R13, R14: the target only ever applies to its sender (targets.target_for)."""
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(commands.store, "get_device", lambda name: {"name": name})
    bound = []
    monkeypatch.setattr(
        commands.store, "set_session_target", lambda key, name, owner: bound.append((key, name, owner))
    )
    ctx.handler("use laptop", session_key="d", platform="telegram", source=Source())
    ctx.handler("use laptop", session_key="k", platform="desktop", source=None)
    assert bound == [("d", "laptop", "telegram:42"), ("k", "laptop", "local")]


def test_use_saves_the_validated_owner_chat_origin_for_device_help(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(
        commands.store, "get_device", lambda name: {"name": name, "device_id": "device-1"}
    )
    targets, origins = [], []
    monkeypatch.setattr(
        commands.store,
        "set_session_target",
        lambda key, name, owner: targets.append((key, name, owner)),
    )
    monkeypatch.setattr(
        commands.store,
        "set_help_origin",
        lambda device_id, owner, origin, session_key: origins.append(
            (device_id, owner, origin, session_key)
        ),
    )

    source = DirectSource()
    reply = ctx.handler("use laptop", session_key="chat-session", platform="telegram", source=source)
    assert reply.startswith("Target set to laptop")
    assert targets == [("chat-session", "laptop", "telegram:42")]
    assert origins == [
        (
            "device-1",
            "telegram:42",
            {
                "platform": "telegram",
                "chat_id": "chat-1",
                "chat_type": "dm",
                "user_id": "42",
            },
            "chat-session",
        )
    ]


def test_use_does_not_save_an_unvalidated_or_foreign_help_origin(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(
        commands.store, "get_device", lambda name: {"name": name, "device_id": "device-1"}
    )
    monkeypatch.setattr(commands.store, "set_session_target", lambda *args, **kwargs: None)
    saved = []
    monkeypatch.setattr(
        commands.store,
        "set_help_origin",
        lambda *args: saved.append(args),
    )

    class BadSource(DirectSource):
        def to_dict(self):
            return {"platform": "telegram", "chat_id": "", "chat_type": "dm", "user_id": "42"}

    assert ctx.handler(
        "use laptop", session_key="chat-session", platform="telegram", source=BadSource()
    ).startswith("Target set to laptop")
    assert ctx.handler(
        "use laptop", session_key="other-session", platform="telegram", source=DirectSource("7")
    ) == "Hands: owner access required."
    assert saved == []


def test_a_slack_group_dm_is_a_shared_chat(monkeypatch):
    """R14: Slack reports a group DM as chat_type dm; only a 1:1 IM's channel id starts with D."""
    ctx = setup(monkeypatch, ["slack:U1"])
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(commands.store, "get_device", lambda name: {"name": name})
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: minted.append(name) or "c")
    group_dm, im = Source("U1", Platform.SLACK), Source("U1", Platform.SLACK)
    group_dm.chat_id, im.chat_id = "G0MPIM", "D0IM"
    reply = ctx.handler("use laptop", session_key="g", platform="slack", source=group_dm)
    assert reply == commands.messages.USE_DIRECT_ONLY
    reply = ctx.handler("pair desk", session_key="g", platform="slack", source=group_dm)
    assert reply == commands.messages.PAIR_DIRECT_ONLY and minted == []
    assert commands._in_shared_chat(im) is False and commands._in_shared_chat(Source()) is False


def test_no_device_can_be_named_server(monkeypatch):
    """Critic: a device called server could never be targeted; /hands use server means the host."""
    ctx = setup(monkeypatch, ["telegram:42"])
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda name, **kwargs: minted.append(name) or "c")
    reply = ctx.handler("pair server", session_key="d", platform="telegram", source=Source())
    assert reply == commands.messages.PAIR_NAME_RESERVED and minted == []


def test_status_shows_the_target_that_applies_to_the_sender(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    monkeypatch.setattr(commands.store, "list_devices", lambda: [])
    monkeypatch.setattr(commands.store, "relay_alive", lambda: True)
    monkeypatch.setattr(commands.store, "get_session_target", lambda key: ("laptop", "telegram:42"))
    owner = ctx.handler("status", session_key="g", platform="telegram", source=Source())
    guest = ctx.handler("status", session_key="g", platform="telegram", source=Source(user_id="7"))
    assert "target laptop;" in owner and "target server;" in guest


def test_revoke_requires_exact_yes(monkeypatch):
    ctx = setup(monkeypatch, ["telegram:42"])
    calls = []
    monkeypatch.setattr(commands.store, "revoke", lambda name: calls.append(name) or True)
    ctx.choice = "Yes"
    assert ctx.handler("revoke laptop", session_key="s", platform="telegram", source=Source()) == "Revoke cancelled."
    assert not calls
    ctx.choice = "yes"
    assert ctx.handler("revoke laptop", session_key="s", platform="telegram", source=Source()) == "Device revoked."
    assert calls == ["laptop"]


def test_pair_command_and_cli_agree_on_urls_env_overrides_and_refusals(monkeypatch, capsys):
    """A7: /hands pair and hermes hands pair print the same URL (including HERMES_DASHBOARD_PUBLIC_URL)
    and refuse the same bad URLs without minting codes."""
    import argparse
    from hands import cli

    minted = []
    monkeypatch.setattr(
        commands.store,
        "mint_pairing_code",
        lambda name, **kwargs: minted.append((name, kwargs.get("owner_label"))) or "pair-code",
    )

    def run_both(cfg, *, dashboard_url=None, name="laptop", owner_label=None):
        install_config(monkeypatch, cfg)
        chat_ctx = setup(monkeypatch, ["telegram:42"])
        cli_config = {"owner_ids": ["telegram:42"]}
        if dashboard_url is not None:
            cli_config["dashboard_url"] = dashboard_url
        c_ctx = type(
            "CliCtx",
            (),
            {
                "config": cli_config,
                "get_config": lambda self, k, default=None: self.config.get(k, default),
                "register_cli_command": lambda self, n, h, s, fn: setattr(self, "setup_fn", s)
                or setattr(self, "handler", fn),
            },
        )()
        if dashboard_url is not None:
            chat_ctx.config["dashboard_url"] = dashboard_url
        cli.register_cli(c_ctx, has_seed=True)
        parser = argparse.ArgumentParser()
        c_ctx.setup_fn(parser)
        chat_args = f"pair {shlex.quote(name)}"
        cli_args = ["pair", name]
        if owner_label is not None:
            chat_args += f" --owner-label {shlex.quote(owner_label)}"
            cli_args.extend(["--owner-label", owner_label])
        chat_out = chat_ctx.handler(chat_args, session_key="s", platform="telegram", source=Source())
        c_ctx.handler(parser.parse_args(cli_args))
        cli_out = capsys.readouterr().out.rstrip("\n")
        return chat_out, cli_out

    # 1. HERMES_DASHBOARD_PUBLIC_URL overrides dashboard.public_url and strips trailing slash.
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "https://env.example.com/")
    chat_out, cli_out = run_both({"dashboard": {"public_url": "https://cfg.example.com"}})
    assert chat_out == cli_out
    assert "hermes-hands pair https://env.example.com --name laptop --code=pair-code" in chat_out
    assert len(minted) == 2

    # 2. Non-loopback http in HERMES_DASHBOARD_PUBLIC_URL overrides valid config and is refused by both.
    minted.clear()
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "http://env.example.com")
    chat_out, cli_out = run_both({"dashboard": {"public_url": "https://cfg.example.com"}})
    assert chat_out == cli_out
    assert "refuses a non-loopback http pairing URL" in chat_out
    assert minted == []

    # 3. Non-loopback http in dashboard.public_url is refused by both.
    monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
    chat_out, cli_out = run_both({"dashboard": {"public_url": "http://hands.example.com"}})
    assert chat_out == cli_out
    assert chat_out.startswith("dashboard.public_url is http://hands.example.com")
    assert minted == []

    # 4. Malformed dashboard.public_url (missing scheme) is refused instead of falling back to loopback.
    chat_out, cli_out = run_both({"dashboard": {"public_url": "hands.example.com"}})
    assert chat_out == cli_out
    assert "hands.example.com" in chat_out and "Pair code:" not in chat_out
    assert minted == []

    # 5. Non-loopback http dashboard_url when public_url is unset is refused by both.
    chat_out, cli_out = run_both({"dashboard": {}}, dashboard_url="http://192.168.1.20:9119")
    assert chat_out == cli_out
    assert "http://192.168.1.20:9119" in chat_out and minted == []

    # 6. Loopback fallback and reserved name "server" agree too.
    chat_out, cli_out = run_both({"dashboard": {}}, dashboard_url="http://127.0.0.1:9119/")
    assert chat_out == cli_out
    assert "hermes-hands pair http://127.0.0.1:9119 --name laptop --code=pair-code" in chat_out
    assert "a loopback URL pairs only a device on the gateway host itself" in chat_out

    chat_out, cli_out = run_both(
        {"dashboard": {"public_url": "https://hands.example.com"}}, owner_label="Ridwan"
    )
    assert chat_out == cli_out and "Owner label: Ridwan" in chat_out

    minted.clear()
    chat_out, cli_out = run_both({"dashboard": {"public_url": "https://hands.example.com"}}, name="server")
    assert chat_out == cli_out == commands.messages.PAIR_NAME_RESERVED
    assert minted == []


def test_public_url_and_basic_auth_resolution_match_hermes_core(monkeypatch, tmp_path):
    """A7: verify against real Hermes v0.23.0 prefix.resolve_public_url and basic._settings."""
    prefix = pytest.importorskip("hermes_cli.dashboard_auth.prefix")
    basic = pytest.importorskip("plugins.dashboard_auth.basic")
    shared = pytest.importorskip("plugins.dashboard_auth._shared")

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for var in (
        "HERMES_DASHBOARD_PUBLIC_URL",
        "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH",
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD",
        "HERMES_DASHBOARD_BASIC_AUTH_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)

    (tmp_path / "config.yaml").write_text(
        "dashboard:\n  public_url: https://cfg.example.com/\n  basic_auth:\n    username: cfguser\n",
        encoding="utf-8",
    )
    assert commands._resolve_public_url()[0] == prefix.resolve_public_url() == "https://cfg.example.com"
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "https://env.example.com/")
    assert commands._resolve_public_url()[0] == prefix.resolve_public_url() == "https://env.example.com"
    # Malformed env falls through to valid config in core (prefix.py:128-137).
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "missing-scheme.example.com")
    assert commands._resolve_public_url()[0] == prefix.resolve_public_url() == "https://cfg.example.com"

    # BasicAuthProvider skips until password or password_hash is provided, then registers with env override.
    with pytest.raises(shared.SkipRegistration):
        basic._settings()
    assert commands.basic_auth_fix()

    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "hunter2")
    assert basic.BasicAuthProvider(**basic._settings()) is not None
    assert not commands.basic_auth_fix()

    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_SECRET", "short")
    with pytest.raises(ValueError):
        basic.BasicAuthProvider(**basic._settings())
    assert commands.basic_auth_fix()
