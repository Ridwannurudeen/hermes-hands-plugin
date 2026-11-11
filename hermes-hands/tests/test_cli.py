import argparse
import sys
import types

import pytest

from hands import cli


class Context:
    def __init__(self):
        self.config = {}
        self.set_calls = []

    def register_cli_command(self, name, help, setup_fn, handler_fn):
        self.setup_fn = setup_fn
        self.handler = handler_fn

    def set_config(self, key, value):
        self.set_calls.append((key, value))

    def get_config(self, key, default=None):
        return self.config.get(key, default)


def test_setup_writes_seed_once_and_owner(monkeypatch, capsys):
    calls = []
    secret = {"value": None}
    secret_scope = types.ModuleType("agent.secret_scope")
    secret_scope.get_secret = lambda key: secret["value"]
    wizard = types.ModuleType("hermes_cli.gateway_setup_wizard")

    def save_env_values(**values):
        calls.append(values)
        secret["value"] = values["HANDS_RELAY_SEED"]

    wizard.save_env_values = save_env_values
    agent = types.ModuleType("agent")
    agent.__path__ = []
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", secret_scope)
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.gateway_setup_wizard", wizard)
    monkeypatch.setattr("builtins.input", lambda prompt: "12345")
    ctx = Context()
    cli.register_cli(ctx, has_seed=True)
    args = types.SimpleNamespace(hands_action="setup")
    ctx.handler(args)
    ctx.handler(args)
    assert len(calls) == 1
    assert len(calls[0]["HANDS_RELAY_SEED"]) == 64
    assert ctx.set_calls == [("owner_ids", ["telegram:12345"])] * 2
    out = capsys.readouterr().out
    assert "hermes config set terminal.backend hands" in out
    assert "hermes config set bot_desktop.placement gateway" in out
    assert "restart the gateway" in out
    assert "Optional owner opt-in for witness H help" in out
    assert "hermes config set plugins.entries.hermes-hands.allow_gateway_injection true" in out
    assert "quoted device text as a user message" in out
    assert "starts an agent turn" in out
    assert "cannot guarantee that the model will avoid tool calls" in out


def test_setup_prints_the_backend_and_placement_steps_even_if_the_prompt_is_aborted(
    monkeypatch, capsys
):
    secret_scope = types.ModuleType("agent.secret_scope")
    secret_scope.get_secret = lambda key: "seed"
    agent = types.ModuleType("agent")
    agent.__path__ = []
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    wizard = types.ModuleType("hermes_cli.gateway_setup_wizard")
    wizard.save_env_values = lambda **values: None
    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", secret_scope)
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.gateway_setup_wizard", wizard)

    def aborted(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", aborted)
    ctx = Context()
    cli.register_cli(ctx, has_seed=True)
    try:
        ctx.handler(types.SimpleNamespace(hands_action="setup"))
    except EOFError:
        pass
    out = capsys.readouterr().out
    assert "Relay seed is already set." in out
    assert "hermes config set terminal.backend hands" in out
    assert "hermes config set bot_desktop.placement gateway" in out


def install_doctor_modules(monkeypatch, config):
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    config_module = types.ModuleType("hermes_cli.config")
    config_module.load_config_readonly = lambda: config
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config_module)
    backend = (config.get("terminal") or {}).get("backend") or ""
    monkeypatch.setattr(cli.commands, "terminal_backend", lambda: backend)


def run_doctor_rc(capsys, dashboard_url="http://127.0.0.1:9119"):
    ctx = Context()
    ctx.config["dashboard_url"] = dashboard_url
    cli.register_cli(ctx, has_seed=True)
    rc = ctx.handler(types.SimpleNamespace(hands_action="doctor"))
    return rc, capsys.readouterr().out.splitlines()


def run_doctor(capsys, dashboard_url="http://127.0.0.1:9119"):
    _, lines = run_doctor_rc(capsys, dashboard_url=dashboard_url)
    return lines


def healthy_config():
    return {
        "terminal": {"backend": "hands"},
        "plugins": {"entries": {"hermes-hands": {"allow_gateway_injection": True}}},
        "dashboard": {
            "public_url": "https://hands.example",
            "basic_auth": {"username": "owner", "password_hash": "scrypt$n=1,r=1,p=1$c2FsdA$aGFzaA"},
        },
    }


def test_doctor_reports_each_deployment_check(monkeypatch, capsys):
    install_doctor_modules(monkeypatch, healthy_config())
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True, "devices": [], "alerts": []})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    lines = run_doctor(capsys)
    assert len(lines) == 7
    assert all(line.startswith("PASS ") for line in lines)
    assert [line.split(":")[0] for line in lines] == [
        "PASS terminal.backend is hands",
        "PASS dashboard_url is loopback",
        "PASS Relay answers at dashboard_url",
        "PASS dashboard.public_url is https or unset",
        "PASS dashboard.basic_auth on the public host",
        "PASS Relay heartbeat row is visible after /local/state",
        "PASS Witness H help gateway injection is explicitly enabled",
    ]


def test_doctor_names_the_backend_and_the_relay_refusal(monkeypatch, capsys):
    config = healthy_config()
    config["terminal"]["backend"] = "local"
    install_doctor_modules(monkeypatch, config)

    def refuse():
        raise cli.client.HandsError("hands: the relay is not reachable.")

    monkeypatch.setattr(cli.client, "state", refuse)
    monkeypatch.setattr(cli.store, "relay_alive", lambda: False)
    lines = run_doctor(capsys)
    assert lines[0] == (
        "FAIL terminal.backend is hands: It is local. Run hermes config set terminal.backend hands, "
        "then restart the gateway."
    )
    assert lines[2] == "FAIL Relay answers at dashboard_url: hands: the relay is not reachable."
    assert lines[5] == "FAIL Relay heartbeat row is visible after /local/state: Fix the relay check first."


def test_doctor_reads_the_heartbeat_only_after_the_relay_answered(monkeypatch, capsys):
    """/local/state starts the relay, which writes its first heartbeat row before replying."""
    install_doctor_modules(monkeypatch, healthy_config())
    calls = []
    monkeypatch.setattr(cli.client, "state", lambda: calls.append("state") or {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: calls.append("heartbeat") or "state" in calls)
    assert run_doctor(capsys)[5] == "PASS Relay heartbeat row is visible after /local/state"
    assert calls == ["state", "heartbeat"]


def test_doctor_blames_the_plugin_data_dir_only_when_the_relay_answers(monkeypatch, capsys):
    install_doctor_modules(monkeypatch, healthy_config())
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True, "devices": [], "alerts": []})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: False)
    assert run_doctor(capsys)[5] == (
        "FAIL Relay heartbeat row is visible after /local/state: The relay answered but wrote no "
        "heartbeat row in this HERMES_HOME, so the gateway and the dashboard use different plugin "
        "data directories."
    )


def test_doctor_fails_an_http_public_url(monkeypatch, capsys):
    """The device refuses a non-loopback http pairing URL, so doctor must not pass one."""
    config = healthy_config()
    config["dashboard"]["public_url"] = "http://hands.example"
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    lines = run_doctor(capsys)
    assert lines[3] == (
        "FAIL dashboard.public_url is https or unset: It is http://hands.example. The device refuses a "
        "non-loopback http pairing URL, so set dashboard.public_url to the https URL of the Hands host."
    )


def test_doctor_fails_a_non_loopback_dashboard_url(monkeypatch, capsys):
    """The local bearer and the job scripts travel to dashboard_url, so it must stay on loopback."""
    install_doctor_modules(monkeypatch, healthy_config())
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    lines = run_doctor(capsys, dashboard_url="http://192.168.1.20:9119")
    assert lines[1] == (
        "FAIL dashboard_url is loopback: It is http://192.168.1.20:9119. The gateway sends its local "
        "bearer and every job script there, so it must be a loopback address such as "
        "http://127.0.0.1:9119."
    )


def test_doctor_fails_a_public_host_without_basic_auth(monkeypatch, capsys):
    """A redirect sign-in provider cannot finish on the Hands host, which serves only device routes."""
    config = healthy_config()
    config["dashboard"].pop("basic_auth")
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    assert run_doctor(capsys)[4] == (
        "FAIL dashboard.basic_auth on the public host: Set dashboard.basic_auth.username with "
        "either dashboard.basic_auth.password or dashboard.basic_auth.password_hash, or set "
        "HERMES_DASHBOARD_BASIC_AUTH_USERNAME with HERMES_DASHBOARD_BASIC_AUTH_PASSWORD or "
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH. A redirect sign-in provider cannot finish on "
        "the Hands host, which serves only the device routes."
    )


def test_doctor_passes_a_loopback_deployment_without_basic_auth(monkeypatch, capsys):
    config = healthy_config()
    config["dashboard"] = {}
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    lines = run_doctor(capsys)
    assert lines[3].startswith("PASS dashboard.public_url")
    assert lines[4].startswith("PASS dashboard.basic_auth")


def test_status_asks_a_relay_that_has_no_fresh_heartbeat(monkeypatch, capsys):
    alive = []  # the relay writes its heartbeat before it answers /local/state
    monkeypatch.setattr(cli.store, "relay_alive", lambda: bool(alive))
    monkeypatch.setattr(cli.store, "list_devices", lambda: [])
    monkeypatch.setattr(
        cli.client, "state", lambda: alive.append(True) or {"relay": True, "devices": [], "alerts": []}
    )
    ctx = Context()
    cli.register_cli(ctx, has_seed=True)
    ctx.handler(types.SimpleNamespace(hands_action="status"))
    assert capsys.readouterr().out == "Relay: up\n"
    alive.clear()
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True, "devices": [], "alerts": []})
    ctx.handler(types.SimpleNamespace(hands_action="status"))  # V50: it answers, its row is elsewhere
    assert capsys.readouterr().out == f"Relay: down\n{cli.messages.STORE_SPLIT}\n"

    def refuse():
        raise cli.client.HandsError("hands: the relay is not reachable.")

    monkeypatch.setattr(cli.client, "state", refuse)
    ctx.handler(types.SimpleNamespace(hands_action="status"))
    assert capsys.readouterr().out == "Relay: down\nhands: the relay is not reachable.\n"


def test_pair_cli_mints_code_and_prints_device_command(monkeypatch, capsys):
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    config = types.ModuleType("hermes_cli.config")
    config.load_config_readonly = lambda: {"dashboard": {"public_url": "https://hands.example.com"}}
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
    minted = []
    monkeypatch.setattr(
        cli.store,
        "mint_pairing_code",
        lambda name, *, owner_label: minted.append((name, owner_label)) or "pair-code",
    )
    ctx = Context()
    cli.register_cli(ctx, has_seed=True)
    parser = argparse.ArgumentParser()
    ctx.setup_fn(parser)
    args = parser.parse_args(["pair", "my laptop", "--owner-label", "Sam"])

    ctx.handler(args)

    assert minted == [("my laptop", "Sam")]
    assert capsys.readouterr().out == (
        "Pair code: pair-code\n"
        "Owner label: Sam\n"
        "Run on the device: hermes-hands pair https://hands.example.com --name 'my laptop' --code=pair-code\n"
    )


def test_pair_cli_refuses_without_a_relay_seed(monkeypatch, capsys):
    minted = []
    monkeypatch.setattr(cli.store, "mint_pairing_code", lambda name: minted.append(name) or "pair-code")
    ctx = Context()
    cli.register_cli(ctx, has_seed=False)
    parser = argparse.ArgumentParser()
    ctx.setup_fn(parser)

    ctx.handler(parser.parse_args(["pair", "laptop", "--owner-label", "Sam"]))

    assert capsys.readouterr().out == cli.messages.NOT_SET_UP + "\n"
    assert minted == []


def test_pair_cli_falls_back_to_dashboard_url(monkeypatch, capsys):
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    config = types.ModuleType("hermes_cli.config")
    config.load_config_readonly = lambda: {}
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
    monkeypatch.setattr(cli.store, "mint_pairing_code", lambda name, **kwargs: "pair-code")
    ctx = Context()
    ctx.config["dashboard_url"] = "http://127.0.0.1:9119"
    cli.register_cli(ctx, has_seed=True)
    parser = argparse.ArgumentParser()
    ctx.setup_fn(parser)

    ctx.handler(parser.parse_args(["pair", "laptop", "--owner-label", "Sam"]))

    out = capsys.readouterr().out
    assert "hermes-hands pair http://127.0.0.1:9119 --name laptop --code=pair-code" in out
    assert "a loopback URL pairs only a device on the gateway host itself" in out


def test_pair_cli_refuses_an_http_public_url(monkeypatch, capsys):
    """The device refuses a non-loopback http pairing URL, so this printer must not mint one."""
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    config = types.ModuleType("hermes_cli.config")
    config.load_config_readonly = lambda: {"dashboard": {"public_url": "http://hands.example.com"}}
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
    minted = []
    monkeypatch.setattr(cli.store, "mint_pairing_code", lambda name: minted.append(name) or "pair-code")
    ctx = Context()
    cli.register_cli(ctx, has_seed=True)
    parser = argparse.ArgumentParser()
    ctx.setup_fn(parser)

    ctx.handler(parser.parse_args(["pair", "laptop", "--owner-label", "Sam"]))

    out = capsys.readouterr().out
    assert out.startswith(
        "dashboard.public_url is http://hands.example.com, and the device refuses a non-loopback http "
        "pairing URL."
    )
    assert minted == []


def test_pair_cli_ignores_an_undeclared_public_url_setting(monkeypatch, capsys):
    """plugin.yaml declares no public_url, so only dashboard.public_url and dashboard_url count here."""
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    config = types.ModuleType("hermes_cli.config")
    config.load_config_readonly = lambda: {"dashboard": {"public_url": "https://hands.example.com"}}
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
    monkeypatch.setattr(cli.store, "mint_pairing_code", lambda name, **kwargs: "pair-code")
    ctx = Context()
    ctx.config["public_url"] = "http://10.0.0.5:1234"
    cli.register_cli(ctx, has_seed=True)
    parser = argparse.ArgumentParser()
    ctx.setup_fn(parser)

    ctx.handler(parser.parse_args(["pair", "laptop", "--owner-label", "Sam"]))

    assert (
        "hermes-hands pair https://hands.example.com --name laptop --code=pair-code"
        in capsys.readouterr().out
    )


def test_doctor_exits_nonzero_when_any_check_fails(monkeypatch, capsys):
    """A6: hermes hands doctor returns 0 when all checks pass and non-zero when any check fails."""
    monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
    install_doctor_modules(monkeypatch, healthy_config())
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True, "devices": [], "alerts": []})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    rc, lines = run_doctor_rc(capsys)
    assert rc == 0 and all(line.startswith("PASS ") for line in lines)

    broken = healthy_config()
    broken["terminal"]["backend"] = "local"
    install_doctor_modules(monkeypatch, broken)
    rc, lines = run_doctor_rc(capsys)
    assert rc == 1 and lines[0].startswith("FAIL ")


def test_doctor_fails_a_loopback_http_public_url(monkeypatch, capsys):
    """A6: dashboard.public_url must be https or unset; a loopback http public_url fails."""
    monkeypatch.delenv("HERMES_DASHBOARD_PUBLIC_URL", raising=False)
    config = healthy_config()
    config["dashboard"]["public_url"] = "http://127.0.0.1:9119"
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    rc, lines = run_doctor_rc(capsys)
    assert rc == 1
    assert lines[3].startswith("FAIL dashboard.public_url is https or unset: It is http://127.0.0.1:9119")


def test_doctor_honors_env_overrides_for_public_url_and_basic_auth(monkeypatch, capsys):
    """A7: HERMES_DASHBOARD_PUBLIC_URL and HERMES_DASHBOARD_BASIC_AUTH_* override config.yaml."""
    config = healthy_config()
    config["dashboard"] = {"public_url": "http://broken.example"}
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)

    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "https://hands.example.com/")
    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", "owner")
    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "s3cret")
    rc, lines = run_doctor_rc(capsys)
    assert rc == 0 and all(line.startswith("PASS ") for line in lines)

    # Blank env does not shadow config.yaml (prefix.py:119-120, 128-134).
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "   ")
    rc, lines = run_doctor_rc(capsys)
    assert rc == 1 and lines[3].startswith("FAIL dashboard.public_url is https or unset: It is http://broken.example")

    # Secret under 16 bytes is rejected by BasicAuthProvider.__init__ (basic/__init__.py:131-132).
    monkeypatch.setenv("HERMES_DASHBOARD_PUBLIC_URL", "https://hands.example.com")
    monkeypatch.setenv("HERMES_DASHBOARD_BASIC_AUTH_SECRET", "too-short")
    rc, lines = run_doctor_rc(capsys)
    assert rc == 1 and lines[4].startswith("FAIL dashboard.basic_auth on the public host:")


@pytest.mark.parametrize("permission", [None, False, "true", True], ids=["absent", "false", "string", "true"])
def test_doctor_requires_explicit_entry_permission_for_witness_help(monkeypatch, capsys, permission):
    config = healthy_config()
    entry = config["plugins"]["entries"]["hermes-hands"]
    if permission is None:
        entry.pop("allow_gateway_injection")
    else:
        entry["allow_gateway_injection"] = permission
    entry["settings"] = {"allow_gateway_injection": True}
    install_doctor_modules(monkeypatch, config)
    monkeypatch.setattr(cli.client, "state", lambda: {"relay": True})
    monkeypatch.setattr(cli.store, "relay_alive", lambda: True)
    rc, lines = run_doctor_rc(capsys)
    help_lines = [line for line in lines if "Witness H help" in line]
    assert len(help_lines) == 1
    if permission is True:
        assert rc == 0
        assert help_lines[0].startswith("PASS ")
    else:
        assert rc == 0
        assert all(line.startswith("PASS ") for line in lines[:6])
        assert help_lines[0].startswith("WARN Witness H help is unavailable")
        assert "hermes config set plugins.entries.hermes-hands.allow_gateway_injection true" in help_lines[0]
        assert "Optional owner opt-in" in help_lines[0]
