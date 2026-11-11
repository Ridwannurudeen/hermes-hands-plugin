import argparse
import types

import pytest

from hands import cli, client, commands, messages


@pytest.mark.parametrize("label", [None, "123456", "telegram:123456", "slack:U123", "discord:person"])
def test_pair_requires_a_human_label_without_minting(monkeypatch, label):
    monkeypatch.setattr(commands, "_resolve_public_url", lambda: ("https://hands.example", "dashboard.public_url"))
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda *args, **kwargs: minted.append(args))
    ctx = types.SimpleNamespace(get_config=lambda *args, **kwargs: ["telegram:123456"])
    reply = commands.pair_reply(ctx, "laptop", has_seed=True, owner_label=label)
    assert "human name" in reply
    assert "--owner-label" in reply
    assert minted == []


@pytest.mark.parametrize("label", [None, "123456", "telegram:123456", "slack:U123", "discord:person"])
def test_cli_pair_requires_a_human_label(monkeypatch, capsys, label):
    monkeypatch.setattr(commands, "_resolve_public_url", lambda: ("https://hands.example", "dashboard.public_url"))
    minted = []
    monkeypatch.setattr(commands.store, "mint_pairing_code", lambda *args, **kwargs: minted.append(args))
    ctx = types.SimpleNamespace(get_config=lambda key, default=None: default, register_cli_command=lambda name, description, setup, handler: callbacks.extend([setup, handler]))
    callbacks = []
    cli.register_cli(ctx, has_seed=True)
    parser = argparse.ArgumentParser()
    callbacks[0](parser)
    args = ["pair", "laptop"]
    if label is not None:
        args.extend(["--owner-label", label])
    callbacks[1](parser.parse_args(args))
    assert "human name" in capsys.readouterr().out
    assert minted == []


def test_screenshot_timeout_and_refusal_have_distinct_plain_messages(monkeypatch):
    monkeypatch.setattr(client, "_post", lambda *args, **kwargs: {"job_id": "job-1"})
    for code, phrase in [("screenshot_timeout", "did not answer in time"), ("screenshot_declined", "said no")]:
        monkeypatch.setattr(client, "job_output", lambda *args, **kwargs: {"done": True, "error": code})
        with pytest.raises(client.HandsError, match=phrase):
            client.request_screenshot("laptop")


def test_protocol_upgrade_hint_points_at_the_plugin_readme():
    reply = messages.protocol_mismatch("older")
    assert reply.startswith("hands: the device speaks older.") and "plugin README" in reply
    assert "pipx" not in reply and "PyPI" not in reply
