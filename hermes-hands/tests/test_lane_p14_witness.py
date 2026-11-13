"""Approval destinations and source-code credential discrimination."""

import json
import os
from pathlib import PurePosixPath

import pytest

pytest.importorskip("tools.environments.base")

from hands import environment, messages, witness  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401
from test_witness_hardening import DEVICE  # noqa: E402


@pytest.mark.parametrize("content", [
    "token: str", "token = None", "token = 0", "token = config.token", "password = False",
    'token = os.getenv("TOKEN")', 'token = os.environ["TOKEN"]',
    'token = os.environ.get("TOKEN")', "token = process.env.TOKEN", "token = $ENV{TOKEN}",
])
def test_ordinary_source_constructs_are_approved(monkeypatch, content):
    from agent.redact import redact_sensitive_text

    assert redact_sensitive_text(content, force=True) == content
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert not witness._contains_secret(content, source=True)
    assert witness.pre_tool_call(
        object(), "write_file", {"path": "/notes.py", "content": content}
    )["action"] == "approve"


@pytest.mark.parametrize("content", [
    'token = "ghp_' + "a" * 36 + '"', 'password = "hunter2"',
    "token = k9XjN2qV6rY4sW8aB3cD7eF1gH5iL0mP", 'token="os.environXYZ123"',
    'token="process.envXYZ123"', 'token="os.getenv(TOKEN)XYZ123"',
    'token="os.environ[TOKEN]XYZ123"', 'token="config.token"',
    'token="os.getenv(TOKEN) + literal"', 'token="process.env.TOKEN + literal"',
    pytest.param("token=k9XjN2qV6rY4sW8aB3cD7eF1gH5iL0mP.a7QzJ2vN4xB6cD8eF0gH3iK5", id="dotted-opaque"),
    'token="process.envXYZ123.TOKEN"', 'token="os.environXYZ123.TOKEN"',
    "token=os.environXYZ123", "token=process.envXYZ123",
    'token=os.getenv("TOKEN")XYZ123', 'token=os.environ["TOKEN"]XYZ123',
    'token=os.getenv("TOKEN") + "literal"', 'token=process.env.TOKEN + "literal"',
    "token=process.envXYZ123.TOKEN", "token=os.environXYZ123.TOKEN",
])
@pytest.mark.parametrize("prefix", ["", "ordinary notes " * 40])
def test_credential_literals_and_environment_lookalikes_are_refused(monkeypatch, content, prefix):
    from agent.redact import redact_sensitive_text

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    value = prefix + content
    expected = (
        messages.WITNESS_SECRET_HIDDEN if redact_sensitive_text(value, force=True) != value
        else messages.WITNESS_SECRET_BLOCKED
    )
    assert witness.pre_tool_call(
        object(), "write_file", {"path": "/notes.py", "content": value}
    ) == {"action": "block", "message": expected}


def test_hands_only_secret_refusal_does_not_claim_core_hides_it(monkeypatch):
    from agent.redact import redact_sensitive_text

    content = 'password = "hunter2"'
    assert redact_sensitive_text(content, force=True) == content
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    result = witness.pre_tool_call(object(), "write_file", {"path": "/notes.py", "content": content})
    assert result == {"action": "block", "message": messages.WITNESS_SECRET_BLOCKED}
    assert "would hide" not in result["message"]


@pytest.mark.parametrize("content,approved", [
    ("token: str", True), ("token = None", True), ("token = 0", True),
    ("token = config.token", True), ("password = False", True),
    ('token = os.getenv("TOKEN")', True), ('token = os.environ["TOKEN"]', True),
    ("token = process.env.TOKEN", True), ('password = "hunter2"', False),
    ('token="os.environXYZ123"', False), ('token = "ghp_' + "a" * 36 + '"', False),
    ("token=os.environXYZ123", False),
    pytest.param("token=k9XjN2qV6rY4sW8aB3cD7eF1gH5iL0mP.a7QzJ2vN4xB6cD8eF0gH3iK5", False, id="dotted-opaque"),
])
def test_registered_write_handler_enforces_credential_policy(dispatch, monkeypatch, content, approved):
    d = dispatch
    monkeypatch.setattr(d.ctx, "session_surface", lambda: "telegram")
    target = d.home / "work" / "source.py"
    result = d.invoke("write_file", {"path": f"{d.base}/work/source.py", "content": content})
    if approved:
        assert not json.loads(result).get("error"), result
        assert len(d.cards) == 1 and d.answers and d.jobs
        assert target.read_bytes() == content.encode("utf-8")
    else:
        assert messages.WITNESS_SECRET_BLOCKED in result
        assert d.cards == [] and d.jobs == [] and not target.exists()


@pytest.mark.parametrize("changed", [False, True], ids=["approved", "boundary-mutation"])
def test_registered_vision_handler_binds_image_url_for_device_fallback(dispatch, monkeypatch, changed):
    from tools import image_source, vision_tools

    d = dispatch
    image = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'
    (d.home / "work" / "image.svg").write_bytes(image)
    (d.home / "work" / "other.svg").write_bytes(image)
    monkeypatch.setattr(vision_tools, "_should_use_native_vision_fast_path", lambda: False)
    # Model the POSIX gateway's path spelling on the Windows test host, and
    # exercise only sandbox reads rather than host-cache lookups.
    monkeypatch.setattr(image_source, "Path", PurePosixPath)
    monkeypatch.setattr(environment, "Path", PurePosixPath)
    monkeypatch.setattr(image_source, "_permitted_host_read_target", lambda path, ctx: None)

    async def analyze(kind, source, prompt, model, stage):
        # Stop after the actual resolver's sandbox read; no network or auxiliary model.
        from tools.image_source import ResolveContext, resolve_image_source

        try:
            result = await resolve_image_source(source, ResolveContext(task_id="p8"))
            return json.dumps({"success": True, "bytes": len(result.data)})
        except Exception as exc:
            return json.dumps({"success": False, "error": str(exc)})

    monkeypatch.setattr(vision_tools, "_run_analysis", analyze)
    execute = environment.HandsEnvironment.execute
    mutations = []

    def mutate(env, command, cwd="", **kwargs):
        if changed and command.startswith("head -c "):
            command = command.replace("image.svg", "other.svg")
            mutations.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    result = json.loads(d.call("vision_analyze", {
        "image_url": f"{d.base}/work/image.svg", "question": "Describe",
    }))
    assert f"image_url={d.base}/work/image.svg" in d.cards[0]
    if changed:
        assert mutations
        assert result == {
            "success": False,
            "error": (
                f"could not read '{d.base}/work/image.svg' inside the sandbox "
                f"({messages.WITNESS_CALL_CHANGED[:200]})"
            ),
        }
        assert d.jobs == []
    else:
        assert result == {"success": True, "bytes": len(image)}
        assert any("image.svg" in job["script"] for job in d.jobs)


def test_media_destination_keys_match_registered_schemas():
    from tools.registry import registry

    for tool, key in (("vision_analyze", "image_url"), ("video_analyze", "video_url")):
        assert witness._DESTINATION_KEYS[tool] == key
        schema = registry.get_schema(tool)
        assert key in schema["parameters"]["required"]


@pytest.mark.parametrize("path_args", [{}, {"path": ""}, {"path": None}, {"path": "   "}])
def test_search_effective_default_is_shown_and_executed(dispatch, monkeypatch, path_args):
    d = dispatch
    execute = environment.HandsEnvironment.execute
    boundary = []

    def observe(env, command, cwd="", **kwargs):
        boundary.append((command, cwd, kwargs))
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", observe)
    args = {"pattern": "public", **path_args}
    result = d.call("search_files", args)
    assert "path=." in d.cards[0]
    assert messages.WITNESS_CALL_CHANGED not in result, boundary
    assert "public" in result and d.jobs
    assert args == {"pattern": "public", **path_args}
    d.jobs.clear()
    d.modify = lambda args: {**args, "path": f"{d.base}/archive"}
    result = d.call("search_files", args)
    assert messages.WITNESS_CALL_CHANGED in result
    assert d.jobs == []


def test_public_terminal_config_bridge_preserves_process_environment(monkeypatch):
    from hermes_cli.config import apply_terminal_config_to_env

    monkeypatch.setenv("TERMINAL_TIMEOUT", "31")
    copied = dict(os.environ)
    result = apply_terminal_config_to_env(env=copied, config={"terminal": {"timeout": 47}}, override=True)
    assert result is copied and result["TERMINAL_TIMEOUT"] == "47"
    assert os.environ["TERMINAL_TIMEOUT"] == "31"


@pytest.mark.parametrize("timeout_args,expected", [({}, 47), ({"timeout": None}, 47), ({"timeout": 5}, 5)])
def test_terminal_timeout_default_is_frozen_before_approval(monkeypatch, timeout_args, expected):
    from hermes_cli import config
    from hands import client

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    calls, records = [], []

    def bridge(*, env):
        assert env is not os.environ
        calls.append(env)
        return {**env, "TERMINAL_TIMEOUT": "47"}

    monkeypatch.setattr(config, "apply_terminal_config_to_env", bridge)
    monkeypatch.setattr(client, "record_shown", lambda session, call, tool, args, rule: records.append(args))
    args = {"command": "echo approved", **timeout_args}
    result = witness.pre_tool_call(object(), "terminal", args)
    assert result["action"] == "approve"
    assert f"timeout={expected}" in result["message"]
    assert records[0]["timeout"] == expected
    assert len(calls) == (expected != 5)
    assert args == {"command": "echo approved", **timeout_args}


def test_registered_terminal_rebuilds_default_timeout_after_explicit_first_call(dispatch, monkeypatch):
    d = dispatch
    monkeypatch.setenv("TERMINAL_TIMEOUT", "180")
    first = d.call("terminal", {"command": "echo first", "timeout": 5})
    assert "first" in first and messages.WITNESS_CALL_CHANGED not in first
    assert "timeout=5" in d.cards[0]
    second = d.call("terminal", {"command": "echo second"})
    assert "second" in second and messages.WITNESS_CALL_CHANGED not in second
    assert "timeout=180" in d.cards[0]
    d.jobs.clear()
    execute = environment.HandsEnvironment.execute
    mutations = []

    def mutate(env, command, cwd="", **kwargs):
        if command == "echo third":
            assert kwargs["timeout"] == 180
            kwargs["timeout"] = 181
            mutations.append(command)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(environment.HandsEnvironment, "execute", mutate)
    third = d.call("terminal", {"command": "echo third"})
    assert mutations and messages.WITNESS_CALL_CHANGED in third
    assert "timeout=180" in d.cards[0]
    assert d.jobs == []
