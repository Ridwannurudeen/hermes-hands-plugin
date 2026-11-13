"""Native file execution locking and programmatic credential references."""

import types
from contextlib import nullcontext

import pytest

from hands import client, commands, messages, targets, witness
from test_commands import Context, Source
from test_witness_hardening import DEVICE


@pytest.mark.parametrize("expression", [
    'os.getenv("TOKEN")', 'os.environ["TOKEN"]', 'os.environ.get("TOKEN")',
    'process.env.TOKEN', '$ENV{TOKEN}',
])
def test_environment_reference_content_can_be_approved(monkeypatch, expression):
    from agent.redact import redact_sensitive_text

    content = f"token = {expression}"
    assert redact_sensitive_text(content, force=True) == content
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert not witness._contains_secret(content, source=True)
    assert witness.pre_tool_call(
        object(), "write_file", {"path": "/notes.py", "content": content}
    )["action"] == "approve"


def test_literal_token_beside_an_environment_reference_is_still_refused(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    literal = 'token = "ghp_' + "a" * 36 + '"'
    for content in (literal, 'token = os.getenv("TOKEN")\n' + literal):
        assert witness.pre_tool_call(
            object(), "write_file", {"path": "/notes.py", "content": content}
        ) == {"action": "block", "message": messages.WITNESS_SECRET_HIDDEN}


def test_first_native_server_read_locks_switching_until_new(monkeypatch, tmp_path):
    from tools import file_operations, file_tools

    path = tmp_path / "notes.txt"
    path.write_text("native server content\n", encoding="utf-8")
    env = types.SimpleNamespace(cwd=str(tmp_path), uses_host_filesystem=True)
    ops = file_operations.ShellFileOperations(env)
    # Exercise POSIX's native branch on Windows too; no shell may be called.
    monkeypatch.setattr(ops, "_native_read_enabled", lambda: True)
    monkeypatch.setattr(file_tools, "_get_file_ops", lambda task_id: ops)
    monkeypatch.setattr(targets, "_RAN", set())
    monkeypatch.setattr(commands, "terminal_backend", lambda: "hands")
    monkeypatch.setattr(commands.store, "get_device", lambda name: {"name": name})
    bound = {"chat": ("server", "telegram:42")}
    monkeypatch.setattr(commands.store, "get_session_target", lambda key: bound.get(key))
    monkeypatch.setattr(
        commands.store, "set_session_target", lambda key, name, owner: bound.__setitem__(key, (name, owner))
    )
    ctx = Context(["telegram:42"])
    commands.register_commands(ctx, has_seed=True)
    result = client.tool_execution(
        tool_name="read_file", args={"path": str(path)}, session_id="native-1", tool_call_id="read-1",
        next_call=lambda args: file_tools.read_file_tool(**args, task_id="native-1"),
    )
    assert "native server content" in result, result
    assert "/new" in ctx.handler(
        "use laptop", session_id="native-1", session_key="chat", platform="telegram", source=Source()
    )
    assert bound["chat"][0] == "server"
    assert ctx.handler(
        "use laptop", session_id="native-2", session_key="chat", platform="telegram", source=Source()
    ).startswith("Target set to laptop")


@pytest.mark.parametrize("tool", [
    "terminal", "read_file", "write_file", "patch", "search_files", "vision_analyze", "video_analyze",
])
@pytest.mark.parametrize("call_id", ["call-1", ""])
def test_machine_tools_guard_pending_calls_without_claiming_execution(monkeypatch, tool, call_id):
    monkeypatch.setattr(targets, "_RAN", set())

    def pending(args):
        assert not targets.has_run("machine-1")
        assert targets.is_pending("machine-1")

    client.tool_execution(
        tool_name=tool, args={}, session_id="machine-1", tool_call_id=call_id,
        next_call=pending,
    )
    assert not targets.has_run("machine-1")
    assert not targets.is_pending("machine-1")


def test_gateway_only_tool_does_not_lock_the_session(monkeypatch):
    monkeypatch.setattr(targets, "_RAN", set())
    client.tool_execution(tool_name="web_search", args={}, session_id="web-1", next_call=lambda args: None)
    assert not targets.has_run("web-1")


@pytest.mark.parametrize("outcome", ["raise", "none"])
def test_native_read_retains_lock_when_downstream_raises_or_suppresses_result(monkeypatch, tmp_path, outcome):
    from tools import file_operations, file_tools

    path = tmp_path / "notes.txt"
    path.write_text("native server content\n", encoding="utf-8")
    env = types.SimpleNamespace(cwd=str(tmp_path), uses_host_filesystem=True)
    ops = file_operations.ShellFileOperations(env)
    monkeypatch.setattr(ops, "_native_read_enabled", lambda: True)
    monkeypatch.setattr(file_tools, "_get_file_ops", lambda task_id: ops)
    monkeypatch.setattr(targets, "_RAN", set())

    def downstream(args):
        result = file_tools.read_file_tool(**args, task_id="native-exception")
        assert "native server content" in result, result
        if outcome == "raise":
            raise RuntimeError("downstream failed after reading")
        return None

    failure = pytest.raises(RuntimeError, match="downstream failed after reading") if outcome == "raise" else nullcontext()
    with failure:
        client.tool_execution(
            tool_name="read_file", args={"path": str(path)}, session_id="native-exception",
            tool_call_id="read-1", next_call=downstream,
        )
    assert targets.has_run("native-exception")
    assert not targets.is_pending("native-exception")
