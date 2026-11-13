import contextvars
import hashlib
import threading
import types

import pytest

from hands import client, messages, store, witness
from hands_fakes import hands_db  # noqa: F401  (fixture)


DEVICE = {
    "name": "laptop", "device_id": "device-id", "witness": True, "session_state": "active",
    "instance": "serve-1", "capabilities": ["witness-v1"],
}


@pytest.fixture(autouse=True)
def fresh_tool_session(monkeypatch):
    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("hardening_tool_session", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    return lambda tool, args=None, ctx=None: witness.pre_tool_call(ctx or object(), tool, args or {})


@pytest.mark.parametrize("tool", ["process", "process_manage", "execute_code", "delegate_task", "cronjob_manage", "send_message", "browser_exec", "computer_use", "skill_manage", "mcp_read", "new_tool"])
def test_unknown_and_indirect_tools_blocked(hook, tool):
    assert hook(tool)["action"] == "block"


@pytest.mark.parametrize("tool", ["web_search", "web_extract", "memory", "todo_list", "clarify", "skill_view", "skills_list", "hands_devices", "tool_search", "tool_describe"])
def test_safe_tools_resolve_device_before_passing(hook, monkeypatch, tool):
    calls = []
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: calls.append(tool) or DEVICE)
    assert hook(tool) is None
    assert calls == [tool]


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "cp " + "./" * 150 + "hidden/notes"}),
    ("write_file", {"path": "/" + "./" * 150 + "hidden", "content": "x"}),
    ("patch", {"mode": "replace", "path": "/notes", "old_string": "x", "new_string": "y" * 1000}),
])
def test_long_arguments_are_blocked_without_truncation(hook, tool, args):
    result = hook(tool, args)
    assert result["action"] == "block"
    assert "Shorten the" in result["message"]
    assert ("~/" in result["message"]) == (tool == "write_file")


@pytest.mark.parametrize("tool,source", [("vision_analyze", "image_url"), ("video_analyze", "video_url")])
def test_media_sources_require_approval(hook, tool, source):
    result = hook(tool, {source: "private.png", "question": "read it"})
    assert result["action"] == "approve"
    assert "private.png" in result["message"] and "question" in result["message"]


def test_every_terminal_argument_visible(hook):
    result = hook("terminal", {"command": "touch notes", "background": True, "workdir": "/tmp", "pty": False})
    assert result["action"] == "approve"
    for item in ["background=true", "workdir=/tmp", "pty=false", "command=touch notes"]:
        assert item in result["message"]


@pytest.mark.parametrize("args", [
    {"mode": "patch", "path": "safe.txt", "patch": "*** Begin Patch\n*** Add File: /home/user/.bashrc\n+bad\n*** End Patch"},
    {"mode": "replace", "path": "safe.txt", "new_string": "*** Begin Patch\n*** Add File: hidden\n+x\n*** End Patch"},
])
def test_v4a_patch_cannot_hide_destination(hook, args):
    assert hook("patch", args)["action"] == "block"


@pytest.mark.parametrize("path", ["~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc", "/home/a/.ssh/authorized_keys", "/etc/cron.d/job", "~/.config/systemd/user/x.service", "C:/Users/A/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.bat", "C:/Users/A/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"])
@pytest.mark.parametrize("tool", ["patch", "write_file"])
def test_autostart_writes_blocked(hook, path, tool):
    assert hook(tool, {"path": path, "mode": "replace", "content": "x"})["action"] == "block"


def test_write_content_has_length_preview_digest(hook):
    result = hook("write_file", {"path": "/notes", "content": "hello"})
    assert result["action"] == "approve"
    assert 'content length=5' in result["message"] and 'first 5 characters="hello"' in result["message"]
    assert f"sha256={hashlib.sha256(b'hello').hexdigest()[:16]} " in result["message"]


@pytest.mark.parametrize("command", ["powershell.exe -enc aaa", "X=1 python.exe -c bad", "env whoami", "nohup touch x", "timeout 3 touch x", "xargs touch", "start calc", "wsl whoami", "cmd.exe /c whoami", "pwsh.exe -c bad", "ipconfig /all"])
def test_wrappers_and_broken_diagnostics_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


def test_flushdns_requires_git_bash_safe_form_and_owner_approval(hook):
    assert hook("terminal", {"command": "ipconfig /flushdns"})["action"] == "block"
    assert hook("terminal", {"command": "MSYS_NO_PATHCONV=1 ipconfig /flushdns"})["action"] == "approve"



@pytest.mark.parametrize("tool,expected", [("web_search", None), ("new_tool", "block"), ("vision_analyze", "block")])
def test_resolver_errors_only_block_unsafe_tools(hook, monkeypatch, tool, expected):
    def fail(ctx):
        raise RuntimeError("store failed")
    monkeypatch.setattr(witness, "_selected_device", fail)
    result = hook(tool)
    assert result is None if expected is None else result["action"] == expected


@pytest.mark.parametrize("control", ["\x1b", "\n", "\u202e", "\u200b", "\ud800"])
@pytest.mark.parametrize("tool", ["terminal", "read_file", "vision_analyze", "write_file"])
def test_control_characters_blocked_in_every_argument(hook, control, tool):
    result = hook(tool, {"command": "touch notes", "path": "notes", "extra": {"nested": ["hidden" + control]}})
    assert result["action"] == "block"


def test_patch_replacement_content_is_fully_identified(hook):
    result = hook("patch", {"path": "/notes", "mode": "replace", "old_string": "old", "new_string": "new", "replace_all": True})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(
        tool="patch", device="laptop", details='path=/notes; mode=replace; replace_all=true; old_string="old"; new_string="new"'
    )


@pytest.mark.parametrize("path", ["~/.config/systemd/user/../user/evil.service", "C:\\Users\\A\\Documents\\WindowsPowerShell\\profile.ps1", "/etc/cron.daily/evil", "~/.ssh/authorized_keys", "~/.bashrc/../.profile", "/etc/profile", "~/.zshenv", "C:/Users/A/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup. /evil.bat", "C:/Users/A/Documents/PowerShell/profile.ps1.", "C:/Users/A/Documents/PowerShell/profile.ps1::$DATA"])
def test_normalized_autostart_paths_blocked(hook, path):
    assert hook("write_file", {"path": path, "content": "x"})["action"] == "block"


@pytest.mark.parametrize("command", ["pythonw.exe -c bad", "python3.12 -c bad", "X=1 python3.12.exe -c bad"])
def test_python_launcher_variants_are_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


@pytest.mark.parametrize("command", ["command bash repair.sh", "builtin source repair.sh", "command python3.12 repair.py", "eval 'bash repair.sh'", "time bash repair.sh", "coproc bash repair.sh", "trap 'bash repair.sh' EXIT", "nice bash repair.sh", "setsid bash repair.sh", "stdbuf -oL bash repair.sh"])
def test_shell_builtin_wrappers_are_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


@pytest.mark.parametrize("tool", ["terminal", "read_file", "patch", "vision_analyze"])
def test_approval_cap_applies_to_the_complete_rendering(hook, tool):
    result = hook(tool, {"command": "touch notes", "path": "/notes", "mode": "replace", "extra": "x" * 280})
    assert result == {"action": "block", "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="extra")}


def test_session_id_does_not_change_the_resolved_target(hook, monkeypatch):
    calls = []
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: calls.append(ctx) or None)
    ctx = object()
    assert witness.pre_tool_call(ctx, "read_file", {"path": "notes"}, session_id="child-session") is None
    assert calls == [ctx]


def test_cron_stays_on_the_server_even_with_a_device_route(monkeypatch, hands_db):
    pytest.importorskip("gateway.session_context")
    monkeypatch.setenv("HERMES_SESSION_KEY", "s1")
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    store.set_session_target("s1", "laptop")
    device = {"name": "laptop", "device_id": "device-id", "witness": True, "session_state": "active", "capabilities": ["witness-v1"]}
    monkeypatch.setattr(store, "get_device", lambda name: device)
    monkeypatch.setattr(store, "device_by_id", lambda device_id: device)
    ctx = types.SimpleNamespace(cron=None, current_cron_execution=lambda: ctx.cron, get_config=lambda key, default=None: default)
    assert witness._witness_device(ctx) == device
    ctx.cron = object()
    assert witness._witness_device(ctx) is None



class _Guard:
    def before_call(self, name, args):
        return types.SimpleNamespace(allows_execution=True)


def _agent():
    return types.SimpleNamespace(
        session_id="sess-1", _current_turn_id="turn-1", _current_api_request_id="req-1",
        _tool_guardrails=_Guard(), tool_progress_callback=None, _touch_activity=lambda *a, **k: None,
        _interrupt_requested=False, _tool_interrupt_reason=None, _tool_worker_threads=set(),
        _tool_worker_threads_lock=threading.Lock(), _context_engine_tool_names=set(), _memory_manager=None,
        valid_tool_names=None, enabled_toolsets=None, disabled_toolsets=None, quiet_mode=True,
        _should_emit_quiet_tool_messages=lambda: False, tool_start_callback=None,
        _checkpoint_mgr=types.SimpleNamespace(enabled=False), interrupt=lambda **k: None,
    )


@pytest.mark.parametrize("situation,expected", [
    ("cli-yes", "ran"), ("gateway-yes", "ran"), ("cli-no", "blocked"), ("process-yolo", "refused"),
    ("session-yolo", "refused"), ("mode-off", "refused"), ("unattended-approve", "refused"),
])
def test_actual_hermes_gate_lets_only_a_human_yes_reach_the_device(monkeypatch, tmp_path, situation, expected):
    """The real plugin manager, approval gate and agent loop executor: every bypass approves the call
    without asking anyone, so its device job is refused; a person's yes lets it run."""
    plugins = pytest.importorskip("hermes_cli.plugins")
    from agent import tool_executor
    from gateway.session_context import set_session_vars
    from hermes_cli.plugins_manifest import PluginManifest
    import tools.approval as approval
    from tools import approval_context, terminal_tool

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for name in ("HERMES_INTERACTIVE", "HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(name, raising=False)
    manager = plugins.PluginManager()
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    witness.register(ctx)
    ctx.register_middleware("tool_execution", client.tool_execution)
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(client, "_APPROVED_CALLS", {})
    config = {"mode": "off" if situation == "mode-off" else "manual"}
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: config)
    monkeypatch.setattr(approval_context, "_get_unattended_approval_mode", lambda: "approve")
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", situation == "process-yolo")
    jobs, approvals = [], []
    manager._hooks["post_approval_response"].append(lambda **kwargs: approvals.append(kwargs))

    def execute(_args):
        try:
            jobs.append(client._decision_fields())
        except client.HandsError as exc:
            jobs.append(str(exc))
        return "{}"

    def run():
        key = "agent:main:telegram:dm:hands"
        if situation.startswith("cli"):
            approval_context.set_hermes_interactive_context(True)
            approval_context.set_current_session_key("cli:sess-1")
            terminal_tool.set_approval_callback(lambda *a, **k: "deny" if situation == "cli-no" else "once")
        elif situation == "unattended-approve":
            set_session_vars(platform="api_server", source="api_server", session_key="api:hands", session_id="sess-1")
            approval_context.set_current_session_key("api:hands")
        else:
            set_session_vars(platform="telegram", source="telegram", session_key=key, session_id="sess-1")
            approval_context.set_current_session_key(key)
            if situation == "session-yolo":
                approval.enable_session_yolo(key)
            approval.register_gateway_notify(
                key,
                lambda _data: threading.Thread(target=approval.resolve_gateway_approval, args=(key, "once")).start(),
            )
        try:
            return tool_executor._run_sequential_tool_execution_middleware(
                _agent(), function_name="terminal", function_args={"command": "touch notes"},
                effective_task_id="task-1", tool_call_id="call-1", execute=execute,
            )
        finally:
            terminal_tool.set_approval_callback(None)
            approval.unregister_gateway_notify(key)
            approval.disable_session_yolo(key)

    result = contextvars.copy_context().run(run)

    assert client._RUNNING_CALLS == {} and client._APPROVED_CALLS == {}
    if expected == "blocked":
        assert result.blocked and jobs == []
        return
    assert not result.blocked, result.result
    if expected == "refused":
        assert approvals == [] and jobs == [messages.WITNESS_NOT_APPROVED]
        return
    assert [(kw["choice"], kw["session_id"], kw["tool_call_id"]) for kw in approvals] == [("once", "sess-1", "call-1")]
    assert approvals[0]["pattern_key"].startswith("plugin_rule:hands-witness:")
    assert jobs == [{"decision": {"device_id": "device-id", "state": [True, "active", "serve-1"]}}]
