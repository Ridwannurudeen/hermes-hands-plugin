import contextvars
import hashlib
import sys
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
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
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
    ("write_file", {"path": "./" * 150 + "hidden", "content": "x"}),
    ("patch", {"mode": "replace", "path": "notes", "old_string": "x", "new_string": "y" * 1000}),
])
def test_long_arguments_are_blocked_without_truncation(hook, tool, args):
    result = hook(tool, args)
    assert result["action"] == "block"
    assert "Shorten the" in result["message"]
    assert ("~/" in result["message"]) == (tool == "write_file")


@pytest.mark.parametrize("tool,source", [("vision_analyze", "image_path"), ("video_analyze", "video_url")])
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
    result = hook("write_file", {"path": "notes", "content": "hello"})
    assert result["action"] == "approve"
    assert 'content length=5' in result["message"] and 'first 5 characters="hello"' in result["message"]
    assert f"sha256={hashlib.sha256(b'hello').hexdigest()[:16]} " in result["message"]


@pytest.mark.parametrize("command", ["powershell.exe -enc aaa", "X=1 python.exe -c bad", "env whoami", "nohup touch x", "timeout 3 touch x", "xargs touch", "start calc", "wsl whoami", "cmd.exe /c whoami", "pwsh.exe -c bad", "ipconfig /all"])
def test_wrappers_and_broken_diagnostics_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


def test_flushdns_requires_git_bash_safe_form_and_owner_approval(hook):
    assert hook("terminal", {"command": "ipconfig /flushdns"})["action"] == "block"
    assert hook("terminal", {"command": "MSYS_NO_PATHCONV=1 ipconfig /flushdns"})["action"] == "approve"


def test_approval_bypass_blocks_even_read_only_commands(hook, monkeypatch):
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: True)
    assert hook("terminal", {"command": "pwd"})["action"] == "block"
    assert hook("web_search") is None


def test_other_hook_blocks_device_tools(hook):
    ctx = types.SimpleNamespace(_manager=types.SimpleNamespace(_middleware={}, _hooks={"pre_tool_call": [lambda **kw: {"action": "modify", "args": {"command": "bad"}}]}))
    assert hook("terminal", {"command": "pwd"}, ctx) == {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}


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
    result = hook("patch", {"path": "notes", "mode": "replace", "old_string": "old", "new_string": "new", "replace_all": True})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(
        tool="patch", device="laptop", details='path=notes; mode=replace; replace_all=true; old_string="old"; new_string="new"'
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
    result = hook(tool, {"command": "touch notes", "path": "notes", "mode": "replace", "extra": "x" * 280})
    assert result == {"action": "block", "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="extra")}


def test_approval_bypass_reads_actual_core_policy(monkeypatch):
    package = types.ModuleType("tools")
    approval = types.ModuleType("tools.approval")
    package.approval = approval
    approval.get_current_session_key = lambda default="": "route-key"
    calls = []
    approval.is_approval_bypass_active_for_session = lambda key: calls.append(key) or key == "route-key"
    approval._yolo_active = lambda: False
    approval._unattended_contexts = lambda: []
    monkeypatch.setitem(sys.modules, "tools", package)
    monkeypatch.setitem(sys.modules, "tools.approval", approval)
    assert witness._approval_bypassed()
    assert calls == ["route-key"]


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


def test_our_registered_hook_is_not_treated_as_another_plugin(hook):
    from functools import partial

    ctx = types.SimpleNamespace(_manager=types.SimpleNamespace(_middleware={}, _hooks={}))
    ctx._manager._hooks["pre_tool_call"] = [partial(witness.pre_tool_call, ctx)]
    assert hook("terminal", {"command": "touch notes"}, ctx)["action"] == "approve"


@pytest.mark.parametrize("bypass", ["process-yolo", "session-yolo", "mode-off"])
def test_actual_hermes_bypass_settings_block_device_calls(monkeypatch, bypass):
    approval = pytest.importorskip("tools.approval")
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(approval, "get_current_session_key", lambda default="": "route-key")
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", bypass == "process-yolo")
    monkeypatch.setattr(approval, "_session_yolo", {"route-key"} if bypass == "session-yolo" else set())
    monkeypatch.setattr(approval.approval_context, "_get_approval_mode", lambda: "off" if bypass == "mode-off" else "manual")
    result = witness.pre_tool_call(object(), "terminal", {"command": "pwd"})
    assert result["action"] == "block"
    assert "yolo" in result["message"]


def test_actual_hermes_hook_registry_blocks_foreign_modifiers(monkeypatch, tmp_path):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    manager = plugins.PluginManager()
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    witness.register(ctx)
    assert witness.pre_tool_call(ctx, "terminal", {"command": "touch notes"})["action"] == "approve"
    ctx.register_hook("pre_tool_call", lambda **kwargs: {"action": "modify", "args": {"command": "hidden"}})
    result = witness.pre_tool_call(ctx, "terminal", {"command": "touch notes"})
    assert result == {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}
