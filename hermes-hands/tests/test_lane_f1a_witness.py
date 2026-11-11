import contextvars
import hashlib
import html
import json
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
    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("f1a_tool_session", default=None))
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    return lambda tool, args=None, ctx=None: witness.pre_tool_call(ctx or object(), tool, args or {})


def surface_units(message):
    return len(html.escape(message).encode("utf-16-le")) // 2


@pytest.mark.parametrize("command", [
    "X+=1 powershell -e AAAA",
    "X+=1 powershell -ec AAAA",
    "X+=1 powershell -en AAAA",
    "X+=1 bash -c payload",
    "X+=1 cmd /c whoami",
    "X+=1 python -c payload",
    "X+=1 sh -c payload",
    "X+=1 pwsh -c payload",
    "X+=1 env whoami",
    "X=1 Y+=2 PowerShell.EXE -e AAAA",
    "p''owershell -e AAAA",
    "X+=1 powershell.exe. -c x",
    "runas /user:admin 'powershell -e AAAA'",
    "schtasks /create /tr 'pwsh -c x'",
])
def test_launcher_behind_an_append_assignment_or_wrapper_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == {"action": "block", "message": messages.WITNESS_COMMAND_BLOCKED}


@pytest.mark.parametrize("flag", ["-e", "-E", "-ec", "-en", "-enc", "-enco", "-EncodedCommand", "--encodedcommand", "/e", "/ec", "-ea", "-EncodedArguments", "-enc:AAAA", "/EncodedCommand:AAAA"])
def test_encoded_command_flags_are_blocked_for_any_program(hook, flag):
    assert hook("terminal", {"command": f"tool {flag} AAAA"})["action"] == "block"


@pytest.mark.parametrize("command", ["dash -c x", "ash -c x", "ksh -c x", "mksh -c x", "csh -c x", "tcsh -c x", "rbash -c x", "yash -c x", "busybox sh -c x", "lua -l x", "tclsh x", "Rscript x", "osascript x", "sudo bash x", "doas sh x", "su root"])
def test_more_interpreters_and_wrappers_are_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


@pytest.mark.parametrize("command", ["pwd", "whoami", "hostname", "uname -a", "df -h", "tasklist"])
def test_read_only_commands_need_the_helpers_approval(hook, command):
    result = hook("terminal", {"command": command})
    assert result["action"] == "approve"
    assert f"command={command}" in result["message"]


def test_a_poisoned_path_cannot_turn_a_later_command_into_an_unapproved_one(hook):
    assert hook("write_file", {"path": "/c/Users/x/t/whoami", "content": "#!/bin/sh\necho hi\n"})["action"] == "approve"
    assert hook("terminal", {"command": "export PATH=/c/Users/x/t:/usr/bin:/bin"})["action"] == "block"
    assert hook("terminal", {"command": "whoami"})["action"] == "approve"


@pytest.mark.parametrize("command", ["export A=1", "declare -x PATH=/x", "alias ls=rm", "hash -p /c/x/evil whoami", "printf -v PATH /c/x", "read PATH", "set -a", "unset PATH", "readonly PATH"])
def test_builtins_that_change_later_commands_are_blocked(hook, command):
    assert hook("terminal", {"command": command})["action"] == "block"


@pytest.mark.parametrize("command,action", [
    ("MSYS_NO_PATHCONV=1 tasklist /FO CSV", "approve"),
    ("MSYS_NO_PATHCONV=1 ipconfig /all", "approve"),
    ("MSYS_NO_PATHCONV=1 ipconfig /flushdns", "approve"),
    ("MSYS_NO_PATHCONV=1 whoami /user", "approve"),
    ("MSYS_NO_PATHCONV=1 taskkill.exe /PID 1234", "approve"),
    ("MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate", "approve"),
    ("MSYS_NO_PATHCONV=1 compact.exe /C /S:\"C:\\Users\\Example\\Archive\"", "approve"),
    ("explorer.exe ms-settings:printers", "approve"),
    ("free -h", "approve"),
    ("uname -r", "approve"),
    ("df", "approve"),
    ("df -h /c", "approve"),
    ("ipconfig", "approve"),
    ("ls /c/Users", "approve"),
    ("tasklist /FO CSV", "block"),
    ("ipconfig /all", "block"),
    ("ipconfig /flushdns", "block"),
    ("whoami /user", "block"),
    ("systeminfo.exe /FO CSV", "block"),
    ("MSYS_NO_PATHCONV=1 reg.exe query HKCU //v x", "block"),
])
def test_git_bash_switch_forms(hook, command, action):
    assert hook("terminal", {"command": command})["action"] == action


@pytest.mark.parametrize("args", [
    {"path": "notes.txt", "content": "a\nb"},
    {"path": "notes.txt", "content": "Checked by helper on 11 Nov\n"},
    {"path": "/c/Users/amina/Desktop/notes.txt", "content": "Fixed the printer.\n"},
    {"path": "notes.txt", "content": "col1\tcol2\r\n"},
    {"path": "C:/Users/her/Docs/notes.txt", "content": "x" * 80},
    {"path": "notes.txt", "content": "line of text\n" * 40},
    {"path": "notes.txt", "content": ("hello world " * 90)[:1024]},
])
def test_normal_writes_are_approved_with_length_digest_and_start(hook, args):
    content = args["content"]
    result = hook("write_file", args)
    assert result["action"] == "approve"
    message = result["message"]
    assert message.startswith(f"Hands witness approval required: tool=write_file; device=laptop; path={args['path']}; ")
    assert f"content length={len(content)}" in message
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert f"sha256={digest[:16]} first " in message and digest not in message
    count = int(message.split(" first ", 1)[1].split(" ", 1)[0])
    assert count >= min(len(content), 20)
    assert f"characters={json.dumps(content[:count], ensure_ascii=False)}" in message
    assert "\n" not in message and "\t" not in message and "\r" not in message
    assert surface_units(message) <= 300
    if count < len(content):
        longer = message.replace(json.dumps(content[:count], ensure_ascii=False), json.dumps(content[:count + 1], ensure_ascii=False)).replace(f"first {count} ", f"first {count + 1} ")
        assert surface_units(longer) > 300


def test_multi_line_patch_is_approved_with_both_strings_in_full(hook):
    result = hook("patch", {"mode": "replace", "path": "notes.txt", "old_string": "a\nb", "new_string": "a\nc", "replace_all": False})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(
        tool="patch", device="laptop", details=r'path=notes.txt; mode=replace; replace_all=false; old_string="a\nb"; new_string="a\nc"'
    )
    assert surface_units(result["message"]) <= 300


def test_patch_too_long_to_show_in_full_is_refused(hook):
    result = hook("patch", {"mode": "replace", "path": "notes.txt", "old_string": "line\n" * 40, "new_string": "x"})
    assert result == {"action": "block", "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="old_string")}


def test_new_lines_are_allowed_only_in_content(hook):
    assert hook("write_file", {"path": "notes\n.txt", "content": "x"})["action"] == "block"
    assert hook("write_file", {"path": "notes.txt", "content": "x", "extra": "a\nb"})["action"] == "block"
    assert hook("write_file", {"path": "notes.txt", "content": "a\x1bb"})["action"] == "block"
    assert hook("write_file", {"path": "notes.txt", "content": "a\u202eb"})["action"] == "block"
    assert hook("terminal", {"command": "touch notes", "content": "a\nb"})["action"] == "block"


@pytest.mark.parametrize("tool,args,expected", [
    ("patch", {"mode": "patch", "path": "safe.txt", "patch": "+x"}, messages.WITNESS_PATCH_MODE_BLOCKED),
    ("patch", {"mode": "patch", "patch": "*** Move File: notes.txt -> x.bat"}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("patch", {"mode": "replace", "path": "safe.txt", "old_string": "a", "new_string": "*** Move File: notes.txt -> x.bat"}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("write_file", {"path": "notes.txt", "content": "x", "extra": {"nested": ["*** Begin Patch"]}}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("patch", {"mode": "replace", "old_string": "a", "new_string": "b"}, messages.WITNESS_PATH_REQUIRED),
    ("write_file", {"path": "  ", "content": "x"}, messages.WITNESS_PATH_REQUIRED),
    ("read_file", {"path": "notes\x1b.txt"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("write_file", {"path": "notes.txt", "content": "a\u202eb"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("terminal", {"command": "touch notes", "extra": {"nested": ["x\u200b"]}}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "notes\ue000.txt"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "a" + " " * 30 + "b"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "x" * 300}, messages.WITNESS_ARGUMENTS_LONG.format(argument="path") + " " + messages.WITNESS_SHORTER_PATH),
    ("read_file", {"path": "export api_key=sk-abcdefghijklmnopqrstuvwxyz123456"}, messages.WITNESS_SECRET_BLOCKED),
])
def test_each_guard_returns_its_own_message(hook, tool, args, expected):
    assert hook(tool, args) == {"action": "block", "message": expected}


def test_arguments_that_are_not_an_object_are_blocked(hook):
    assert hook("read_file", ["notes.txt"]) == {"action": "block", "message": messages.WITNESS_ARGUMENTS_BLOCKED}


@pytest.mark.parametrize("tool", ["tool_search", "tool_describe"])
def test_tool_search_bridge_reads_pass(hook, tool):
    assert hook(tool, {"names": ["hands_checkup"]}) is None


def test_unresolved_tool_call_bridge_is_blocked(hook):
    assert hook("tool_call", {"calls": [{"name": "hands_checkup", "arguments": {}}]})["action"] == "block"


@pytest.mark.parametrize("tool", ["hands_checkup", "hands_screenshot"])
def test_device_reaching_hands_tools_need_the_helpers_approval(hook, tool):
    result = hook(tool, {})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(tool=tool, device="laptop", details="no arguments")


def test_hands_devices_stays_on_the_gateway(hook):
    assert hook("hands_devices") is None


def _command_of_message_length(units):
    base = messages.WITNESS_APPROVAL.format(tool="terminal", device="laptop", details="command=touch ")
    return "touch " + "a" * (units - len(base))


@pytest.mark.parametrize("units,action", [(299, "approve"), (300, "approve"), (301, "block")])
def test_cap_is_the_smallest_surface_limit(hook, units, action):
    result = hook("terminal", {"command": _command_of_message_length(units)})
    assert result["action"] == action
    if action == "approve":
        assert surface_units(result["message"]) == units


def test_cap_counts_escaped_quotes_and_astral_characters(hook):
    assert hook("terminal", {"command": "cp notes.txt " + "''" * 60 + "/c/Users/x/target/final.txt"})["action"] == "block"
    assert hook("terminal", {"command": 'cp notes.txt ' + '""' * 45 + "/c/Users/x/final.txt"})["action"] == "block"
    assert hook("read_file", {"path": "/c/Users/x/" + "\U0001F600" * 110})["action"] == "block"
    assert hook("read_file", {"path": "/c/Users/x/" + "\U0001F600" * 50})["action"] == "approve"


def test_redacted_secrets_are_never_shown_as_masked_text(hook, monkeypatch):
    monkeypatch.setattr(witness, "_display_problem", lambda message: messages.WITNESS_SECRET_BLOCKED if "hunter2" in message else None)
    assert hook("read_file", {"path": "hunter2.txt"}) == {"action": "block", "message": messages.WITNESS_SECRET_BLOCKED}
    result = hook("write_file", {"path": "notes.txt", "content": "a" * 30 + "hunter2"})
    assert result["action"] == "approve"
    assert "first 36 characters" in result["message"]
    assert hook("write_file", {"path": "notes.txt", "content": "hunter2 and more"}) == {"action": "block", "message": messages.WITNESS_SECRET_BLOCKED}


def test_the_approval_shows_the_coerced_arguments_that_run(hook, monkeypatch):
    seen = []

    def coerced(tool_name, args):
        seen.append(args)
        return {**args, "background": True}

    monkeypatch.setattr(witness, "_coerced", coerced)
    original = {"command": "touch notes", "background": "yes"}
    result = hook("terminal", original)
    assert "background=true" in result["message"]
    assert original == {"command": "touch notes", "background": "yes"}
    assert seen == [original]


def test_pwd_with_extra_arguments_needs_approval(hook):
    result = hook("terminal", {"command": "pwd", "workdir": "/tmp"})
    assert result["action"] == "approve"
    assert result["message"].startswith("Hands witness approval required: tool=terminal; device=laptop; command=pwd; workdir=/tmp")


def test_other_hooks_block_without_a_dropped_note(hook):
    ctx = types.SimpleNamespace(_manager=types.SimpleNamespace(_middleware={}, _hooks={"pre_tool_call": [lambda **kw: None]}))
    assert hook("terminal", {"command": "touch notes"}, ctx) == {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}


def test_execution_middleware_blocks_device_tools(hook):
    from functools import partial

    ctx = types.SimpleNamespace()
    ctx._manager = types.SimpleNamespace(_middleware={"tool_execution": [lambda **kw: None]}, _hooks={"pre_tool_call": [partial(witness.pre_tool_call, ctx)]})
    assert hook("terminal", {"command": "touch notes"}, ctx) == {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}
    ctx._manager._middleware = {"tool_execution": []}
    assert hook("terminal", {"command": "touch notes"}, ctx)["action"] == "approve"


def _fake_approval(monkeypatch, *, bypass=False, yolo=False, contexts=()):
    package = types.ModuleType("tools")
    approval = types.ModuleType("tools.approval")
    package.approval = approval
    approval.get_current_session_key = lambda default="": "route-key"
    approval.is_approval_bypass_active_for_session = lambda key: bypass
    approval._yolo_active = lambda: yolo
    approval._unattended_contexts = lambda: [types.SimpleNamespace(mode=lambda mode=mode: mode) for mode in contexts]
    monkeypatch.setitem(sys.modules, "tools", package)
    monkeypatch.setitem(sys.modules, "tools.approval", approval)


@pytest.mark.parametrize("contexts,bypassed", [((), False), (("deny",), False), (("approve",), True), (("deny", "approve"), False), (("approve", "deny"), True)])
def test_unattended_approve_modes_count_as_a_bypass(monkeypatch, contexts, bypassed):
    _fake_approval(monkeypatch, contexts=contexts)
    assert witness._approval_bypassed() is bypassed


@pytest.mark.parametrize("mode", ["single_query", "cron", "unattended"])
@pytest.mark.parametrize("setting,blocked", [("approve", True), ("deny", False)])
def test_actual_hermes_unattended_modes(monkeypatch, mode, setting, blocked):
    approval = pytest.importorskip("tools.approval")
    from tools import approval_context

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(approval, "get_current_session_key", lambda default="": "route-key")
    monkeypatch.setattr(approval, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval, "_session_yolo", set())
    monkeypatch.setattr(approval_context, "_get_approval_mode", lambda: "manual")
    monkeypatch.setattr(approval, "_is_single_query_approval_context", lambda: mode == "single_query")
    monkeypatch.setattr(approval, "_is_cron_approval_context", lambda: mode == "cron")
    monkeypatch.setattr(approval, "_is_unattended_platform_approval_context", lambda: mode == "unattended")
    monkeypatch.setattr(approval, "_get_session_platform", lambda: "api_server", raising=False)
    monkeypatch.setattr(approval_context, f"_get_{mode}_approval_mode", lambda: setting)
    result = witness.pre_tool_call(object(), "terminal", {"command": "touch notes"})
    assert (result == {"action": "block", "message": messages.WITNESS_APPROVAL_DISABLED}) is blocked
    if not blocked:
        assert result["action"] == "approve"


def test_actual_hermes_unattended_turn_blocks(monkeypatch):
    pytest.importorskip("tools.approval")
    from gateway.session_finite import finite_turn_scope

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    with finite_turn_scope(True, unattended=True):
        assert witness.pre_tool_call(object(), "terminal", {"command": "pwd"})["message"] == messages.WITNESS_APPROVAL_DISABLED


def _register(monkeypatch, tmp_path):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    manager = plugins.PluginManager()
    monkeypatch.setattr(plugins, "_plugin_manager", manager)
    monkeypatch.setattr(plugins, "_plugin_managers_by_home", {})
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    witness.register(ctx)
    return plugins, ctx


@pytest.mark.parametrize("tool,args", [("terminal", {"command": "ls"}), ("read_file", {"path": "a"}), ("patch", {"path": "a", "old_string": "x", "new_string": "y"})])
def test_classic_cli_with_no_device_paired_runs_tools(monkeypatch, tmp_path, hands_db, tool, args):
    pytest.importorskip("gateway.session_context")
    plugins, _ = _register(monkeypatch, tmp_path)
    from tools.approval_context import reset_current_session_key, set_current_session_key

    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    token = set_current_session_key("20261111_101500_abc123")
    try:
        assert plugins._dispatch_pre_tool_call_hooks(tool, args, session_id="20261111_101500_abc123") == (None, None)
    finally:
        reset_current_session_key(token)


def test_actual_hermes_execution_middleware_blocks(monkeypatch, tmp_path):
    plugins, ctx = _register(monkeypatch, tmp_path)
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    assert witness.pre_tool_call(ctx, "terminal", {"command": "touch notes"})["action"] == "approve"
    ctx.register_middleware("tool_execution", client.tool_execution)
    assert witness.pre_tool_call(ctx, "terminal", {"command": "touch notes"})["action"] == "approve"
    other = plugins.PluginContext(PluginManifest(name="other-plugin", kind="backend"), ctx._manager)
    other.register_middleware("tool_execution", lambda **kw: kw["next_call"]({"command": "rm -rf x"}))
    assert witness.pre_tool_call(ctx, "terminal", {"command": "touch notes"})["message"] == messages.WITNESS_HOOKS_BLOCKED


def test_delegated_child_resolves_the_parent_route(monkeypatch, hands_db):
    pytest.importorskip("gateway.session_context")
    monkeypatch.setenv("HERMES_SESSION_KEY", "parent-route")
    monkeypatch.setenv("HERMES_SESSION_ID", "child-session")
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    store.set_session_target("parent-route", "laptop")
    device = {"name": "laptop", "device_id": "device-id", "witness": True, "session_state": "active", "capabilities": ["witness-v1"]}
    monkeypatch.setattr(store, "get_device", lambda name: device if name == "laptop" else None)
    monkeypatch.setattr(store, "device_by_id", lambda device_id: device if device_id == "device-id" else None)
    ctx = types.SimpleNamespace(current_cron_execution=lambda: None, get_config=lambda key, default=None: default)
    assert witness._witness_device(ctx) == device
    monkeypatch.setenv("HERMES_SESSION_KEY", "child-session")
    assert witness._witness_device(ctx) is None


def _adapters():
    telegram = pytest.importorskip("plugins.platforms.telegram.adapter")
    discord = pytest.importorskip("plugins.platforms.discord.adapter")
    slack = pytest.importorskip("plugins.platforms.slack.adapter")
    adapters = [object.__new__(module_class) for module_class in (telegram.TelegramAdapter, discord.DiscordAdapter, slack.SlackAdapter)]
    for adapter in adapters:
        adapter.config = types.SimpleNamespace(extra={})
    return adapters


_CARD_CASES = [
    ("terminal", {"command": "cp notes.txt " + "''" * 60 + "/c/Users/x/target/final.txt"}),
    ("terminal", {"command": "cp notes.txt " + '""' * 45 + "/c/Users/x/target/final.txt"}),
    ("terminal", {"command": "rm -f old.tmp " + "a.tmp " * 40 + "/c/Users/A/Documents/thesis.docx"}),
    ("terminal", {"command": "cp report.txt " + "a/" * 120 + "final.txt"}),
    ("terminal", {"command": "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 0 /f"}),
    ("read_file", {"path": "/c/Users/x/" + "\U0001F600" * 60 + "/final.txt"}),
    ("write_file", {"path": "/c/Users/amina/Desktop/notes.txt", "content": "Fixed the printer & \"cleared\" <queue>.\n" * 30}),
    ("patch", {"mode": "replace", "path": "/c/Users/amina/Desktop/notes.txt", "old_string": "a & b\n" * 20, "new_string": "<c>\n" * 20}),
] + [("terminal", {"command": "touch " + "a" * n + " /c/final.txt"}) for n in range(150, 230, 7)]


@pytest.mark.parametrize("tool,args", _CARD_CASES)
def test_every_approval_is_shown_whole_on_every_card(monkeypatch, tool, args):
    adapters = _adapters()
    from agent.redact import redact_approval_display

    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    result = witness.pre_tool_call(object(), tool, args)
    if result["action"] == "block":
        assert result["message"].startswith("Hermes Hands cannot show this request in full")
        return
    shown = redact_approval_display(result["message"])
    assert shown == result["message"]
    for adapter in adapters:
        assert adapter._ea_fit(shown, adapter._EA_REASON_BUDGET) == shown, type(adapter).__name__
        card = adapter._format_exec_approval("<terminal> (plugin approval rule)", shown, False)
        assert adapter._ea_escape(shown) in card, type(adapter).__name__


def test_the_hook_binds_the_device_it_decided_on(monkeypatch):
    bound = []
    monkeypatch.setattr(client, "bind_tool_session", lambda device, **kw: bound.append((device, kw)))
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    normal = {**DEVICE, "witness": False, "session_state": "normal", "capabilities": []}
    for device, expected in [(None, None), (normal, None), (DEVICE, "approve")]:
        monkeypatch.setattr(witness, "_selected_device", lambda ctx, device=device: device)
        result = witness.pre_tool_call(object(), "terminal", {"command": "touch notes"}, session_id="agent-1", tool_call_id="call-1")
        assert (result if result is None else result["action"]) == expected
        assert bound.pop() == (device, {"session_id": "agent-1", "tool_call_id": "call-1"})
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert witness.pre_tool_call(object(), "web_search", {"query": "x"}) is None
    assert bound == [(DEVICE, {"session_id": "", "tool_call_id": ""})]


def test_our_own_middleware_does_not_count_as_another_plugin(hook):
    from functools import partial

    ctx = types.SimpleNamespace()
    ctx._manager = types.SimpleNamespace(_middleware={"tool_execution": [client.tool_execution]}, _hooks={"pre_tool_call": [partial(witness.pre_tool_call, ctx)]})
    assert hook("terminal", {"command": "touch notes"}, ctx)["action"] == "approve"


@pytest.mark.parametrize("text,expected", [
    ("touch notes", None),
    ("cat R\u00e9sum\u00e9.txt \U0001F600", None),
    ("export api_key=abc", messages.WITNESS_SECRET_BLOCKED),
    ("curl -H Authorization: Bearer abcdef", messages.WITNESS_SECRET_BLOCKED),
    ("cat notes" + " " * 21 + "x", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat \u3164.txt", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\u200bb", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\ue000b", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\u2028b", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat e\u0301", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
])
def test_without_hermes_core_the_display_check_is_stricter(monkeypatch, text, expected):
    monkeypatch.setitem(sys.modules, "agent.redact", None)
    assert witness._display_problem(text) == expected
    monkeypatch.setitem(sys.modules, "tools.arg_coercion", None)
    args = {"command": ["x"]}
    copied = witness._coerced("terminal", args)
    assert copied == args and copied["command"] is not args["command"]
