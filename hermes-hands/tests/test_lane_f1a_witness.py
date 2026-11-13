import contextvars
import hashlib
import html
import json
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
    {"path": "/notes.txt", "content": "a\nb"},
    {"path": "/notes.txt", "content": "Checked by helper on 11 Nov\n"},
    {"path": "/c/Users/amina/Desktop/notes.txt", "content": "Fixed the printer.\n"},
    {"path": "/notes.txt", "content": "col1\tcol2\r\n"},
    {"path": "C:/Users/her/Docs/notes.txt", "content": "x" * 80},
    {"path": "/notes.txt", "content": "line of text\n" * 40},
    {"path": "/notes.txt", "content": ("hello world " * 90)[:1024]},
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
    result = hook("patch", {"mode": "replace", "path": "/notes.txt", "old_string": "a\nb", "new_string": "a\nc", "replace_all": False})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(
        tool="patch", device="laptop", details=r'path=/notes.txt; mode=replace; replace_all=false; old_string="a\nb"; new_string="a\nc"'
    )
    assert surface_units(result["message"]) <= 300


def test_patch_too_long_to_show_in_full_is_refused(hook):
    result = hook("patch", {"mode": "replace", "path": "/notes.txt", "old_string": "line\n" * 40, "new_string": "x"})
    assert result == {"action": "block", "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="old_string")}


def test_new_lines_are_allowed_only_in_content(hook):
    assert hook("write_file", {"path": "notes\n.txt", "content": "x"})["action"] == "block"
    assert hook("write_file", {"path": "/notes.txt", "content": "x", "extra": "a\nb"})["action"] == "block"
    assert hook("write_file", {"path": "/notes.txt", "content": "a\x1bb"})["action"] == "block"
    assert hook("write_file", {"path": "/notes.txt", "content": "a\u202eb"})["action"] == "block"
    assert hook("terminal", {"command": "touch notes", "content": "a\nb"})["action"] == "block"


@pytest.mark.parametrize("tool,args,expected", [
    ("patch", {"mode": "patch", "path": "safe.txt", "patch": "+x"}, messages.WITNESS_PATCH_MODE_BLOCKED),
    ("patch", {"mode": "patch", "patch": "*** Move File: notes.txt -> x.bat"}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("patch", {"mode": "replace", "path": "safe.txt", "old_string": "a", "new_string": "*** Move File: notes.txt -> x.bat"}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("write_file", {"path": "/notes.txt", "content": "x", "extra": {"nested": ["*** Begin Patch"]}}, messages.WITNESS_PATCH_DIRECTIVE_BLOCKED),
    ("patch", {"mode": "replace", "old_string": "a", "new_string": "b"}, messages.WITNESS_PATH_REQUIRED),
    ("write_file", {"path": "  ", "content": "x"}, messages.WITNESS_PATH_REQUIRED),
    ("read_file", {"path": "notes\x1b.txt"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("write_file", {"path": "/notes.txt", "content": "a\u202eb"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("terminal", {"command": "touch notes", "extra": {"nested": ["x\u200b"]}}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "notes\ue000.txt"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "a" + " " * 30 + "b"}, messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("read_file", {"path": "x" * 300}, messages.WITNESS_ARGUMENTS_LONG.format(argument="path") + " " + messages.WITNESS_SHORTER_PATH),
    ("read_file", {"path": "export api_key=sk-abcdefghijklmnopqrstuvwxyz123456"}, messages.WITNESS_SECRET_HIDDEN),
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
    base = messages.WITNESS_APPROVAL.format(tool="terminal", device="laptop", details="command=touch ; timeout=180")
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
    result = hook("write_file", {"path": "/notes.txt", "content": "a" * 30 + "hunter2"})
    assert result["action"] == "approve"
    assert "first 36 characters" in result["message"]
    assert hook("write_file", {"path": "/notes.txt", "content": "hunter2 and more"}) == {"action": "block", "message": messages.WITNESS_SECRET_BLOCKED}


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "touch notes", "background": "true"}),
    ("terminal", {"command": "touch notes", "background": 1}),
    ("terminal", {"command": "touch notes", "timeout": "30"}),
    ("terminal", {"command": "touch notes", "timeout": True}),
    ("terminal", {"command": 5}),
    ("terminal", {"command": "touch notes", "notify": "true"}),
    ("read_file", {"path": "notes.txt", "limit": "50"}),
    ("read_file", {"path": "notes.txt", "offset": 1.5}),
    ("search_files", {"pattern": "x", "path": "/c/Users/x", "context": "2"}),
    ("write_file", {"path": ["notes.txt"], "content": "x"}),
    ("patch", {"path": "notes.txt", "old_string": "a", "new_string": "b", "replace_all": "false"}),
])
def test_an_argument_that_is_not_its_schema_type_is_refused(hook, tool, args):
    """Core coerces "true" to True only after this hook (model_tools.py:902): the card would show
    another value than the one that runs."""
    assert hook(tool, args) == {"action": "block", "message": messages.WITNESS_ARGUMENT_TYPES_BLOCKED}


def test_arguments_already_their_type_are_shown_as_given(hook):
    original = {"command": "touch notes", "background": True, "timeout": 30, "workdir": None, "notify": [1]}
    assert hook("terminal", original) == {
        "action": "block",
        "message": "a background command has no time limit: leave out timeout; press S to stop it",
    }
    result = hook("terminal", {key: value for key, value in original.items() if key != "timeout"})
    assert result["action"] == "approve" and "background=true" in result["message"]
    assert "no time limit" in result["message"] and "timeout" not in result["message"].lower()
    assert hook("read_file", {"path": "notes.txt", "offset": 1, "limit": 50})["action"] == "approve"
    assert original == {"command": "touch notes", "background": True, "timeout": 30, "workdir": None, "notify": [1]}


def test_the_argument_types_are_cores_schemas():
    pytest.importorskip("model_tools")
    import model_tools  # noqa: F401  (registers the tools)
    from tools.registry import registry

    python = {"string": str, "boolean": bool, "integer": int, "array": list}
    for tool, types in witness._ARGUMENT_TYPES.items():
        properties = registry.get_schema(tool)["parameters"]["properties"]
        declared = {
            key: tuple(python[variant["type"]] for variant in schema["anyOf"]) if "anyOf" in schema
            else (python[schema["type"]],)
            for key, schema in properties.items()
        }
        assert declared == types, tool


def test_pwd_with_extra_arguments_needs_approval(hook):
    result = hook("terminal", {"command": "pwd", "workdir": "/tmp"})
    assert result["action"] == "approve"
    assert result["message"] == messages.WITNESS_APPROVAL.format(
        tool="terminal", device="laptop", details="command=pwd; timeout=180; workdir=/tmp"
    )




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
    normal = {**DEVICE, "witness": False, "session_state": "normal", "capabilities": []}
    for device, expected in [(None, None), (normal, None), (DEVICE, "approve")]:
        monkeypatch.setattr(witness, "_selected_device", lambda ctx, device=device: device)
        result = witness.pre_tool_call(object(), "terminal", {"command": "touch notes"}, session_id="agent-1", tool_call_id="call-1")
        assert (result if result is None else result["action"]) == expected
        assert bound.pop() == (device, {"session_id": "agent-1", "tool_call_id": "call-1"})
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    assert witness.pre_tool_call(object(), "web_search", {"query": "x"}) is None
    assert bound == [(DEVICE, {"session_id": "", "tool_call_id": ""})]



@pytest.mark.parametrize("text,expected", [
    ("touch notes", None),
    ("cat R\u00e9sum\u00e9.txt \U0001F600", None),
    ("export api_key=abc", messages.WITNESS_SECRET_HIDDEN),
    ("curl -H Authorization: Bearer abcdef", messages.WITNESS_SECRET_HIDDEN),
    ("cat notes" + " " * 21 + "x", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat \u3164.txt", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\u200bb", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\ue000b", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat a\u2028b", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
    ("cat e\u0301", messages.WITNESS_CONTROL_CHARACTERS_BLOCKED),
])
def test_the_display_check_is_stricter_than_cores(text, expected):
    from agent.redact import redact_approval_display

    assert witness._display_problem(text) == expected
    if redact_approval_display(text, force=True) != text:
        assert expected is not None


def test_every_character_core_would_show_differently_is_refused():
    """Core's approval surfaces show redact_approval_display's copy (agent/redact.py:984-986), which
    is never visible here: whatever it changes, the public check refuses."""
    from agent.redact import redact_approval_display

    points = list(range(0, 0x3000)) + list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE0110)) + [0x3164, 0xFFA0]
    texts = [f"cat a{chr(point)}b" for point in points if not 0xD800 <= point <= 0xDFFF]
    texts += ["cat a" + "\n" * count + "b" for count in range(1, 6)] + ["cat a" + " " * count + "b" for count in (20, 21, 70)]
    texts += ["export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123", "git clone https://u:ghp_abcdefghijklmnopqrstuvwxyz0123456789@x"]
    missed = [text for text in texts if redact_approval_display(text, force=True) != text and witness._display_problem(text) is None]
    assert missed == []


@pytest.mark.parametrize("path", ["keyboard.txt", "tokenizer.py", "monkey.py", "/home/x/secret_santa_list.txt"])
def test_secret_words_in_ordinary_paths_are_not_secrets(hook, path):
    assert hook("read_file", {"path": path})["action"] == "approve"
    assert hook("terminal", {"command": f"cat {path}"})["action"] == "approve"


_SECRET_SAMPLES = [
    "password=hunter2",
    "token: abcdefghijklmnopqrstuvwxyz",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    "sk-" + "a" * 40,
    "ghp_" + "a" * 36,
    "gho_" + "a" * 36,
    "github_pat_" + "a" * 82,
    "xoxb-" + "1" * 40,
    "AKIA" + "A" * 16,
    "AIza" + "a" * 35,
    "-----BEGIN PRIVATE KEY-----",
]


@pytest.mark.parametrize("secret", _SECRET_SAMPLES)
@pytest.mark.parametrize("location", ["command", "content", "late-content"])
def test_real_secrets_are_refused_without_showing_a_mask(hook, secret, location):
    if location == "command":
        tool, args = "terminal", {"command": f"echo '{secret}'"}
    else:
        prefix = "ordinary notes " * 30 if location == "late-content" else ""
        tool, args = "write_file", {"path": "/notes.txt", "content": prefix + secret}
    from agent.redact import redact_sensitive_text

    value = args["command" if location == "command" else "content"]
    expected = (
        messages.WITNESS_SECRET_HIDDEN if redact_sensitive_text(value, force=True) != value
        else messages.WITNESS_SECRET_BLOCKED
    )
    assert hook(tool, args) == {"action": "block", "message": expected}


@pytest.mark.parametrize("text", _SECRET_SAMPLES + [
    "keyboard tokenizer monkey secret santa",
    "BRAVE_API_KEY=opaquecredentialvalue123456789",
    '{"api_key": "opaquecredentialvalue123456789"}',
    "api_key: opaquecredentialvalue123456789",
    "postgresql://user:hunter2@localhost/db",
    "https://user:hunter2@example.com",
    "hf_" + "a" * 30,
    "npm_" + "a" * 36,
    "ctx7sk-" + "a" * 32,
    "Bearer " + "a" * 30,
    "-----BEGIN RSA PRIVATE KEY-----",
    "secret-key: ordinary-value",
])
def test_nothing_core_redacts_can_reach_a_witness_card_unmasked(hook, text):
    redact = pytest.importorskip("agent.redact").redact_sensitive_text
    for value in (text, f"command=echo '{text}'", f'content="{text}"'):
        if redact(value, force=True) != value:
            assert witness._display_problem(value) == messages.WITNESS_SECRET_HIDDEN
    if redact(text, force=True) != text:
        for prefix in ("", "ordinary notes " * 30):
            value = prefix + text
            expected = (
                messages.WITNESS_SECRET_HIDDEN if redact(value, force=True) != value
                else messages.WITNESS_SECRET_BLOCKED
            )
            result = hook("write_file", {"path": "/notes.txt", "content": value})
            assert result == {"action": "block", "message": expected}
