"""Round-3 witness gate fixes: startup persistence stays out of a witness session, ordinary writes fit
the approval card, refusals say what to change, and the model-facing texts match what the gate does."""

import contextvars
import hashlib
import html
from pathlib import Path

import pytest

from hands import client, messages, witness
from test_tools import load_tools

DEVICE = {
    "name": "laptop",
    "device_id": "device-id",
    "witness": True,
    "session_state": "active",
    "instance": "serve-1",
    "capabilities": ["witness-v1"],
}
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def fresh_tool_session(monkeypatch):
    monkeypatch.setattr(
        client, "_TOOL_SESSION", contextvars.ContextVar("r3a_tool_session", default=None)
    )
    monkeypatch.setattr(client, "_CALL_SESSIONS", {})


@pytest.fixture
def hook(monkeypatch):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    return lambda tool, args=None, ctx=None: witness.pre_tool_call(
        ctx or object(), tool, args or {}
    )


def on_device(monkeypatch, name):
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: {**DEVICE, "name": name})


def surface_units(message):
    return len(html.escape(message).encode("utf-16-le")) // 2


PERSISTENCE = {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}


@pytest.mark.parametrize(
    "path",
    [
        "/home/x/.config/autostart/evil.desktop",
        "/home/x/.config/autostart/subdir/evil.desktop",
        "~/.config/autostart/evil.desktop",
        "/etc/xdg/autostart/evil.desktop",
        "autostart/evil.desktop",
        "/Users/x/Library/LaunchAgents/com.evil.plist",
        "~/Library/LaunchAgents/com.evil.plist",
        "/Library/LaunchDaemons/com.evil.plist",
        "/etc/rc.local",
        "~/.xprofile",
        "/home/x/.xinitrc",
        "/home/x/.xsessionrc",
    ],
)
@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_linux_and_mac_autostart_writes_are_blocked(hook, tool, path):
    args = (
        {"path": path, "content": "[Desktop Entry]"}
        if tool == "write_file"
        else {"path": path, "mode": "replace", "old_string": "a", "new_string": "b"}
    )
    assert hook(tool, args) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    [
        "MSYS_NO_PATHCONV=1 reg.exe add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v U /t REG_SZ /d C:\\\\u.exe /f",
        "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' /v U /d 'C:\\u.exe' /f",
        'MSYS_NO_PATHCONV=1 reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v U /d x /f',
        "MSYS_NO_PATHCONV=1 REG.EXE ADD 'hklm\\software\\wow6432node\\microsoft\\windows\\currentversion\\run' /v U /d x",
        "MSYS_NO_PATHCONV=1 reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run' /v U /d x",
        "MSYS_NO_PATHCONV=1 reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx' /v U /d x",
        "MSYS_NO_PATHCONV=1 reg add 'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v Shell /d x",
        "reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -v U -d x",
        "MSYS_NO_PATHCONV=1 reg copy 'HKCU\\Software\\X' 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' /s /f",
        "reg import /c/Users/x/Downloads/settings.reg",
        "reg.exe IMPORT settings.reg",
        "regedit.exe -s settings.reg",
        "MSYS_NO_PATHCONV=1 schtasks.exe /create /tn Updater /tr C:\\\\u.exe /sc onlogon",
        "MSYS_NO_PATHCONV=1 schtasks /Change /tn Updater /tr C:\\\\u.exe",
        "schtasks -create -tn Updater -tr u.exe -sc onlogon",
        "cp u.exe '/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/u.exe'",
        "mv x.desktop /home/x/.config/autostart/x.desktop",
        "cp evil /home/x/.bashrc",
        "cp -t /home/x/.config/autostart x.desktop",
        "dd if=x of=/home/x/.profile",
        "cp evil .bashrc",
        "cd '/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'",
        "cd autostart",
    "cp u.exe Startup",
    "cp x.desktop autostart",
    "mv com.x.plist LaunchAgents",
        "pushd Startup",
        "robocopy . 'C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' u.exe",
        "crontab job.txt",
        "crontab -i job.txt",
        "systemctl --user enable evil.service",
        "systemctl --user link /home/x/evil.service",
    ],
)
def test_terminal_startup_persistence_is_blocked(hook, command):
    assert hook("terminal", {"command": command}) == PERSISTENCE


def test_a_terminal_workdir_in_a_startup_folder_is_blocked(hook):
    workdir = "/c/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    assert hook("terminal", {"command": "touch u.cmd", "workdir": workdir}) == PERSISTENCE


@pytest.mark.parametrize(
    "command",
    [
        "MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate",
        "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 0 /f",
        "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate /t REG_SZ /d 1 /f",
        "MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
        "MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\\Software\\Example' /v Run /d 1 /f",
        "MSYS_NO_PATHCONV=1 schtasks /query /fo LIST",
        "crontab -l",
        "systemctl --user status",
        "netsh wlan show profile",
        "cat /c/Users/x/notes.txt",
    ],
)
def test_ordinary_registry_task_and_file_commands_still_reach_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


def test_the_persistence_refusal_says_it_would_outlast_the_session():
    text = messages.WITNESS_AUTOSTART_BLOCKED
    assert "30 minute" in text
    for words in ("Run keys", "scheduled tasks", "startup", "shell profiles"):
        assert words in text


def test_the_hooks_refusal_names_the_remedy():
    text = messages.WITNESS_HOOKS_BLOCKED
    assert "Turn it off for this session" in text
    assert "hermes plugins disable" in text


def test_a_benign_shipped_plugin_hook_blocks_with_the_remedy(monkeypatch, tmp_path):
    plugins = pytest.importorskip("hermes_cli.plugins")
    from hermes_cli.plugins_manifest import PluginManifest

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    manager = plugins.PluginManager()
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    monkeypatch.setattr(witness, "_selected_device", lambda ctx: DEVICE)
    monkeypatch.setattr(witness, "_approval_bypassed", lambda: False)
    witness.register(ctx)
    assert witness.pre_tool_call(ctx, "terminal", {"command": "whoami"})["action"] == "approve"
    other = plugins.PluginContext(PluginManifest(name="security-guidance", kind="backend"), manager)
    other.register_hook("pre_tool_call", lambda **kwargs: None)
    for tool, args in [
        ("terminal", {"command": "whoami"}),
        ("read_file", {"path": "notes.txt"}),
        ("hands_checkup", {}),
    ]:
        result = witness.pre_tool_call(ctx, tool, args)
        assert result == {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}
        assert "Turn it off for this session" in result["message"]
    assert witness.pre_tool_call(ctx, "web_search", {"query": "x"}) is None


WINDOWS_PATH = "C:\\Users\\Samantha\\OneDrive\\Documents\\Printer help\\notes1.txt"
NOTE = "Printer fixed on 11 Nov. The queue was paused, and now it runs."


def test_a_normal_windows_write_fits_on_a_twelve_character_device(hook, monkeypatch):
    assert len(WINDOWS_PATH) == 60 and len(NOTE) == 63
    on_device(monkeypatch, "samantha-pc1")
    result = hook("write_file", {"path": WINDOWS_PATH, "content": NOTE})
    assert result["action"] == "approve"
    digest = hashlib.sha256(NOTE.encode("utf-8")).hexdigest()
    assert f"sha256={digest[:16]} " in result["message"] and digest not in result["message"]
    count = int(result["message"].split(" first ", 1)[1].split(" ", 1)[0])
    assert count >= 20 and f'characters="{NOTE[:count]}"' in result["message"]
    assert surface_units(result["message"]) <= 300


@pytest.mark.parametrize("length", range(44, 61, 4))
def test_windows_paths_of_44_to_60_characters_are_approved(hook, monkeypatch, length):
    on_device(monkeypatch, "samantha-pc1")
    path = "C:\\Users\\Sam\\Documents\\" + "p" * (length - 27) + ".txt"
    assert len(path) == length
    assert hook("write_file", {"path": path, "content": NOTE})["action"] == "approve"


def test_a_vision_question_on_the_screenshot_cache_path_is_approved(hook, monkeypatch):
    on_device(monkeypatch, "samantha-pc1")
    image = "C:\\Users\\samantha\\AppData\\Local\\hermes\\cache\\hermes-hands\\0f8c2a1e-5b7d-4c3e-9a10-6d2f8b4e7c11.png"
    result = hook(
        "vision_analyze",
        {"image_path": image, "question": "What does the error dialog on screen say?"},
    )
    assert result["action"] == "approve"


@pytest.mark.parametrize(
    "tool,args,argument",
    [
        (
            "write_file",
            {"path": "C:\\Users\\Samantha\\" + "p" * 200 + "\\notes.txt", "content": NOTE},
            "path",
        ),
        ("read_file", {"path": "/c/Users/x/" + "p" * 300}, "path"),
        (
            "patch",
            {
                "path": "/c/Users/x/notes.txt",
                "mode": "replace",
                "old_string": "o" * 60,
                "new_string": "n" * 90,
            },
            "new_string",
        ),
        (
            "patch",
            {
                "path": "/c/Users/x/notes.txt",
                "mode": "replace",
                "old_string": "o" * 90,
                "new_string": "n" * 60,
            },
            "old_string",
        ),
        ("vision_analyze", {"image_path": "/tmp/s.png", "question": "q" * 300}, "question"),
        ("terminal", {"command": "touch " + "a" * 300}, "command"),
    ],
)
def test_a_long_request_refusal_names_the_argument_and_suggests_a_home_path(
    hook, tool, args, argument
):
    result = hook(tool, args)
    assert result == {
        "action": "block",
        "message": messages.WITNESS_ARGUMENTS_LONG.format(argument=argument)
        + (" " + messages.WITNESS_SHORTER_PATH if argument == "path" else ""),
    }
    assert f"Shorten the {argument} argument" in result["message"]
    # ~ is refused in a terminal command, so only a file path gets the ~/ hint.
    assert ("~/" in result["message"]) == (argument == "path")


def test_a_model_supplied_key_never_becomes_the_named_argument(hook):
    result = hook("read_file", {"path": "notes.txt", "X" * 40: "y" * 300})
    assert result == {
        "action": "block",
        "message": messages.WITNESS_ARGUMENTS_LONG.format(argument="longest"),
    }


@pytest.mark.parametrize(
    "folder",
    ["Old Photos (2019)", "Bills & Receipts", "JANEDO~1\\Archive", "Notes #2", "100% Done"],
)
def test_symbols_in_a_quoted_path_are_refused_with_a_reason_the_model_can_explain(hook, folder):
    command = f'MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\\Users\\Jane\\{folder}"'
    assert hook("terminal", {"command": command}) == {
        "action": "block",
        "message": messages.WITNESS_COMMAND_BLOCKED,
    }
    assert "even inside quotes" in messages.WITNESS_COMMAND_BLOCKED


def test_the_checkup_description_does_not_overstate_the_command_gate(monkeypatch):
    description = load_tools(monkeypatch).schemas["hands_checkup"]["description"]
    assert "Scripts and chained commands are blocked" not in description
    assert (
        "Shell composition and known script interpreters are blocked there. Every other command, "
        "including ones that can start programs, needs the helper's approval"
    ) in description


@pytest.mark.parametrize(
    "command",
    [
        "explorer.exe C:\\\\Users\\\\Jane\\\\Downloads\\\\run.bat",
        "mshta.exe https://example.com/a.hta",
        "rundll32.exe url.dll,FileProtocolHandler C:\\\\Users\\\\Jane\\\\run.bat",
        "git -c core.pager=calc.exe log",
    ],
)
def test_launchers_outside_the_list_still_need_the_helper(hook, command):
    assert hook("terminal", {"command": command})["action"] == "approve"


def test_the_upgrade_hint_names_no_install_source():
    """r4-release-3: the device package is not on PyPI, so the hint points at the plugin README."""
    assert messages.UPGRADE == (
        "Update the Hermes Hands device agent on that computer to the version that matches this "
        "plugin. The install command is in the plugin README."
    )
    assert "pipx" not in messages.UPGRADE and "==" not in messages.UPGRADE
    assert messages.UPGRADE in messages.protocol_mismatch("hands/1")


EXECUTOR_ERRORS = (
    "Git Bash was not found or failed its probe",
    "Could not create Windows job object",
    "Could not set Windows job object limits",
    "Could not assign process to Windows job object",
    "Could not identify the suspended device process thread",
    "Could not open the suspended device process thread",
    "Could not resume the device process thread",
    "The device process thread was not suspended exactly once",
    "Could not establish job guardian protection",
    "The job guardian did not acknowledge protection",
    "The job guardian could not identify the protected process",
)


@pytest.mark.parametrize("error", EXECUTOR_ERRORS)
def test_executor_errors_are_the_ones_the_device_raises(error):
    source = (REPO / "device" / "hermeshands_device" / "executor.py").read_text(encoding="utf-8-sig")
    assert f'"{error}"' in source


@pytest.mark.parametrize("prefix", ["", "[Errno 5] ", "[WinError 5] "])
@pytest.mark.parametrize("error", EXECUTOR_ERRORS)
def test_executor_errors_reach_the_helper_as_plain_sentences(error, prefix):
    text = messages.device_result_error(prefix + error, "desk")
    assert "The device reported" not in text and "_" not in text
    assert "desk" in text and text.endswith("Do not guess a reason or retry.")


def test_missing_git_bash_names_the_fix():
    text = messages.device_result_error("Git Bash was not found or failed its probe", "desk")
    assert text == (
        "Git Bash is missing or did not start on desk, so nothing ran. Install Git for Windows there, "
        "then run hermes-hands doctor on it. Do not guess a reason or retry."
    )


def test_a_real_oserror_from_the_executor_maps_to_a_sentence():
    error = OSError(5, "Could not create Windows job object")
    assert "The device reported" not in messages.device_result_error(str(error), "desk")
    assert "The device reported" in messages.device_result_error("[Errno 5] Something else", "desk")


def test_the_skill_playbooks_stay_executable(hook):
    import re

    skill = (REPO / "hermes-hands" / "skills" / "hands" / "SKILL.md").read_text(encoding="utf-8-sig")
    commands = [
        line.strip()
        for block in re.findall(r"```bash\n(.*?)```", skill, re.S)
        for line in block.splitlines()
        if line.strip()
    ]
    assert commands
    for command in commands:
        assert hook("terminal", {"command": command})["action"] == "approve", command




def test_missing_screenshot_support_asks_for_a_reinstall_without_an_extra():
    text = messages.device_result_error(
        "Screenshot support is not available on this computer. Reinstall hermes-hands.", "desk"
    )
    assert text == (
        "Screenshots are not available on desk. Nothing was captured. The person at the computer "
        "should reinstall the Hermes Hands device agent there. Do not guess a reason or retry."
    )
    assert "[screen]" not in text and "extra" not in text
