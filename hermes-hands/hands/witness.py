from __future__ import annotations

import copy
import hashlib
import html
import json
import posixpath
import re
import secrets
import shlex
import unicodedata
from functools import partial

from . import messages, store, targets

# Hermes v0.23.0 tools/{web_tools,memory_tool,todo_tool,clarify_tool,skills_tool}.py
# register these gateway-only tools. tool_search and tool_describe are catalog reads
# answered inline (model_tools.py:739-742); tool_call reaches this hook as the real tool.
_SAFE_TOOLS = frozenset(
    {
        "web_search", "web_extract", "memory", "todo_list", "clarify", "skill_view",
        "skills_list", "hands_devices", "tool_search", "tool_describe",
    }
)
# file_tools.py:863,959,1052 and vision_tools.py:1030,1185 read via the active environment.
# hands/tools.py runs hands_checkup and hands_screenshot on the device.
_APPROVE_TOOLS = frozenset(
    {
        "terminal", "read_file", "search_files", "write_file", "patch", "vision_analyze",
        "video_analyze", "hands_checkup", "hands_screenshot",
    }
)
# process_registry.py:2746, delegate_tool.py:920, cronjob_tools.py:1263,
# skill_manager_tool.py:940 and browser/desktop tools can act outside this approval.
# MCP names are dynamic; all names outside SAFE and APPROVE are blocked too.
_BLOCKED_TOOLS = frozenset(
    {
        "execute_code", "process", "process_manage", "delegate_task", "cronjob",
        "cronjob_manage", "send_message", "skill_manage", "browser_cdp", "browser_dialog",
        "browser_exec", "browser_vault", "computer_use", "read_window_below", "read_terminal",
        "close_terminal", "desktop_project", "desktop_preview", "drive_preview",
        "annotate_preview", "focus_pane",
    }
)
# Discord cuts the approval reason at 300 characters (plugins/platforms/discord/adapter.py:5645);
# Telegram and Slack cut at 500, Telegram in UTF-16 units after html.escape (adapter.py:4233-4236).
_SURFACE_LIMIT = 300
_PREVIEW_MIN = 20
_DESTINATION_KEYS = {
    "terminal": "command", "read_file": "path", "search_files": "path", "write_file": "path",
    "patch": "path", "vision_analyze": "image_path", "video_analyze": "video_url",
}
# The only arguments that may hold line breaks; they are shown JSON-escaped on one line.
_CONTENT_KEYS = {"write_file": ("content",), "patch": ("old_string", "new_string")}
_SCRIPT_EXECUTABLES = frozenset(
    {
        ".",
        "ash",
        "bash",
        "busybox",
        "cmd",
        "command",
        "builtin",
        "csh",
        "dash",
        "doas",
        "eval",
        "time",
        "coproc",
        "trap",
        "cscript",
        "deno",
        "exec",
        "fish",
        "ksh",
        "lua",
        "mksh",
        "node",
        "osascript",
        "perl",
        "php",
        "powershell",
        "pwsh",
        "py",
        "rbash",
        "rscript",
        "ruby",
        "runas",
        "sh",
        "source",
        "su",
        "sudo",
        "tclsh",
        "tcsh",
        "wscript",
        "yash",
        "zsh",
        "env",
        "nohup",
        "nice",
        "setsid",
        "stdbuf",
        "timeout",
        "xargs",
        "start",
        "wsl",
        "caffeinate",
        "chroot",
        "chrt",
        "faketime",
        "firejail",
        "flock",
        "forfiles",
        "ionice",
        "ltrace",
        "nsenter",
        "numactl",
        "pkexec",
        "prlimit",
        "screen",
        "script",
        "strace",
        "systemd-run",
        "taskset",
        "tmux",
        "unbuffer",
        "unshare",
        "watch",
    }
)
# Hermes keeps the shell state between commands (base_session_env.py:183-199), so these
# builtins could change what a later approved command runs.
_STATE_BUILTINS = frozenset(
    {
        "alias", "declare", "enable", "export", "getopts", "hash", "let", "local", "mapfile",
        "printf", "read", "readarray", "readonly", "set", "shopt", "typeset", "unalias", "unset",
    }
)
# Native Windows programs whose /switch arguments Git Bash rewrites into paths.
_WINDOWS_TOOLS = frozenset(
    {
        "attrib", "bcdedit", "certutil", "chkdsk", "cipher", "compact", "control", "dism",
        "driverquery", "explorer", "findstr", "fsutil", "getmac", "gpresult", "icacls",
        "ipconfig", "msiexec", "net", "netsh", "netstat", "powercfg", "reg", "robocopy", "sc",
        "schtasks", "sfc", "shutdown", "systeminfo", "takeown", "taskkill", "tasklist",
        "wevtutil", "where", "whoami", "wmic", "xcopy",
    }
)
_SCRIPT_SUFFIXES = (
    ".bat",
    ".cmd",
    ".js",
    ".mjs",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".pyw",
    ".rb",
    ".sh",
    ".vbs",
)
_SHELL_META = frozenset(";&|<>`$(){}*?[]~#!%")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_SWITCH = re.compile(r"^(?:-{1,2}|/)([^:=]*)")
_V4A = re.compile(r"\*\*\*\s*(?:Begin Patch|End Patch|(?:Update|Add|Delete|Move)\s+File:)")
# Without Hermes core, refuse what its redaction or display escaping (agent/redact.py:922-963) could change.
_SECRET_HINT = re.compile(
    r"key|token|secret|passw|bearer|authorization|credential|private key|sk-|ghp_|gho_|github_pat_|xox[abprs]-|akia|aiza",
    re.I,
)
# Startup persistence outlasts the 30 minute session: Windows Startup, XDG autostart, macOS
# launchd and cron folders, plus the registry keys Windows runs at logon.
_AUTOSTART_FOLDERS = frozenset(
    {
        "startup", "autostart", "launchagents", "launchdaemons", "cron", "cron.d", "cron.daily",
        "cron.hourly", "cron.weekly", "cron.monthly", "profile.d", "autostart-scripts",
    }
)
# Generic names that are persistence only under their OS parent (Start Menu\Programs\Startup,
# /etc/cron, /var/spool/cron, /usr/lib/cron, /etc/profile, /etc/crontab), so src/startup or a
# folder named Profile is ordinary work. A relative path's real parent is unknown, so its first
# part still counts.
_PARENTED_NAMES = {
    "startup": frozenset({"programs"}),
    "cron": frozenset({"etc", "spool", "lib"}),
    "profile": frozenset({"etc"}),
    "crontab": frozenset({"etc"}),
}
_DRIVE_RELATIVE = re.compile(r"^[a-z]:(?!/)")
# Folders read at login inside a parent that is ordinary to read: systemd user units, KDE Plasma
# login scripts and fish shell startup files. cd, pushd and workdir into such a parent are refused
# (_working_folder), so a relative path below it needs a symlink or similar indirection.
_LOGIN_FOLDERS = {
    "systemd": frozenset({"user", "user.control"}),
    "plasma-workspace": frozenset({"env", "shutdown"}),
    "fish": frozenset({"conf.d", "functions"}),
}
_UNIT_SUFFIXES = (
    ".service", ".socket", ".timer", ".path", ".target", ".mount", ".automount", ".swap", ".slice", ".wants",
    ".requires",
)
# These never write a file, so a bare word in them is a search pattern, not a destination.
_SEARCH_TOOLS = frozenset({"egrep", "fgrep", "findstr", "grep", "rg"})
_RUN_KEYS = frozenset({"run", "runonce", "runonceex", "runservices", "runservicesonce", "winlogon"})
_SYSTEMCTL_INSTALLS = frozenset(
    {"enable", "reenable", "link", "preset", "preset-all", "add-wants", "add-requires", "edit", "set-default"}
)
# sed commands that only print or edit the stream. w, W, r, R and e reach files or run a command,
# and so do the w and e flags of s.
_SED_COMMANDS = frozenset("=dDgGhHlnNpPqQxz")
_SED_FLAGS = frozenset("gpiImM0123456789")
# GNU tar long options that run a program; tar accepts any unambiguous prefix of a long option.
_TAR_PROGRAMS = (
    "to-command", "checkpoint-action", "use-compress-program", "info-script", "new-volume-script", "rsh-command",
)
# Vim runs editor commands from -c, --cmd and +cmd and scripts from -S, -s and -u; :w writes any file.
_VIM_PROGRAMS = frozenset({"vim", "vi", "nvim", "ex", "view", "gvim", "gview", "rvim", "rview", "vimdiff"})
_FIND_RUNS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_BLANK_GLYPHS = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180f\u2800\u3164\uffa0")


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", partial(pre_tool_call, ctx))


def _selected_device(ctx) -> dict | None:
    from . import environment

    # The target the device job itself resolves, so the hook and the environment agree.
    target = environment.resolve_current_target(ctx)
    if target == targets.SERVER:
        return None
    device = store.get_device(target)
    if device is None:
        return None
    device = store.device_by_id(device["device_id"])
    if device is None:
        raise RuntimeError("the selected device disappeared during target resolution")
    return device


def _active_witness(device: dict | None) -> bool:
    if device is None:
        return False
    capabilities = device.get("capabilities")
    return (
        bool(device.get("witness"))
        and device.get("session_state") == "active"
        and isinstance(capabilities, list)
        and "witness-v1" in capabilities
    )


def _witness_device(ctx) -> dict | None:
    device = _selected_device(ctx)
    return device if _active_witness(device) else None


def _sanitize_approval_text(value: str) -> str:
    return "".join(
        " " if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char
        for char in value
    )


def _visible(char: str) -> bool:
    if " " <= char <= "~":
        return True
    return ord(char) > 127 and unicodedata.category(char)[0] in "LNPS" and char not in _BLANK_GLYPHS


def _display_problem(message: str) -> str | None:
    try:
        from agent.redact import redact_approval_display, sanitize_command_for_display
    except ImportError:
        if " " * 21 in message or not all(map(_visible, message)):
            return messages.WITNESS_CONTROL_CHARACTERS_BLOCKED
        return messages.WITNESS_SECRET_BLOCKED if _SECRET_HINT.search(message) else None
    # Every approval surface shows the redacted copy (tools/approval.py:935-936); force ignores the config switch.
    if sanitize_command_for_display(message) != message:
        return messages.WITNESS_CONTROL_CHARACTERS_BLOCKED
    if redact_approval_display(message, force=True) != message:
        return messages.WITNESS_SECRET_BLOCKED
    return None


def _coerced(tool_name: str, args: dict) -> dict:
    try:
        from tools.arg_coercion import coerce_tool_args
    except ImportError:
        return copy.deepcopy(args)
    # The agent path coerces the arguments only after this hook runs (model_tools.py:902).
    return coerce_tool_args(tool_name, copy.deepcopy(args))


def _message(tool_name: str, device_name: str, details: str) -> str:
    return messages.WITNESS_APPROVAL.format(
        tool=_sanitize_approval_text(tool_name),
        device=_sanitize_approval_text(device_name),
        details=_sanitize_approval_text(details),
    )


def _problem(message: str) -> str | None:
    if problem := _display_problem(message):
        return problem
    if len(html.escape(message).encode("utf-16-le")) // 2 > _SURFACE_LIMIT:
        return messages.WITNESS_ARGUMENTS_LONG
    return None


def _approval(tool_name: str, device_name: str, details: str) -> dict:
    message = _message(tool_name, device_name, details)
    if problem := _problem(message):
        return {"action": "block", "message": problem}
    return {
        "action": "approve",
        "message": message,
        "rule_key": f"hands-witness:{secrets.token_hex(16)}",
    }


def _details(tool_name: str, args: dict, count: int | None = None) -> str:
    destination = _DESTINATION_KEYS.get(tool_name)
    content = _CONTENT_KEYS.get(tool_name, ())
    parts = []
    for key in sorted(args, key=lambda key: (key != destination, content.index(key) if key in content else -1, key)):
        value = args[key]
        if count is not None and key == "content":
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
            preview = json.dumps(value[:count], ensure_ascii=False)
            parts.append(f"content length={len(value)} sha256={digest} first {count} characters={preview}")
        elif key in content and isinstance(value, str):
            parts.append(f"{key}={json.dumps(value, ensure_ascii=False)}")
        else:
            rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
            parts.append(f"{key}={rendered}")
    return "; ".join(parts) or "no arguments"


def _too_long(tool_name: str, args: dict) -> str:
    # A write's content is cut to a preview, so the other arguments are what must get shorter.
    sizes = {
        key: len(html.escape(_details(tool_name, {key: value})).encode("utf-16-le"))
        for key, value in args.items()
        if not (tool_name == "write_file" and key == "content")
    }
    key = max(sizes, key=sizes.get, default="")
    # The key comes from the model, so only a plain argument name is repeated back.
    argument = key if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key) else "longest"
    refusal = messages.WITNESS_ARGUMENTS_LONG.format(argument=argument)
    # ~ is refused in a terminal command, so only a file path gets the ~/ hint.
    return f"{refusal} {messages.WITNESS_SHORTER_PATH}" if argument == "path" else refusal


def _render(tool_name: str, device_name: str, args: dict) -> dict:
    content = args.get("content")
    if tool_name != "write_file" or not isinstance(content, str):
        result = _approval(tool_name, device_name, _details(tool_name, args))
    else:
        # A write shows its length, digest and as much of its start as fits on one line.
        count = 0
        while count < len(content):
            problem = _problem(_message(tool_name, device_name, _details(tool_name, args, count + 1)))
            if problem:
                break
            count += 1
        if count < min(len(content), _PREVIEW_MIN):
            result = {"action": "block", "message": problem}
        else:
            result = _approval(tool_name, device_name, _details(tool_name, args, count))
    if result["message"] == messages.WITNESS_ARGUMENTS_LONG:
        result["message"] = _too_long(tool_name, args)
    return result


def _encoded_flag(token: str) -> bool:
    match = _SWITCH.match(token.casefold())
    name = match.group(1) if match else ""
    # PowerShell accepts any prefix of -EncodedCommand and -EncodedArguments, plus -ec and -ea.
    return bool(name) and (
        "encodedcommand".startswith(name) or "encodedarguments".startswith(name) or name in {"ec", "ea"}
    )


def _program(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1].casefold().rstrip(" .").removesuffix(".exe")


def _launcher(executable: str) -> bool:
    return (
        executable in _SCRIPT_EXECUTABLES
        or re.fullmatch(r"python(?:\d+(?:\.\d+)*)?w?", executable) is not None
        or executable.endswith(_SCRIPT_SUFFIXES)
    )


def _command_words(words: list[str]) -> tuple[list[str], list[str]]:
    words = list(words)
    assignments = []
    while words and _ASSIGNMENT.match(words[0]):
        assignments.append(words.pop(0))
    return assignments, words


def _long_option(word: str, names: tuple[str, ...]) -> bool:
    name = word.casefold()[2:].split("=", 1)[0] if word.startswith("--") else ""
    return len(name) >= 2 and any(option.startswith(name) for option in names)


def _short_option(arguments: list[str], letters: str) -> bool:
    return any(re.match(r"-[^-]", word) and set(word[1:]) & set(letters) for word in arguments)


def _sed_field(script: str, start: int) -> int:
    """The index of the delimiter that closes the field opened by script[start], or -1."""
    index = start + 1
    while index < len(script):
        if script[index] == "\\":
            index += 2
        elif script[index] == script[start]:
            return index
        else:
            index += 1
    return -1


def _sed_script_prints(script: str) -> bool:
    """Whether a sed script only prints or edits the stream. Anything it cannot read counts as no."""
    index, size = 0, len(script)
    while index < size:
        if script[index].isspace() or script[index] == ";":
            index += 1
            continue
        # Addresses: line numbers, first~step, ranges and /regex/ or \cregexc with the I and M flags.
        while index < size:
            if script[index].isdigit() or script[index] in ",~+ ":
                index += 1
            elif script[index] in "/\\":
                index += script[index] == "\\"
                index = _sed_field(script, index) if index < size else -1
                if index < 0:
                    return False
                index += 1
                while index < size and script[index] in "IM":
                    index += 1
            else:
                break
        if index >= size:
            return False
        command = script[index]
        if command in _SED_COMMANDS:
            index += 1
            while index < size and script[index].isdigit():
                index += 1
        elif command in "sy" and index + 1 < size and script[index + 1] not in "\\ ":
            pattern = _sed_field(script, index + 1)
            index = _sed_field(script, pattern) if pattern >= 0 else -1
            if index < 0:
                return False
            index += 1
            while command == "s" and index < size and not script[index].isspace() and script[index] != ";":
                if script[index] not in _SED_FLAGS:
                    return False
                index += 1
        else:
            return False
    return True


def _sed_prints(arguments: list[str]) -> bool:
    """Whether every script of a sed call only prints or edits the stream. A script file is unseen."""
    scripts, operands, index = [], [], 0
    while index < len(arguments):
        word = arguments[index]
        if word == "--":
            operands += arguments[index + 1 :]
            break
        if word.startswith("--"):
            name, equals, value = word[2:].partition("=")
            if "file".startswith(name):
                return False
            if "expression".startswith(name) or "line-length".startswith(name):
                if not equals:
                    index += 1
                    value = arguments[index] if index < len(arguments) else ""
                if name[0] == "e":
                    scripts.append(value)
        elif word.startswith("-") and len(word) > 1:
            for position, letter in enumerate(word[1:], 2):
                if letter in "efl":
                    value = word[position:]
                    if not value:
                        index += 1
                        value = arguments[index] if index < len(arguments) else ""
                    if letter == "f":
                        return False
                    if letter == "e":
                        scripts.append(value)
                    break
                if letter == "i":
                    break
        else:
            operands.append(word)
        index += 1
    return all(map(_sed_script_prints, scripts or operands[:1]))


def _split(value: str) -> list[list[str]]:
    try:
        posix = shlex.split(value, posix=True)
    except ValueError:
        posix = []
    # The posix split drops backslashes (HKCU\...\Run), so the plain split is judged too.
    return [posix, value.split()]


def _inner_lines(executable: str, words: list[str]):
    """Command lines carried inside arguments: git grep -O'cp a b', tar --to-command='crontab x', find -exec."""
    # A longer command is refused for its length (_render), so it is never split again.
    if sum(map(len, words)) > _SURFACE_LIMIT:
        return
    for index, word in enumerate(words):
        if executable == "find" and word.casefold() in _FIND_RUNS:
            yield words[index + 1 :]
        for value in _values(word):
            if any(char.isspace() for char in value):
                yield from (split for split in _split(value) if split)


def _runs_program(words: list[str], depth: int) -> bool:
    """Whether a command runs a program the card does not show as the command, or a sed script that
    writes or runs, here or in a command line carried in one of its arguments (two levels deep)."""
    assignments, words = _command_words(words)
    executable = _program(words[0]) if words else ""
    arguments = words[1:]
    if (
        # Judged as written: in a quoted path such as 'Start Menu' or 'Source Code' the first word is a folder.
        (depth and words and _launcher(words[0].casefold().rstrip(" .").removesuffix(".exe")))
        or (executable in {"sed", "gsed"} and not _sed_prints(arguments))
        or (executable == "rg" and any(word == "--pre" or word.startswith(("--pre=", "--pre-glob")) for word in arguments))
        or (
            executable in _VIM_PROGRAMS
            and (
                _short_option(arguments, "cSsu")
                or any(word.startswith("+") or _long_option(word, ("cmd",)) for word in arguments)
            )
        )
        or (
            executable == "git"
            and "grep" in arguments
            and (_short_option(arguments, "O") or any(_long_option(word, ("open-files-in-pager",)) for word in arguments))
        )
        or (
            executable == "git"
            and "difftool" in arguments
            and (_short_option(arguments, "x") or any(_long_option(word, ("extcmd",)) for word in arguments))
        )
        or (
            executable == "tar"
            and (
                _short_option(arguments, "IF")
                or any(
                    word.casefold().startswith("--checkpoint-")
                    or (_long_option(word, _TAR_PROGRAMS) and not word.casefold().startswith("--checkpoint"))
                    for word in arguments
                )
            )
        )
        or (executable == "zip" and any(word == "-TT" or _long_option(word, ("unzip-command",)) for word in arguments))
    ):
        return True
    # A search pattern runs nothing: grep 'command not found'.
    if executable in _SEARCH_TOOLS:
        return False
    lines = list(_inner_lines(executable, assignments + words))
    return bool(lines) and (depth == 2 or any(_runs_program(line, depth + 1) for line in lines))


def _command_decision(command: str) -> dict:
    blocked = {"action": "block", "message": messages.WITNESS_COMMAND_BLOCKED}
    if not command.strip() or any(char in _SHELL_META for char in command):
        return blocked
    if any(unicodedata.category(char) == "Cc" for char in command):
        return blocked
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return blocked
    words = list(argv)
    assignments = []
    while words and _ASSIGNMENT.match(words[0]):
        assignments.append(words.pop(0))
    if not words:
        return blocked
    first = words[0]
    executable = _program(first)
    tokens = [token for word in argv for token in word.split()]
    if (
        "/" in first
        or "\\" in first
        or _launcher(executable)
        or executable in _STATE_BUILTINS
        or any("powershell" in token.casefold() or "pwsh" in token.casefold() for token in tokens)
        or any(_encoded_flag(token) for token in tokens)
        or _runs_program(argv, 0)
    ):
        return blocked
    # A native argv probe in Git Bash confirms that /all and /flushdns become paths and
    # //x becomes /x. Only the exact MSYS_NO_PATHCONV=1 prefix keeps a /switch intact.
    if first.casefold().endswith(".exe") or executable in _WINDOWS_TOOLS:
        for word in words[1:]:
            if word.startswith("//") or (
                word.startswith("/") and "/" not in word[1:] and "MSYS_NO_PATHCONV=1" not in assignments
            ):
                return blocked
    return {"action": "approve"}


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _hidden_characters(value, allowed: str = "") -> bool:
    return any(
        char not in allowed and unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        for text in _strings(value) for char in text
    )


def _autostart_path(path: str) -> bool:
    normalized = posixpath.normpath(path.replace("\\", "/")).casefold()
    # C:Startup is relative to drive C's own current folder.
    drive_relative = _DRIVE_RELATIVE.match(normalized) is not None
    if drive_relative:
        normalized = posixpath.normpath(normalized[2:])
    anchored = not drive_relative and (
        normalized.startswith(("/", "~")) or re.match(r"^[a-z]:/", normalized) is not None
    )
    raw = normalized.split("/")
    if not anchored:
        while raw and raw[0] == "..":
            raw.pop(0)
    # Win32 trims trailing dots/spaces and accepts alternate data stream suffixes.
    parts = [part.split(":", 1)[0].rstrip(" .") for part in raw]
    if not parts:
        return False
    return (
        parts[-1] in {
            ".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc", ".zprofile",
            ".zlogin", ".zshenv", "authorized_keys", "authorized_keys2", "profile.ps1",
            "bashrc", "bash.bashrc", "zshrc", "zshenv", ".xprofile", "config.fish",
            ".xinitrc", ".xsession", ".xsessionrc", "rc.local",
        }
        or parts[-1].endswith("_profile.ps1")
        or any(
            (part in _AUTOSTART_FOLDERS and part not in _PARENTED_NAMES)
            or (
                part in _PARENTED_NAMES
                and (part in _AUTOSTART_FOLDERS or index == len(parts) - 1)
                and (parts[index - 1] in _PARENTED_NAMES[part] if index else not anchored)
            )
            for index, part in enumerate(parts)
        )
        or any(after in _LOGIN_FOLDERS.get(part, ()) for part, after in zip(parts, parts[1:]))
        # user/<unit> is a systemd user unit when the working folder is a systemd folder reached
        # through a symlink, which _working_folder cannot see.
        or (
            not anchored
            and len(parts) > 1
            and parts[0] == "user"
            and parts[1].removesuffix(".d").endswith(_UNIT_SUFFIXES)
        )
    )


def _working_folder(path: str) -> bool:
    """Whether a later command could run in a startup folder or a parent of login folders."""
    parts = posixpath.normpath(path.replace("\\", "/")).casefold().split("/")
    return _autostart_path(path) or any(part in _LOGIN_FOLDERS for part in parts)


def _values(word: str):
    yield word
    # Every tail after = or : (of=Startup/a=b.cmd, /LOG+:Startup\e.cmd).
    for index, char in enumerate(word):
        if char in "=:":
            yield word[index + 1 :]
    # A short option can carry its value glued on: -tStartup, -sLoStartup/e.cmd, -o.bashrc.
    if re.match(r"-[^-]", word):
        for index in range(2, len(word)):
            if not (word[index - 1].isascii() and word[index - 1].isalnum()):
                break
            yield word[index:]


def _persistent_command(command: str) -> bool:
    """Whether a command that passed the composition gate sets up startup persistence."""
    return _persistent_words(shlex.split(command, posix=True), 0)


def _persistent_words(words: list[str], depth: int) -> bool:
    assignments, words = _command_words(words)
    executable = words[0].casefold().rstrip(" .").removesuffix(".exe") if words else ""
    rest = [word.casefold() for word in words[1:]]
    # An assignment before the command is part of it: HOME=<Startup> cd, CDPATH=<systemd> cd user.
    arguments = assignments + words[1:]
    switches = {word.lstrip("/-") for word in rest}
    if executable == "reg" and rest:
        keys = [set(re.split(r"[\\/]+", word)) for word in rest[1:] if "\\" in word or "/" in word]
        # An import, restore or load writes keys the approval card cannot show.
        if rest[0] in {"import", "restore", "load"}:
            return True
        if rest[0] in {"add", "copy"} and any(key & _RUN_KEYS for key in keys):
            return True
    if (
        executable == "regedit"
        or (executable == "schtasks" and switches & {"create", "change"})
        or (executable == "crontab" and rest != ["-l"])
        or (executable == "systemctl" and switches & _SYSTEMCTL_INSTALLS)
    ):
        return True
    if executable in {"cd", "pushd"} and any(_working_folder(value) for word in arguments for value in _values(word)):
        return True
    # A bare word is a relative path (Startup, profile after cd /etc) unless the program never
    # writes it: a search pattern, git log without --output, or a keyword such as wmic startup,
    # systemctl status cron, journalctl -u cron without --cursor-file and netsh wlan show profile.
    # netsh export writes its bare arguments except the profile keyword of netsh wlan export.
    # Paths in those still count.
    searching = executable in _SEARCH_TOOLS or (
        executable == "git" and rest[:1] in (["grep"], ["log"]) and not any(word.startswith("--ou") for word in rest)
    )
    keyword = (
        executable in {"systemctl", "wmic"}
        or (executable == "journalctl" and not any(word.startswith("--cu") for word in rest))
        or (executable == "netsh" and "export" not in rest)
    )
    exported = executable == "netsh" and rest[:2] == ["wlan", "export"]
    if any(
        _autostart_path(value)
        for word in arguments
        for value in _values(word)
        if not (
            (searching or (keyword and value == word) or (exported and value == word and value.casefold() == "profile"))
            and "/" not in value
            and "\\" not in value
            and not value.startswith(".")
            and not _DRIVE_RELATIVE.match(value.casefold())
        )
    ):
        return True
    # A command line inside one argument is judged as a command; a search pattern runs nothing.
    if searching:
        return False
    lines = list(_inner_lines(executable, assignments + words))
    return bool(lines) and (depth == 2 or any(_persistent_words(line, depth + 1) for line in lines))


def _approval_bypassed() -> bool:
    from tools import approval

    session_key = approval.get_current_session_key(default="")
    # _run_approval_gate lets the first unattended context decide (tools/approval.py:1086-1101),
    # and its approve mode answers the prompt with nobody present.
    unattended = approval._unattended_contexts()
    return (
        approval.is_approval_bypass_active_for_session(session_key)
        or approval._yolo_active()
        or (bool(unattended) and unattended[0].mode() == "approve")
    )


def _other_hooks(ctx) -> bool:
    from . import client

    manager = getattr(ctx, "_manager", None)
    if manager is None:
        return False
    # Hermes reads the callback lists on every call. Another pre_tool_call hook may return
    # modify after our approval text is built (plugins.py:1937-1958), and other tool_execution
    # middleware may rewrite arguments around this hook (agent/tool_executor.py).
    # Our own middleware only carries the hook decision into the call (client.py).
    return any(
        callback is not client.tool_execution for callback in tuple(manager._middleware.get("tool_execution", ()))
    ) or any(
        not (isinstance(callback, partial) and callback.func is pre_tool_call and callback.args == (ctx,))
        for callback in tuple(manager._hooks.get("pre_tool_call", ()))
    )


def pre_tool_call(ctx, tool_name: str, args: dict, **kwargs):
    from . import client

    try:
        device = _selected_device(ctx)
        # Freeze the device session this decision saw for every job of the call (client.py).
        client.bind_tool_session(
            device, session_id=kwargs.get("session_id", ""), tool_call_id=kwargs.get("tool_call_id", "")
        )
        if not _active_witness(device):
            return None
        if tool_name in _SAFE_TOOLS:
            return None
        if tool_name in _BLOCKED_TOOLS or tool_name not in _APPROVE_TOOLS:
            return {"action": "block", "message": messages.WITNESS_TOOL_BLOCKED}
        if _approval_bypassed():
            return {"action": "block", "message": messages.WITNESS_APPROVAL_DISABLED}
        if _other_hooks(ctx):
            return {"action": "block", "message": messages.WITNESS_HOOKS_BLOCKED}
        if not isinstance(args, dict):
            return {"action": "block", "message": messages.WITNESS_ARGUMENTS_BLOCKED}
        args = _coerced(tool_name, args)
        if not isinstance(args, dict):
            return {"action": "block", "message": messages.WITNESS_ARGUMENTS_BLOCKED}
        multiline = _CONTENT_KEYS.get(tool_name, ())
        if any(
            _hidden_characters(key) or _hidden_characters(value, "\n\r\t" if key in multiline else "")
            for key, value in args.items()
        ):
            return {"action": "block", "message": messages.WITNESS_CONTROL_CHARACTERS_BLOCKED}
        if any(_V4A.search(text) for text in _strings(args)):
            return {"action": "block", "message": messages.WITNESS_PATCH_DIRECTIVE_BLOCKED}
        if tool_name == "patch" and args.get("mode", "replace") != "replace":
            return {"action": "block", "message": messages.WITNESS_PATCH_MODE_BLOCKED}
        if tool_name in {"write_file", "patch"}:
            path = args.get("path")
            if not isinstance(path, str) or not path.strip():
                return {"action": "block", "message": messages.WITNESS_PATH_REQUIRED}
            if _autostart_path(path):
                return {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}
        if tool_name == "terminal":
            command = args.get("command")
            if not isinstance(command, str):
                return {"action": "block", "message": messages.WITNESS_COMMAND_BLOCKED}
            decision = _command_decision(command)
            if decision["action"] == "block":
                return decision
            workdir = args.get("workdir")
            if _persistent_command(command) or (isinstance(workdir, str) and _working_folder(workdir)):
                return {"action": "block", "message": messages.WITNESS_AUTOSTART_BLOCKED}
        return _render(tool_name, device["name"], args)
    except Exception:
        if tool_name not in _SAFE_TOOLS:
            return {"action": "block", "message": messages.WITNESS_TARGET_BLOCKED}
        return None
