from __future__ import annotations

import ast
import copy
import hashlib
import html
import io
import json
import os
import posixpath
import re
import secrets
import shlex
import tokenize
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
# Discord cuts the approval reason at 300 characters; Telegram at 500 escaped UTF-16 units.
# Keep the other surfaces at 300, including Slack after entity escaping and code wrapping.
_SURFACE_LIMIT = 300
_PREVIEW_MIN = 20
_MARKDOWN_CONTROL = re.compile(r"\*\*|__|~~|\|\||`|\[[^\]]*\]\([^)]*\)|(?<!\w)[*_](?=\w)|(?<=\w)[*_](?!\w)")
_DESTINATION_KEYS = {
    "terminal": "command", "read_file": "path", "search_files": "path", "write_file": "path",
    "patch": "path", "vision_analyze": "image_url", "video_analyze": "video_url",
}
# The approve tools' argument types (terminal_tool.py, file_tools.py and vision_tools.py schemas
# in Hermes v0.23.0 and v0.23.1).
_ARGUMENT_TYPES = {
    "terminal": {
        "command": (str,), "background": (bool,), "timeout": (int,), "workdir": (str,), "pty": (bool,),
        "notify": (bool, list), "heartbeat": (int,), "persist_on_release": (bool,),
    },
    "read_file": {"path": (str,), "offset": (int,), "limit": (int,)},
    "search_files": {
        "pattern": (str,), "target": (str,), "path": (str,), "file_glob": (str,), "limit": (int,),
        "offset": (int,), "order": (str,), "output_mode": (str,), "context": (int,),
    },
    "write_file": {"path": (str,), "content": (str,)},
    "patch": {"path": (str,), "old_string": (str,), "new_string": (str,), "replace_all": (bool,)},
    "vision_analyze": {"image_url": (str,), "question": (str,), "region": (list,)},
    "video_analyze": {"video_url": (str,), "question": (str,)},
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
# Structured credentials, not words in ordinary names. Core's public redactor also covers
# provider formats and registered patterns (agent/redact.py).
_SECRET_NAME = (
    r"\b(?:(?:api|secret)[_ -]?key|(?:access|refresh|auth)[_-]?token|token|secret|password|passwd|pass|pwd|"
    r"credential|private[_ -]?key|authorization|AccountKey|X-Amz-Signature)\b"
)
_SECRET_ASSIGNMENT = re.compile(_SECRET_NAME + r"[\"']?\s*[:=]\s*", re.I)
_OPAQUE_SOURCE_VALUE = re.compile(r"[A-Za-z_][A-Za-z0-9._~+/-]{19,}(?=$|[\s\"';,)\]}])")
_SOURCE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".scala", ".lua", ".sh", ".bash", ".zsh", ".ps1",
})
_SLASH_COMMENT_SUFFIXES = _SOURCE_SUFFIXES - {".py", ".rb", ".lua", ".sh", ".bash", ".zsh", ".ps1"}
_SECRET_HINT = re.compile(
    r"(?P<assignment>" + _SECRET_NAME + r"=[^\s;,]+)"
    r"|\bBearer\s+(?:\[[^\]]+\]|[A-Za-z0-9._~+/-]{20,}=*)"
    r"|-----BEGIN (?:(?:[A-Z0-9]+ )*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    r"|(?<![\w-])--password(?:=|[ \t]+)[\"']?[^\s\"'-][^\s\"';]*"
    r"|\b(?:mysql|mariadb|sshpass)(?:\.exe)?[ \t]+[^\r\n;]*?(?<!\S)(?-i:-p)[ \t]*[\"']?(?!\.(?:\s|$))[^\s\"';-][^\s\"';]*"
    r"|\bcurl(?:\.exe)?[ \t]+[^\r\n;]*?(?<!\S)(?:-u[ \t]*|--user(?:=|[ \t]+))[\"']?[^\s\"':]+:[^\s\"';]+"
    r"|https://hooks\.slack(?:-gov)?\.com/services/[^\s\"'<>]+"
    r"|\bya29\.[A-Za-z0-9._~-]+"
    r"|\b(?:sk-[A-Za-z0-9_-]+|gh[po]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+"
    r"|xox[a-z]*-[A-Za-z0-9-]+|AKIA[A-Z0-9]+|AIza[A-Za-z0-9_-]+)\b",
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
# These environment values select commands, executable code or Git configuration that can do so.
_COMMAND_ENV = frozenset({
    "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER",
    "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_EXEC_PATH",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "SSH_ASKPASS", "PAGER", "EDITOR",
    "VISUAL", "LD_PRELOAD", "LD_AUDIT", "RSYNC_RSH",
})
_GIT_COMMAND_CONFIG = frozenset({
    "core.editor", "core.sshcommand", "core.pager", "core.askpass", "core.gitproxy",
    "core.hookspath", "core.fsmonitor", "sequence.editor", "diff.external", "credential.helper", "gpg.program",
    "core.alternaterefscommand", "imap.tunnel", "uploadpack.packobjectshook", "gpg.ssh.defaultkeycommand",
    "man.viewer", "web.browser", "init.templatedir", "include.path", "protocol.allow",
    "gc.recentobjectshook", "interactive.difffilter", "help.browser", "instaweb.browser", "instaweb.httpd",
})
_BLANK_GLYPHS = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180f\u2800\u3164\uffa0")
# A person's answers. Yolo, approvals off, unattended approve and the session cache approve without
# firing post_approval_response (tools/approval.py:1072-1105); smart_approve is an LLM's.
_HUMAN_CHOICES = frozenset({"once", "session", "always"})
_RULE_PREFIX = "hands-witness:"


def register(ctx) -> None:
    from . import client

    ctx.register_hook("post_tool_call", client.post_tool_call)
    ctx.register_hook("post_approval_response", client.post_approval_response)
    ctx.register_hook("pre_tool_call", partial(pre_tool_call, ctx))
    ctx.register_hook("pre_tool_call", client.explicit_terminal_timeout)
    ctx.register_hook("post_approval_response", post_approval_response)
    ctx.register_hook("transform_tool_result", transform_tool_result)


def post_approval_response(
    *, choice: str = "", pattern_key: str = "", session_id: str = "", tool_call_id: str = "", **kwargs
) -> None:
    from . import client

    # Other cards fire this hook with the same call ids: dangerous commands, protected file writes, and
    # another plugin's approve that core picked first (hermes_cli/plugins.py:1953). Only the exact rule
    # key of this call's own card counts (client.record_approval).
    if choice in _HUMAN_CHOICES and pattern_key.startswith(f"plugin_rule:{_RULE_PREFIX}"):
        client.record_approval(session_id, tool_call_id, pattern_key.removeprefix("plugin_rule:"))


def transform_tool_result(
    *, tool_name: str = "", session_id: str = "", tool_call_id: str = "", status: str = "", **kwargs
) -> str | None:
    """A read or search whose device command Hands refused shows Hands' message (client.py);
    every other result is left as it is."""
    try:
        from tools.registry import tool_error

        from . import client

        message = client.take_refusal(session_id, tool_call_id, tool_name)
        return tool_error(message) if message is not None else None
    except Exception:
        return None


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


def _source_tail(value: str, *, slash_comments: bool = False, arguments: bool = False) -> bool:
    tail = value.lstrip(" \t")
    while slash_comments and tail.startswith("/*"):
        end = tail.find("*/", 2)
        if end < 0:
            return False
        tail = tail[end + 2:].lstrip(" \t")
    if arguments:
        if re.match(r",[ \t]*(?:[\"']?[A-Za-z_]\w*[\"']?[ \t]*[:=]|[)\]}])", tail):
            return True
        closing = re.match(r"[)\]}]+:?[ \t]*", tail)
        if closing is not None:
            tail = tail[closing.end():]
    return not tail or tail[0] in "\r\n;#" or slash_comments and tail.startswith("//")


def _source_expression(value: str, *, slash_comments: bool = False, arguments: bool = False) -> bool:
    if value.startswith("(") or re.match(r"await\b", value):
        end, depth = len(value), 0
        lines = value.splitlines(keepends=True)
        try:
            for token in tokenize.generate_tokens(io.StringIO(value).readline):
                if not depth and (
                    token.type in {tokenize.NEWLINE, tokenize.ENDMARKER}
                    or token.type == tokenize.OP and token.string in ";,)]}"
                ):
                    end = sum(map(len, lines[:token.start[0] - 1])) + token.start[1]
                    break
                if token.type == tokenize.OP:
                    depth += token.string in "([{"
                    depth -= token.string in ")]}"
            if not _source_tail(value[end:], slash_comments=slash_comments, arguments=arguments):
                return False
            expression = ast.parse(value[:end], mode="eval").body
        except (SyntaxError, ValueError, tokenize.TokenError):
            return False
        if isinstance(expression, ast.Await):
            expression = expression.value
            if not isinstance(expression, ast.Call) or any(
                isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)) for node in ast.walk(expression)
            ):
                return False
        if not isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript, ast.Name, ast.Constant, ast.UnaryOp)):
            return False
        inner = ast.get_source_segment(value, expression)
        if inner is None or inner == value:
            return False
        return _source_expression(inner, slash_comments=slash_comments, arguments=arguments) or (
            isinstance(expression, ast.Name) and _OPAQUE_SOURCE_VALUE.match(inner) is None
        )
    initial = re.match(
        r"(?P<number>[-+]?(?:0[xX][\da-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][-+]?\d[\d_]*)?))"
        r"|(?P<environment>\$(?:[A-Za-z_]\w*\{[A-Za-z_]\w*\}|\{[A-Za-z_]\w*\}|[A-Za-z_]\w*(?::[A-Za-z_]\w*)?))"
        r"|[A-Za-z_]\w*", value
    )
    if initial is None:
        return False
    index = initial.end()
    expression = initial.lastgroup is not None
    while initial.lastgroup is None:
        while index < len(value) and value[index] in " \t":
            index += 1
        attribute = re.match(r"\.[A-Za-z_]\w*", value[index:])
        if attribute is not None:
            index += attribute.end()
            expression = True
            continue
        if index >= len(value) or value[index] not in "([":
            break
        expression = True
        stack = [{"(": ")", "[": "]"}[value[index]]]
        index += 1
        quote = ""
        while index < len(value) and stack:
            char = value[index]
            if quote:
                if char == "\\":
                    index += 2
                elif value.startswith(quote, index):
                    index += len(quote)
                    quote = ""
                else:
                    index += 1
                continue
            if char in "\"'`":
                quote = char * 3 if value.startswith(char * 3, index) else char
                index += len(quote)
                continue
            if char == "#" or slash_comments and value.startswith("//", index):
                while index < len(value) and value[index] not in "\r\n":
                    index += 1
                continue
            if slash_comments and value.startswith("/*", index):
                end = value.find("*/", index + 2)
                if end < 0:
                    return False
                index = end + 2
                continue
            if char in "([{":
                stack.append({"(": ")", "[": "]", "{": "}"}[char])
            elif char in ")]}":
                if char != stack.pop():
                    return False
            index += 1
        if stack or quote:
            return False
    return expression and _source_tail(value[index:], slash_comments=slash_comments, arguments=arguments)


def _python_source_assignments(message: str) -> bool:
    try:
        tree = ast.parse(message)
    except (SyntaxError, ValueError):
        return False
    positions = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            positions.update((target.lineno, target.col_offset) for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.keyword) and node.arg is not None:
            positions.add((node.lineno, node.col_offset))
    assignments = list(_SECRET_ASSIGNMENT.finditer(message))
    return bool(assignments) and all(
        (
            message.count("\n", 0, assignment.start()) + 1,
            len(message[message.rfind("\n", 0, assignment.start()) + 1:assignment.start()].encode("utf-8")),
        ) in positions
        for assignment in assignments
    )


def _secret_problem(message: str, *, source: bool = False, card: bool = False, slash_comments: bool = False, unspaced: bool = True, spacing_hint: bool = False) -> str | None:
    from agent.redact import redact_sensitive_text

    if redact_sensitive_text(message, force=True) != message:
        if source and not card and unspaced and spacing_hint and _python_source_assignments(message):
            spaced = _SECRET_ASSIGNMENT.sub(
                lambda assignment: re.sub(r"[ \t]*=[ \t]*$", " = ", assignment.group()), message
            )
            if (
                spaced != message
                and redact_sensitive_text(spaced, force=True) == spaced
                and _secret_problem(spaced, source=True, slash_comments=slash_comments) is None
                and not any(
                    _OPAQUE_SOURCE_VALUE.match(message[assignment.end():])
                    for assignment in _SECRET_ASSIGNMENT.finditer(message)
                )
            ):
                return (
                    messages.WITNESS_SECRET_HIDDEN
                    + " if this is ordinary code, writing it with spaces around = (token = token) is not masked"
                )
        return messages.WITNESS_SECRET_HIDDEN
    if any(
        hint.lastgroup != "assignment" or not (source and unspaced)
        for hint in _SECRET_HINT.finditer(message)
    ):
        return messages.WITNESS_SECRET_BLOCKED
    for assignment in _SECRET_ASSIGNMENT.finditer(message):
        value = message[assignment.end():]
        arguments = source and unspaced
        compact = arguments and re.fullmatch(_SECRET_NAME + r"[\"']?[:=]", assignment.group(), re.I) is not None
        # Spaced source assignments retain their existing behavior.
        if compact:
            hint = _SECRET_HINT.search(value)
            if hint is not None and hint.lastgroup != "assignment":
                return messages.WITNESS_SECRET_BLOCKED
            if re.match(r"(?:os\.(?:environb?|getenv)|process\.env)", value) and not re.match(
                r"(?:os\.getenv\s*\(|os\.environ(?:\s*\[|\.get\s*\()|process\.env(?:\.[A-Za-z_]\w*|\s*\[))", value
            ):
                return messages.WITNESS_SECRET_BLOCKED
        # Core's YAML matcher is line-anchored; a credential mapping inside prose is
        # still a literal, even when the surrounding text keeps core from masking it.
        fragment = assignment.group() + re.split(r"[\"'\r\n]", value, maxsplit=1)[0]
        if not compact and redact_sensitive_text(fragment, force=True) != fragment:
            return messages.WITNESS_SECRET_BLOCKED
        if re.match(r"Bearer\s+\S+", value, re.I):
            return messages.WITNESS_SECRET_BLOCKED
        # A literal stays a literal in the JSON-escaped approval copy too.
        literal = re.match(r"(?:[rubf]{1,2})?((?:\\?\"){3}|(?:\\?'){3}|\\?[\"'`])(.*?)\1", value, re.I | re.S)
        if literal is not None:
            tail = value[literal.end():].lstrip(" \t")
            value = literal.group(2)
            if (
                value not in {"", "...", "xxx"}
                and not re.fullmatch(r"<[^<>\s]+>|\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*", value)
                or not card and not _source_tail(tail, slash_comments=slash_comments, arguments=arguments)
            ):
                return messages.WITNESS_SECRET_BLOCKED
            continue
        if compact and not card and _OPAQUE_SOURCE_VALUE.match(value):
            return messages.WITNESS_SECRET_BLOCKED
        if card or source and _source_expression(value, slash_comments=slash_comments, arguments=arguments):
            continue
        if re.match(r"[A-Za-z0-9._~+/-]{20,}(?=$|[\s\"';,])", value):
            return messages.WITNESS_SECRET_BLOCKED
        if not source and value.strip():
            return messages.WITNESS_SECRET_BLOCKED
        if source and not card:
            bare = re.match(r"[A-Za-z_]\w*", value)
            if bare is None or not _source_tail(value[bare.end():], slash_comments=slash_comments, arguments=arguments):
                return messages.WITNESS_SECRET_BLOCKED
    return None


def _contains_secret(message: str, *, source: bool = False) -> bool:
    return _secret_problem(message, source=source) is not None

def _display_problem(message: str) -> str | None:
    if " " * 21 in message or not all(map(_visible, message)):
        return messages.WITNESS_CONTROL_CHARACTERS_BLOCKED
    # Every approval surface shows the redacted copy (tools/approval.py:935-936); force ignores the config switch.
    # Complete arguments have already been scanned with their file context. This copy
    # can contain a JSON-escaped source preview, so do not reclassify its bare names.
    if problem := _secret_problem(message, source=True, card=True):
        return problem
    return None


def _mistyped(tool_name: str, args: dict) -> bool:
    """Whether an argument is not already its schema type. The agent path coerces the arguments only
    after this hook runs (model_tools.py:902), so the card would show another value than the one
    that runs."""
    types = _ARGUMENT_TYPES.get(tool_name, {})
    return any(
        key in types
        and value is not None
        and (not isinstance(value, types[key]) or (isinstance(value, bool) and bool not in types[key]))
        for key, value in args.items()
    )


def _message(tool_name: str, device_name: str, details: str) -> str:
    return messages.WITNESS_APPROVAL.format(
        tool=_sanitize_approval_text(tool_name),
        device=_sanitize_approval_text(device_name),
        details=_sanitize_approval_text(details),
    )


def _surface_text(message: str, surface: str) -> str:
    if surface in {"slack", "discord"}:
        # Slack decodes only these three entities. Both dialects leave code spans literal.
        return "`" + (html.escape(message, quote=False) if surface == "slack" else message) + "`"
    return message


def _problem(message: str, surface: str = "") -> str | None:
    if problem := _display_problem(message):
        return problem
    if surface in {"slack", "discord"}:
        if "`" in message:
            return messages.WITNESS_MARKDOWN_BLOCKED
    elif surface != "telegram" and _MARKDOWN_CONTROL.search(message):
        return messages.WITNESS_MARKDOWN_BLOCKED
    rendered = _surface_text(message, surface)
    # Core escapes Telegram's HTML; the unknown-surface budget stays conservative as before.
    measured = html.escape(rendered) if surface not in {"slack", "discord"} else rendered
    limit = 500 if surface == "telegram" else _SURFACE_LIMIT
    if len(measured.encode("utf-16-le")) // 2 > limit:
        return messages.WITNESS_ARGUMENTS_LONG
    return None


def _approval(tool_name: str, device_name: str, details: str, surface: str = "") -> dict:
    message = _message(tool_name, device_name, details)
    if problem := _problem(message, surface):
        return {"action": "block", "message": problem}
    return {
        "action": "approve",
        "message": _surface_text(message, surface),
        "rule_key": f"{_RULE_PREFIX}{secrets.token_hex(16)}",
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
    if tool_name == "terminal" and args.get("background") is True:
        parts.append("A background command has no time limit; press S to stop it.")
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


def _render(tool_name: str, device_name: str, args: dict, surface: str = "") -> dict:
    content = args.get("content")
    if tool_name != "write_file" or not isinstance(content, str):
        result = _approval(tool_name, device_name, _details(tool_name, args), surface)
    else:
        # A write shows its length, digest and as much of its start as fits on one line.
        count = 0
        for end in range(1, len(content) + 1):
            problem = _problem(_message(tool_name, device_name, _details(tool_name, args, end)), surface)
            if problem is None:
                count = end
            elif problem not in {messages.WITNESS_SECRET_BLOCKED, messages.WITNESS_SECRET_HIDDEN}:
                break
        if count < min(len(content), _PREVIEW_MIN):
            result = {"action": "block", "message": problem}
        else:
            result = _approval(tool_name, device_name, _details(tool_name, args, count), surface)
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
    end = arguments.index("--") if "--" in arguments else len(arguments)
    return any(re.match(r"-[^-]", word) and set(word[1:]) & set(letters) for word in arguments[:end])


def _carrier_options(arguments: list[str], short_values: str, long_values: tuple[str, ...], *, short_flags: str | None = None) -> list[str]:
    options = []
    words = iter(arguments)
    for word in words:
        if word == "--":
            break
        if not word.startswith("-"):
            continue
        options.append(word)
        if word.startswith("--"):
            if "=" not in word and _long_option(word, long_values):
                next(words, "")
        else:
            for index, letter in enumerate(word[1:], 2):
                if short_flags is not None and letter not in short_flags + short_values:
                    options[-1] = word[:index - 1]
                    break
                if letter in short_values:
                    options[-1] = word[:index]
                    if index == len(word):
                        next(words, "")
                    break
    return options


def _container_runs_program(arguments: list[str]) -> bool:
    words = iter(arguments)
    for word in words:
        if word == "--":
            word = next(words, "")
        elif word in {"--config", "--context", "--host", "--log-level", "--connection", "--url", "--root", "--runroot", "-c", "-H", "-l"}:
            next(words, "")
            continue
        elif word.startswith("-"):
            continue
        if word == "container":
            word = next(words, "")
        return word in {"exec", "run"}
    return False


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
        # make variable values can become recipe commands, including nested assignments.
        # Ordinary message, pattern and path arguments carry data, even with whitespace.
        if executable == "make" or (not executable and _ASSIGNMENT.match(word)):
            if "=" in word:
                for value in _values(word):
                    if any(char.isspace() for char in value):
                        yield from (split for split in _split(value) if split)


# Shipped commands from Git 2.54 help -a and --list-cmds=builtins, excluding external commands.
_GIT_SUBCOMMANDS = frozenset("""
add am annotate apply archimport archive backfill bisect blame branch bugreport bundle cat-file
check-attr check-ignore check-mailmap check-ref-format checkout checkout--worker checkout-index
cherry cherry-pick citool clean clone column commit commit-graph commit-tree config count-objects
credential credential-cache credential-cache--daemon credential-store cvsexportcommit cvsimport
cvsserver daemon describe diagnose diff diff-files diff-index diff-pairs diff-tree difftool
fast-export fast-import fetch fetch-pack filter-branch fmt-merge-msg for-each-ref for-each-repo
format-patch fsck fsck-objects fsmonitor--daemon gc get-tar-commit-id gitk gitweb grep gui
hash-object help history hook http-backend imap-send index-pack init init-db instaweb
interpret-trailers last-modified log ls-files ls-remote ls-tree mailinfo mailsplit maintenance
merge merge-base merge-file merge-index merge-one-file merge-ours merge-recursive
merge-recursive-ours merge-recursive-theirs merge-subtree merge-tree mergetool mktag mktree
multi-pack-index mv name-rev notes p4 pack-objects pack-redundant pack-refs patch-id pickaxe
prune prune-packed pull push quiltimport range-diff read-tree rebase receive-pack reflog refs
remote remote-ext remote-fd repack replace replay repo request-pull rerere reset restore rev-list
rev-parse revert rm scalar send-email send-pack sh-i18n sh-setup shortlog show show-branch
show-index show-ref sparse-checkout stage stash status stripspace submodule submodule--helper
survey svn switch symbolic-ref tag unpack-file unpack-objects update-index update-ref
update-server-info upload-archive upload-archive--writer upload-pack var verify-commit
verify-pack verify-tag version whatchanged worktree write-tree
""".split())
_GIT_PROGRAM_OPTIONS = (
    "upload-pack", "receive-pack", "exec", "exec-path", "upload-archive", "ssh-command", "sendmail-cmd",
)


# Value-taking options and executable selectors from Git 2.54 command help.
_GIT_OPTIONS = {
    "clone": ("oubjc", ("origin", "branch", "jobs", "config", "template", "reference", "reference-if-able", "depth", "shallow-since", "shallow-exclude", "separate-git-dir", "server-option", "filter", "bundle-uri", "revision", "ref-format"), "u", ("upload-pack", "template")),
    "init": ("b", ("initial-branch", "separate-git-dir", "object-format", "ref-format"), "", ("template",)),
    "fetch": ("jo", ("jobs", "depth", "shallow-since", "shallow-exclude", "deepen", "refmap", "server-option", "negotiation-tip", "filter"), "", ("upload-pack",)),
    "pull": ("sXo", ("strategy", "strategy-option", "cleanup", "depth", "shallow-since", "shallow-exclude", "deepen", "refmap", "server-option", "negotiation-tip"), "", ("upload-pack",)),
    "ls-remote": ("o", ("sort", "server-option"), "", ("upload-pack", "exec")),
    "fetch-pack": ("", (), "", ("upload-pack", "exec")),
    "send-pack": ("", ("remote", "push-option"), "", ("receive-pack", "exec")),
    "upload-pack": ("", ("timeout",), "", ()),
    "receive-pack": ("", (), "", ()),
    "push": ("o", ("repo", "push-option", "recurse-submodules"), "", ("receive-pack", "exec")),
    "archive": ("o", ("output", "format", "prefix", "add-file", "add-virtual-file", "mtime", "remote"), "", ("exec",)),
    "grep": ("efmABC", ("max-count", "context", "before-context", "after-context", "threads", "max-depth"), "O", ("open-files-in-pager",)),
    "difftool": ("tSGlOI", ("tool", "stat-width", "stat-name-width", "stat-graph-width", "stat-count", "ws-error-highlight", "src-prefix", "dst-prefix", "line-prefix", "inter-hunk-context", "output-indicator-new", "output-indicator-old", "output-indicator-context", "ignore-matching-lines", "diff-algorithm", "anchored", "word-diff-regex", "color-moved-ws", "rotate-to", "skip-to", "find-object", "diff-filter", "max-depth", "output"), "x", ("extcmd",)),
    "mergetool": ("t", ("tool",), "", ()),
    "commit": ("mFCctU", ("message", "file", "template", "unified", "inter-hunk-context", "reuse-message", "reedit-message", "author", "date", "cleanup", "trailer", "fixup", "squash", "pathspec-from-file"), "", ()),
    "log": ("SGL", ("grep", "author", "committer", "since", "until", "after", "before"), "", ()),
    "show": ("SGL", (), "", ()),
    "rebase": ("CsX", ("onto", "whitespace", "empty", "strategy", "strategy-option", "trailer"), "x", ("exec",)),
    "config": ("ft", ("file", "blob", "type", "default", "comment", "value", "url"), "e", ("edit",)),
    "send-email": ("", ("from", "to", "cc", "bcc", "subject", "reply-to", "in-reply-to", "compose-encoding", "8bit-encoding", "transfer-encoding", "envelope-sender", "smtp-server", "smtp-server-option", "smtp-server-port", "smtp-user", "smtp-pass", "smtp-encryption", "smtp-ssl-cert-path", "smtp-ssl-client-cert", "smtp-ssl-client-key", "smtp-domain", "smtp-auth", "smtp-debug", "imap-sent-folder", "batch-size", "relogin-delay", "identity", "suppress-cc", "confirm"), "", ("sendmail-cmd", "to-cmd", "cc-cmd", "header-cmd", "smtp-server")),
}


def _git_parts(arguments: list[str]) -> tuple[list[str], str, list[str]]:
    index = 0
    while index < len(arguments):
        word = arguments[index]
        if word == "--":
            index += 1
            break
        if not word.startswith("-"):
            break
        index += 1
        if word in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source", "--shallow-file"}:
            index += 1
    return arguments[:index], arguments[index] if index < len(arguments) else "", arguments[index + 1:]


def _git_command_config(config: str) -> bool:
    name = config.partition("=")[0].casefold()
    return (
        name in _GIT_COMMAND_CONFIG
        or name.startswith(("alias.", "pager.", "filter."))
        or name.startswith("gpg.") and name.endswith(".program")
        or name.startswith("merge.") and name.endswith(".driver")
        or name.startswith(("diff.", "difftool.", "mergetool.")) and name.endswith((".command", ".cmd", ".textconv"))
        or name.startswith(("difftool.", "mergetool.", "man.", "browser.")) and name.endswith((".cmd", ".path"))
        or name.startswith(("tar.", "hook.")) and name.endswith(".command")
        or name.startswith("credential.") and name.endswith(".helper")
        or name.startswith("remote.") and name.endswith((".uploadpack", ".receivepack", ".vcs"))
        or name.startswith("sendemail.") and name.endswith((".sendmailcmd", ".tocmd", ".cccmd", ".headercmd", ".smtpserver"))
        or name.startswith("submodule.") and name.endswith(".update")
        or name.startswith("includeif.") and name.endswith(".path")
        or name.startswith("protocol.") and name.endswith(".allow")
        or name.startswith("trailer.") and name.endswith((".command", ".cmd"))
        or name.startswith("guitool.") and name.endswith(".cmd")
    )


def _git_runs_program(global_arguments: list[str], subcommand: str, arguments: list[str]) -> bool:
    if subcommand and subcommand not in _GIT_SUBCOMMANDS:
        return True
    if subcommand in {"filter-branch", "daemon", "instaweb", "credential"} or subcommand.startswith("credential-"):
        return True
    if subcommand in {"bisect", "submodule"}:
        operation = next((word for word in arguments if not word.startswith("-")), "")
        if operation == {"bisect": "run", "submodule": "foreach"}[subcommand]:
            return True
    short_values, long_values, short_programs, long_programs = _GIT_OPTIONS.get("init" if subcommand == "init-db" else subcommand, ("", (), "", ()))
    options = _carrier_options(arguments, short_values, long_values)
    # Difftool parses its own options before forwarding unknown arguments to diff.
    # An unknown short letter preserves the whole remaining argument, including pattern text.
    program_options = _carrier_options(arguments, "tx", ("tool", "extcmd"), short_flags="gdy") if subcommand == "difftool" else options
    global_options = _carrier_options(global_arguments, "Cc", ("git-dir", "work-tree", "namespace", "attr-source", "config-env", "shallow-file"))
    # Check every invocation, even commands absent from the value table. Consumed values
    # and arguments after -- are data; executable selectors accept abbreviated long names.
    if _short_option(program_options, short_programs) or any(
        word.startswith("--") and bool(word[2:].split("=", 1)[0])
        and any(name.startswith(word[2:].split("=", 1)[0].casefold()) for name in long_programs)
        for word in program_options
    ) or any(
        word.startswith("--") and bool(word[2:].split("=", 1)[0])
        and any(name.startswith(word[2:].split("=", 1)[0].casefold()) for name in _GIT_PROGRAM_OPTIONS)
        for word in global_options + options
    ):
        return True
    if subcommand == "config":
        words = iter(arguments)
        operands = []
        read_only = False
        mutating = False
        rename = False
        for word in words:
            if word == "--":
                operands.extend(words)
                break
            if word == "-l" or _long_option(word, ("get", "get-all", "get-regexp", "get-urlmatch", "get-color", "get-colorbool", "list")):
                read_only = True
            elif _long_option(word, ("add", "replace-all", "unset", "unset-all", "rename-section", "remove-section")):
                mutating = True
                rename = rename or _long_option(word, ("rename-section",))
            elif word.startswith("--"):
                if "=" not in word and _long_option(word, long_values):
                    next(words, "")
            elif word.startswith("-"):
                for index, letter in enumerate(word[1:], 2):
                    if letter in short_values:
                        if index == len(word):
                            next(words, "")
                        break
            else:
                operands.append(word)
        if operands and operands[0] in {"get", "list", "set", "unset", "rename-section", "remove-section", "edit"}:
            action = operands.pop(0)
            if action == "edit":
                return True
            read_only = action in {"get", "list"}
            mutating = action not in {"get", "list"}
            rename = action == "rename-section"
        if rename and len(operands) > 1 and any(
            _git_command_config(operands[1] + "." + key)
            for key in ("editor", "helper", "program", "driver", "textconv", "cmd", "clean", "command", "path", "uploadpack", "receivepack", "vcs", "sendmailcmd", "tocmd", "cccmd", "headercmd", "smtpserver", "update", "allow")
            + tuple(name.rsplit(".", 1)[-1] for name in _GIT_COMMAND_CONFIG)
        ):
            return True
        if (not read_only or mutating) and operands and _git_command_config(operands[0]):
            return True
    # Only global -c/--config-env and clone -c/--config are configuration.
    groups = [(global_arguments, "C", ("git-dir", "work-tree", "namespace", "attr-source", "shallow-file"), True)]
    if subcommand == "clone":
        groups.append((arguments, short_values.replace("c", ""), tuple(name for name in long_values if name != "config"), False))
    for group, short_values, long_values, global_options in groups:
        words = iter(group)
        for word in words:
            if word == "--":
                break
            config = ""
            indirect = global_options and word.startswith("--config-env")
            if word.startswith("-c"):
                config = word[2:] or next(words, "")
            elif indirect or not global_options and _long_option(word, ("config",)):
                config = word.partition("=")[2] or next(words, "")
            elif word.startswith("--"):
                if "=" not in word and _long_option(word, long_values):
                    next(words, "")
            elif word.startswith("-"):
                for index, letter in enumerate(word[1:], 2):
                    if letter == "c":
                        config = word[index:] or next(words, "")
                        break
                    if letter in short_values:
                        if index == len(word):
                            next(words, "")
                        break
            if _git_command_config(config):
                return True
    return False


def _runs_program(words: list[str], depth: int) -> bool:
    """Whether a command runs a program the card does not show as the command, or a sed script that
    writes or runs, here or in a command line carried in one of its arguments (two levels deep)."""
    assignments, words = _command_words(words)
    executable = _program(words[0]) if words else ""
    arguments = words[1:]
    git_global, git_command, git_arguments = _git_parts(arguments) if executable == "git" else ([], "", [])
    rsync_options = _carrier_options(arguments, "fBMT", (
        "exclude", "include", "exclude-from", "include-from", "filter", "files-from", "password-file",
        "log-file", "out-format", "chmod", "chown", "usermap", "groupmap", "bwlimit", "timeout",
        "contimeout", "max-size", "min-size", "max-delete", "backup-dir", "suffix", "temp-dir",
        "compare-dest", "copy-dest", "link-dest", "partial-dir", "address", "port", "sockopts", "block-size",
    )) if executable == "rsync" else []
    if (
        # Judged as written: in a quoted path such as 'Start Menu' or 'Source Code' the first word is a folder.
        (depth and words and _launcher(words[0].casefold().rstrip(" .").removesuffix(".exe")))
        or any(word.split("=", 1)[0].rstrip("+").upper() in _COMMAND_ENV for word in assignments)
        or executable == "ssh"
        or (executable == "git" and _git_runs_program(git_global, git_command, git_arguments))
        or (
            executable == "rsync"
            and (_short_option(rsync_options, "e") or any(_long_option(word, ("rsh", "rsync-path")) for word in rsync_options))
        )
        or (executable == "scp" and _short_option(arguments, "SDFo"))
        or (executable in {"docker", "podman"} and _container_runs_program(arguments))
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
    git_command = _git_parts(words[1:])[1] if executable == "git" else ""
    if git_command and git_command not in _GIT_SUBCOMMANDS:
        return {"action": "block", "message": messages.WITNESS_COMMAND_BLOCKED + " unknown git subcommand, may be an alias"}
    git_grep = git_command == "grep"
    if (
        "/" in first
        or "\\" in first
        or _launcher(executable)
        or executable in _STATE_BUILTINS
        or any("powershell" in token.casefold() or "pwsh" in token.casefold() for token in tokens)
        or any(_encoded_flag(token) and not (git_grep and token == "-e") for token in tokens)
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


def pre_tool_call(ctx, tool_name: str, args: dict, **kwargs):
    from . import client, environment

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
        if not isinstance(args, dict):
            return {"action": "block", "message": messages.WITNESS_ARGUMENTS_BLOCKED}
        args = copy.deepcopy(args)
        if tool_name == "terminal" and args.get("background") is True and "timeout" in args:
            return {"action": "block", "message": "a background command has no time limit: leave out timeout; press S to stop it"}
        if tool_name == "terminal" and args.get("background") is not True and args.get("timeout") is None:
            from hermes_cli.config import apply_terminal_config_to_env

            terminal_env = apply_terminal_config_to_env(env=dict(os.environ))
            args["timeout"] = int(terminal_env.get("TERMINAL_TIMEOUT", "180"))
        if tool_name == "search_files":
            path = args.get("path")
            if path is None or (isinstance(path, str) and not path.strip()):
                args["path"] = "."
        if _mistyped(tool_name, args):
            return {"action": "block", "message": messages.WITNESS_ARGUMENT_TYPES_BLOCKED}
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
            # Core anchors a relative path on one of several folders (file_tools_paths.py:131-144).
            if environment.absolute_file_path(path) is None:
                return {"action": "block", "message": messages.WITNESS_ABSOLUTE_PATH_REQUIRED}
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
        # Scan complete values before a write is shortened to its preview.
        suffix = posixpath.splitext(args["path"].replace("\\", "/"))[1].casefold() if tool_name in _CONTENT_KEYS else ""
        source = suffix in _SOURCE_SUFFIXES
        problems = {
            _secret_problem(text, source=source and key in multiline, slash_comments=suffix in _SLASH_COMMENT_SUFFIXES and key in multiline, unspaced=suffix not in {".sh", ".bash", ".zsh"}, spacing_hint=tool_name == "write_file" and suffix == ".py" and key == "content")
            for key, value in args.items() for text in _strings(value)
        }
        problems.update(_secret_problem(text) for text in _strings(list(args)))
        if problem := next((problem for problem in problems if problem and problem.startswith(messages.WITNESS_SECRET_HIDDEN)), None):
            return {"action": "block", "message": problem}
        if messages.WITNESS_SECRET_BLOCKED in problems:
            return {"action": "block", "message": messages.WITNESS_SECRET_BLOCKED}
        surface = ctx.session_surface() if hasattr(ctx, "session_surface") else ""
        if tool_name != "terminal":
            texts = list(_strings(args))
            if (
                surface in {"slack", "discord"} and any("`" in text for text in texts)
                or surface not in {"slack", "discord", "telegram"}
                and any(_MARKDOWN_CONTROL.search(text) for text in texts)
            ):
                return {"action": "block", "message": messages.WITNESS_MARKDOWN_BLOCKED}
        decision = _render(tool_name, device["name"], args, surface)
        if decision["action"] == "approve":
            # Another plugin's modify can change the arguments after this card is built
            # (plugins.py:1230-1238); the device runs only commands that match it (environment.py).
            client.record_shown(
                kwargs.get("session_id", ""), kwargs.get("tool_call_id", ""), tool_name, args, decision["rule_key"]
            )
        return decision
    except Exception:
        if tool_name not in _SAFE_TOOLS:
            return {"action": "block", "message": messages.WITNESS_TARGET_BLOCKED}
        return None
