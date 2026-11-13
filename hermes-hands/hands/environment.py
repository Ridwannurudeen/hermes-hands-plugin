"""The ``hands`` terminal backend: one environment object that runs each call on the target the
conversation chose (``targets.resolve_target``), through one lazily created sub-environment per target.

``server`` is a plain ``LocalEnvironment`` on the gateway host and never touches the relay. A device
is a :class:`DeviceEnvironment`, whose commands travel through the relay as signed jobs; an offline,
revoked or refused device, or a relay that is down, fails the call with 255 and nothing runs anywhere
else.
"""

from __future__ import annotations

import base64
import contextvars
import json
import logging
import os
import posixpath
import re
import shlex
import sqlite3
import threading
from pathlib import Path

from gateway.session_context import get_session_env
from tools.environments.base import BaseEnvironment
from tools.environments.local import LocalEnvironment

from . import client, messages, store, targets, witness
from .handle import RemoteProcessHandle
from .relay import UNREACHABLE

logger = logging.getLogger(__name__)

_DRIVE_PATH = re.compile(r"^([A-Za-z]):[\\/]*(.*)$")
# Core's background launcher and poller name their files after the registry session
# (process_registry.py:1271-1300, 1418-1466) and kill by pid (:2245-2246).
_BACKGROUND_FILE = re.compile(r"hermes_bg_([\w-]+)\.(?:log|pid|exit)\b")
_BACKGROUND_KILL = re.compile(r"kill (\d+) 2>/dev/null")
# One shell word of a file-tool command: single-quoted as core's file tools quote arguments
# (file_operations.py:535-557), or a bare word ``shlex.quote`` left unquoted.
_SHELL_WORD = r"'(?:[^']|'\"'\"')*'|[\w@%+=:,./-]+"
# The poller's liveness probe and exit read (process_registry.py:1460, 1465), and the start of its
# log read (process_registry_env_log.py:17-18), each naming one job file.
_BACKGROUND_PROBE = re.compile(
    rf'kill -0 "\$\(cat ({_SHELL_WORD}) 2>/dev/null\)" 2>/dev/null; echo \$\?'
)
_BACKGROUND_EXIT = re.compile(rf"cat ({_SHELL_WORD}) 2>/dev/null")
_BACKGROUND_LOG = re.compile(rf"O=(\d+); S=\$\(\{{ wc -c < ({_SHELL_WORD}); \}}")
# Core launcher fields: folder, command, log, exit file and pid file (process_registry.py:1282-1288).
_LAUNCH_WRAPPER = re.compile(
    rf"mkdir -p ({_SHELL_WORD}) && \( nohup bash -lc ({_SHELL_WORD}) > ({_SHELL_WORD}) 2>&1; "
    rf"rc=\$\?; printf '%s\\n' \"\$rc\" > ({_SHELL_WORD}) \) & echo \$! > ({_SHELL_WORD}) && cat \5"
)
_LINTER = re.compile(rf"(node --check|npx tsc --noEmit|go vet|rustfmt --check) ({_SHELL_WORD}) 2>&1")
_WORD = re.compile(r"'((?:[^']|'\"'\"')*)'|(?<![^\s<>|;&(])([\w@%+=:,./-]+)(?=[\s<>|;&)]|\Z)")
# The start of core's atomic write (file_operations.py:586-606): its parent and target.
_ATOMIC_WRITE = re.compile(rf"set -e; d=({_SHELL_WORD}); t=({_SHELL_WORD}); ")
# A search_files command (file_operations_search.py:688-693, 1221, 1328): rg, grep or find first.
# The executable is bare, or single-quoted when its path has a space (file_operations_search.py:695-702).
_SEARCH = re.compile(
    r"(?:set -o pipefail; )?(?:cd \S.*? && )?"
    r"(?P<executable>'(?:[^']|'\"'\"')*[\\/](?:rg|rg\.exe)'|(?:[^'\s]*[\\/])?(?:rg|rg\.exe|grep|find)) ", re.I
)
# A Windows path core joined onto the base, which it does to anything not POSIX-absolute for a
# container backend (file_tools_paths.py:157-163): ``<home>/C:\Users\x`` or ``<home>/C:/Users/x``.
_JOINED_DRIVE = re.compile(r"/([A-Za-z]:(?:[\\/].*)?)\Z", re.S)
# Core's python snippets (file_operations.py:722-737) and the path they act on (:748, :1317).
_PYTHON_SNIPPET = re.compile(
    r"(python3?) -c \"import base64; exec\(base64\.b64decode\('([A-Za-z0-9+/=]*)'\)\.decode\(\)\)\""
)
_SNIPPET_PATH = re.compile(r"^p = (?:pathlib\.Path\()?(\"(?:[^\"\\]|\\.)*\")", re.M)
# A paged read or document extraction, for primary-refusal reporting.
_SED_PAGE = re.compile(r"sed -n '(\d+),(\d+)p'")
_WHOLE_READ = re.compile(rf"base64 < (?:{_SHELL_WORD})")
_SEARCH_EXECUTABLE = re.compile(r"(?:set -o pipefail; )?('(?:[^']|'\"'\"')*'|\S+) ")
# Core turns on rg's multiline mode for a \n escape (file_operations_search.py:382-389).
_REGEX_NEWLINE = re.compile(r"(?<!\\)(?:\\\\)*\\n")
_OUTPUT_FLAGS = {"files_only": "-l", "count": "-c"}
# Whole-document transport precedes extraction and pagination (tools/read_extract.py, both versions).
_DOCUMENT_EXTENSIONS = frozenset({
    ".ipynb", ".docx", ".xlsx", ".db", ".sqlite", ".sqlite3", ".doc", ".docm", ".ppt", ".pps",
    ".pot", ".pptx", ".pptm", ".ppsx", ".ppsm", ".xls", ".xlsm", ".xlsb", ".odt", ".ods",
    ".odp", ".rtf", ".epub", ".pdf",
})
# Core's zero-match hidden-file probe exclusions (agent/search_policy.py, both pinned versions).
_SEARCH_HINT_PRUNES = sorted({
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "site-packages", "dist-packages",
    "vendor", "third_party", "build", "dist", "target", "out", "coverage", ".next", ".turbo",
    ".parcel-cache", ".nuxt", ".svelte-kit", ".archive", "__pycache__", ".cache", ".Trash",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".npm", ".yarn", ".pnpm-store",
    ".gradle", ".m2", ".nuget", "backups", "backup", ".backups",
})
# The session key (else the task id) -> target -> where the target's last terminal command that
# core records ended. Keyed as core keys its own cwd record, which outlives an idle-reaped
# environment and /new (terminal_tool.py:255-283, 1528-1530), and kept per process as that is.
_SESSION_CWDS: dict[str, dict[str, str]] = {}
# Set by DeviceEnvironment.execute for one call and read in _run_bash, which core runs on its wait
# worker in a copy of the caller's context (agent/deadline.py:340-361).
_INLINE_LIMIT: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "hermes_hands_inline_limit", default=None
)

_FILE_OP: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "hermes_hands_file_op", default=False
)


def device_path(path: str) -> str:
    """A native Windows path (``C:\\Users\\x``, ``C:/Users/x``) in its Git Bash form ``/c/Users/x``;
    any other path unchanged. Core does this only for the local backend (``local.py:172-189``)."""
    match = _DRIVE_PATH.match(path)
    if match is None:
        return path
    tail = match.group(2).replace("\\", "/")
    return f"/{match.group(1).lower()}/{tail}"


_FILE_TOOLS = frozenset({"read_file", "write_file", "patch", "search_files", "vision_analyze"})


def _gateway_home() -> str | None:
    """The home core's file tools put in place of a model's ``~`` (file_tools_paths.py:32-49, 147-154),
    when it is a POSIX path; a Windows gateway's home could never appear in a device command."""
    from hermes_constants import get_subprocess_home

    home = (get_subprocess_home() or os.path.expanduser("~")).rstrip("/")
    return home if home and posixpath.isabs(home) else None


def _configured_cwd() -> str | None:
    """``terminal.cwd``, which gateway startup bridges to TERMINAL_CWD (agent/runtime_cwd.py:3-6),
    when absolute: core's file tools anchor only on such a cwd (file_tools_paths.py:96-112)."""
    configured = os.path.expanduser(os.getenv("TERMINAL_CWD", "").strip())
    return configured if os.path.isabs(configured) else None


def absolute_file_path(path: str) -> str | None:
    """A write or patch path that names one file whatever folder core anchors on: absolute, or
    ``~/`` as core expands it (file_tools_paths.py:32-49), normalized as core normalizes it (:157-163).
    A drive path, which core joins onto the folder, names one file only on a Windows device and
    only without . or .. parts (DeviceEnvironment._file_path). None for any other path."""
    expanded = _expand_tilde(path)
    if posixpath.isabs(expanded):
        return posixpath.normpath(expanded)
    if re.match(r"^[A-Za-z]:[\\/]", expanded) and not {".", ".."} & set(re.split(r"[\\/]", expanded)):
        return expanded
    return None


def resolve_current_target(ctx) -> str:
    return targets.resolve_target(
        session_key=get_session_env("HERMES_SESSION_KEY", ""),
        in_cron=ctx.current_cron_execution() is not None,
        default_target=str(ctx.get_config("default_target", targets.SERVER)),
    )


def _expand_tilde(path: str) -> str:
    """A model's ``~`` as core's file tools expand it (file_tools_paths.py:32-49)."""
    from hermes_constants import get_subprocess_home

    home = get_subprocess_home()
    if home and (path == "~" or path.startswith("~/")):
        return home if path == "~" else os.path.join(home, path[2:])
    return os.path.expanduser(path)


def _hands_failure(result: dict) -> bool:
    """A result the gateway half made up (handle.py, relay.py): a non-zero exit with a ``hands:`` line."""
    output = result.get("output") or ""
    return result.get("returncode") != 0 and any(
        line.startswith("hands:") for line in output.splitlines()
    )


def _file_tool() -> bool:
    """Whether a file tool's call runs this command (tools/file_tools.py:1410-1435), as core names it
    to tool_execution. A terminal command and execute_code keep the full deny-list."""
    return client.current_tool() in _FILE_TOOLS


def _log_delta_command(quoted_log_path: str, offset: int) -> str:
    """Core's background log read, copied from tools/process_registry_env_log.py (Hermes v0.23.0 and
    v0.23.1): a poll that is not exactly this command is not core's and follows no job."""
    return (
        f"O={offset}; "
        f"S=$({{ wc -c < {quoted_log_path}; }} 2>/dev/null | tr -dc '0-9'); "
        f"S=${{S:-0}}; "
        f'if [ "$S" -lt "$O" ]; then O=0; fi; '
        f'N=0; P=$S; while [ "$P" -gt "$O" ] && [ "$N" -lt 3 ]; do '
        f"B=$(tail -c +$P {quoted_log_path} 2>/dev/null | head -c 1 | od -An -to1 | tr -dc '0-9'); "
        f'case "$B" in 2[0-7][0-7]) P=$((P-1)); N=$((N+1));; *) break;; esac; done; '
        f'if [ "$N" -gt 0 ] || [ "$P" -eq "$S" ]; then '
        f"B=$(tail -c +$P {quoted_log_path} 2>/dev/null | head -c 1 | od -An -to1 | tr -dc '0-9'); "
        f'case "$B" in 3[0-3][0-7]) L=2;; 3[4-5][0-7]) L=3;; 3[6-7][0-7]) L=4;; *) L=1;; esac; '
        f'if [ "$L" -gt $((N+1)) ]; then S=$((P-1)); fi; fi; '
        f'echo "$S $O"; '
        f'if [ "$S" -gt "$O" ]; then '
        f"tail -c +$((O+1)) {quoted_log_path} 2>/dev/null | head -c $((S-O)); fi"
    )


def _job_file(word: str, ext: str) -> str | None:
    """The registry session a job file names, when ``word`` is that file exactly as core quotes it."""
    path = shlex.split(word)[0]
    name = re.fullmatch(rf"hermes_bg_([\w-]+)\.{ext}", posixpath.basename(path))
    return name.group(1) if name is not None and shlex.quote(path) == word else None


def _quoted(value: str) -> str:
    """A word as core's file tools quote it (file_operations.py:535-566)."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


_ATOMIC_WRITE_SUFFIX = (
    'if [ -L "$t" ]; '
    'then rt="$(readlink -f "$t" 2>/dev/null || realpath "$t" 2>/dev/null || true)"; '
    '[ -n "$rt" ] && { t="$rt"; '
    'd="$(dirname "$t")"; '
    '}; '
    'fi; '
    'mkdir -p "$d"; '
    'tmp="$(mktemp -p "$d" \'.hermes-tmp.XXXXXX\' 2>/dev/null || mktemp "$d/.hermes-tmp.$$.XXXXXX" 2>/dev/null || { tmp="$d/.hermes-tmp.$$"; '
    ': > "$tmp" && echo "$tmp"; '
    '})"; '
    '[ -n "$tmp" ] || { echo "atomic write: could not create temp file" >&2; '
    'exit 1; '
    '}; '
    'trap \'rm -f \\"$tmp\\"\' EXIT; '
    'if [ -e "$t" ]; '
    'then m="$(stat -c%a "$t" 2>/dev/null || stat -f%Lp "$t" 2>/dev/null || true)"; '
    '[ -n "$m" ] && chmod "$m" "$tmp" 2>/dev/null || true; '
    'fi; '
    'cat > "$tmp"; '
    'if [ ! -e "$t" ]; '
    'then chmod "=rw" "$tmp" 2>/dev/null || true; '
    'fi; '
    'mv -f "$tmp" "$t"; '
    'trap - EXIT'
)

_UTF16_BODY = (
    'try:\n'
    '    size = os.path.getsize(p)\n'
    '    if size > MAX:\n'
    "        print('HERMES_UTF16:NO'); sys.exit(0)\n"
    "    with open(p, 'rb') as f:\n"
    '        data = f.read()\n'
    '    sample = data[:SAMPLE]\n'
    '    enc = None\n'
    "    if sample[:2] == b'\\xfe\\xff':\n"
    "        enc = 'utf-16-be'\n"
    "    elif sample[:2] == b'\\xff\\xfe':\n"
    "        enc = 'utf-16-le'\n"
    '    else:\n'
    '        odd = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)\n'
    '        even = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)\n'
    '        if even == 0 and odd >= 2:\n'
    "            enc = 'utf-16-le'\n"
    '        elif odd == 0 and even >= 2:\n'
    "            enc = 'utf-16-be'\n"
    '    if enc is None:\n'
    "        print('HERMES_UTF16:NO'); sys.exit(0)\n"
    "    text = data.decode(enc, 'replace')\n"
    "    if text[:1] == '\\ufeff':\n"
    '        text = text[1:]\n'
    "    text = text.replace('\\r\\n', '\\n')\n"
    "    lines = text.split('\\n')\n"
    '    total = len(lines)\n'
    '    sel = lines[offset - 1: offset - 1 + limit]\n'
    "    out = {'total_lines': total, 'encoding': enc,\n"
    "           'content': '\\n'.join(sel)}\n"
    "    print('HERMES_UTF16:OK')\n"
    '    print(json.dumps(out, ensure_ascii=True))\n'
    'except Exception:\n'
    "    print('HERMES_UTF16:NO'); sys.exit(0)\n"
)

def _atomic_write_command(path: str) -> str:
    parent = os.path.dirname(path) or "."
    if os.name == "nt":
        path, parent = (device_path(value).replace("\\", "/") for value in (path, parent))
    return f"set -e; d={_quoted(parent)}; t={_quoted(path)}; " + _ATOMIC_WRITE_SUFFIX


def _utf16_program(path: str, offset: int, limit: int) -> str:
    return (
        "import sys, json, os\n"
        f"p = {json.dumps(path)}\n"
        f"offset = {offset}\nlimit = {limit}\n"
        "MAX = 10485760\nSAMPLE = 512\n" + _UTF16_BODY
    )


def _native_linter_path(path: str, windows: bool) -> str:
    if windows:
        drive = re.fullmatch(r"/(?:(?:cygdrive|mnt)/)?([a-zA-Z])(/.*)?", path)
        if drive is not None:
            path = f"{drive.group(1).upper()}:{drive.group(2) or '/'}"
        path = path.replace("\\", "/")
    return path


def _file_candidates(tool: str, args: dict, path: str, command: str) -> set[str]:
    """Complete core scripts rebuilt from approved arguments. Only the random fence token
    is recovered from command text; its alphabet cannot carry executable shell text.
    Templates are pinned by real-core comparisons on both tested Hermes versions."""
    from hermes_cli.config import load_config

    config = load_config().get("tool_output", {})
    limits = []
    for key, default in (("max_lines", 2000), ("max_line_length", 2000)):
        try:
            value = int(config.get(key, default)) if isinstance(config, dict) else default
        except (TypeError, ValueError):
            value = default
        limits.append(value if value > 0 else default)
    max_lines, max_length = limits
    offset = max(1, 1 if args.get("offset") is None else int(args["offset"]))
    limit = max(1, min(2000 if args.get("limit") is None else int(args["limit"]), max_lines))
    end = offset + limit - 1
    clamp = 4 * max_length + 1
    shell_path = device_path(path).replace("\\", "/") if os.name == "nt" else path
    arg = _quoted(shell_path)
    parent_path = os.path.dirname(path) or "."
    parent = _quoted(device_path(parent_path).replace("\\", "/") if os.name == "nt" else parent_path)
    missing = "__hermes_missing__"
    not_regular = "__hermes_not_regular__"
    expected = set()
    if tool == "vision_analyze":
        expected.add(f"head -c 52428801 < {shlex.quote(str(Path(path)))} | base64 | tr -d '\\n'")
        return expected
    if tool == "search_files":
        expected |= {
            "command -v rg 2>/dev/null",
            f"test -e {arg} && echo exists || echo not_found",
            f"test -d {parent} && echo yes || echo no",
            f"ls -1 {parent} 2>/dev/null | head -20",
        }
        expected |= {f"command -v {binary} >/dev/null 2>&1 && echo 'yes'" for binary in ("grep", "find")}
        return expected
    expected.add(
        f"if [ -f {arg} ]; then wc -c < {arg} 2>/dev/null; "
        f"elif [ -e {arg} ] || [ -L {arg} ]; then echo {not_regular}; "
        f"else echo {missing}; fi"
    )
    expected |= {
        f"head -c 1000 {arg} 2>/dev/null",
        f"ls -1 {parent} 2>/dev/null",
        f"ls -1 {parent} 2>/dev/null | head -50",
    }
    fences = set(re.findall(r"__HERMES_(?:RF|WF|RB)_[0-9a-f]{32}__", command))
    if len(fences) == 1:
        sentinel = fences.pop()
        mark = f"echo {sentinel}"
        if sentinel.startswith("__HERMES_RB_"):
            bodies = [(f"head -c 1000 {arg} 2>/dev/null | base64", ())]
            if tool in {"write_file", "patch"}:
                bodies += [(f"{binary} < {arg}", (f"wc -c < {arg}",)) for binary in ("base64", "od -An -v -tx1")]
            for body, more in bodies:
                rest = "".join(f"{mark}; {part}; " for part in more)
                expected.add(f"{{ set +x; }} 2>/dev/null; {mark}; {body}; __hb=$?; {rest}{mark}; echo $__hb")
        elif tool == "read_file" and sentinel.startswith("__HERMES_RF_"):
            expected.add(
                f"if [ -f {arg} ]; then "
                f"wc -c < {arg} 2>/dev/null; {mark}; "
                f"head -c 1000 {arg} 2>/dev/null | base64 2>/dev/null; __hs=$?; {mark}; "
                f"sed -n '{offset},{end}p' {arg} 2>/dev/null"
                f" | cut -b1-{clamp} 2>/dev/null; __hr=$?; {mark}; "
                f"wc -l < {arg} 2>/dev/null; {mark}; "
                f"tail -c 1 {arg} 2>/dev/null | wc -l; {mark}; "
                f'echo "$__hs $__hr"; '
                f"elif [ -e {arg} ] || [ -L {arg} ]; then echo {not_regular}; "
                f"else echo {missing}; fi"
            )
        elif tool in {"write_file", "patch"} and sentinel.startswith("__HERMES_WF_"):
            for body in (f"cat {arg} 2>/dev/null", f"head -c 4096 {arg} 2>/dev/null", ":"):
                expected.add(
                    f"if [ -f {arg} ]; then "
                    f"head -c 3 {arg} 2>/dev/null | base64 2>/dev/null; {mark}; "
                    f"{body}; else echo {missing}; fi"
                )
    if tool == "read_file":
        expected |= {
            f"sed -n '{offset},{end}p' {arg} | cut -b1-{clamp}",
            f"wc -l < {arg}",
            f"tail -c 1 {arg} | wc -l",
        }
        if posixpath.splitext(path)[1].lower() in _DOCUMENT_EXTENSIONS or all(args.get(key) is None for key in ("offset", "limit")):
            expected.add(f"base64 < {arg}")
        encoded = base64.b64encode(_utf16_program(path, offset, limit).encode("utf-8")).decode("ascii")
        expected |= {f"{python} -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"" for python in ("python3", "python")}
    elif tool in {"write_file", "patch"}:
        expected |= {
            _atomic_write_command(path),
            f"cat {arg} 2>/dev/null",
            f"head -c 3 {arg} 2>/dev/null",
            f"head -c 4096 {arg} 2>/dev/null",
            f"sha256sum {arg} 2>/dev/null",
        }
        expected |= {
            f"command -v {binary} >/dev/null 2>&1 && echo 'yes'"
            for binary in ("python", "node", "npx", "go", "rustfmt")
        }
        if os.name == "posix":
            expected |= {
                f"{linter} {_quoted(path)} 2>&1"
                for linter in ("node --check", "npx tsc --noEmit", "go vet", "rustfmt --check")
            }
    return expected


def _searched(args: dict, command: str, roots: set[str]) -> bool:
    """Whether a search command is one core builds from exactly the approved arguments
    (file_operations_search.py:1076-1432): pattern, target, file_glob, output_mode, context and
    order, with limit and offset, which reach the device only as their sum in head -n. Any other
    shape is refused, including hints whose pattern, glob or path differs."""
    executable = _SEARCH_EXECUTABLE.match(command)
    if executable is None or executable.group(1) not in {"rg", "grep", "find"}:
        return False
    rg = "rg" if executable.group(1) == "rg" else None
    pattern = args.get("pattern", "")
    target = args.get("target", "content")
    target = {"grep": "content", "find": "files"}.get(target, target)
    glob = args.get("file_glob")
    limit = max(1, 50 if args.get("limit") is None else args["limit"])
    offset = max(0, 0 if args.get("offset") is None else args["offset"])
    mode = args.get("output_mode", "content")
    context = args.get("context", 0)
    if not isinstance(context, int):
        return False
    order = args.get("order", "discovery")
    expected = set()
    for root in roots:
        shell_root = device_path(root).replace("\\", "/") if os.name == "nt" else root
        quoted = _quoted(shell_root)
        native_root = root
        if os.name == "nt":
            drive = re.fullmatch(r"/(?:(?:cygdrive|mnt)/)?([a-zA-Z])(/.*)?", root)
            if drive is not None:
                native_root = f"{drive.group(1).upper()}:{drive.group(2) or '/'}"
            native_root = native_root.replace("\\", "/")
        native = _quoted(native_root)
        if target == "files":
            name = pattern.split("/")[-1] if pattern.startswith("**/") or "/" in pattern else pattern
            glob_name = name if "/" in name or name.startswith("*") else f"*{name}"
            fetch = limit + offset + 1
            if rg is not None:
                sort = " --sortr=modified" if order == "modified" else ""
                expected.add(f"set -o pipefail; {rg} --files{sort} -g {_quoted(glob_name)} -- {native} | head -n {fetch}")
                folders = (
                    f"find -H {quoted} -mindepth 1 \\( -type d -name '.*' ! -path {quoted} \\) -prune -o -type d "
                    f"! -name '.*' -name {_quoted(glob_name)}"
                )
                expected |= {f"{folders} -printf '%T@ %p\\n' 2>/dev/null | sort -rn", f"{folders} 2>/dev/null"}
            operand = f"./{shell_root}" if root.startswith("-") else shell_root
            start = _quoted(operand)
            literal = _quoted(re.sub(r"([*?\[\]])", r"\\\1", operand))
            found = (
                f"set -o pipefail; find -H {start} \\( -type d -name '.*' ! -path {start} \\) -prune -o "
                f"\\( -type f -o \\( -type d ! -path {literal} \\) \\) ! -name '.*' -name {_quoted(name)}"
            )
            listed = " -printf '%T@ %p\\n' | sort -rn" if order == "modified" else " -print"
            expected.add(f"{found}{listed} | head -n {fetch}")
            continue
        fetch = limit + offset + (200 if context > 0 else 0)
        around = ["-C", str(context)] if context > 0 else []
        flag = [_OUTPUT_FLAGS[mode]] if mode in _OUTPUT_FLAGS else []
        cut = "" if mode in _OUTPUT_FLAGS else " | cut -c1-2000"
        if rg is not None:
            words = [rg, "--line-number", "--no-heading", "--with-filename"]
            words += [] if mode in _OUTPUT_FLAGS else ["--max-columns", "2000", "--max-columns-preview"]
            words += ["--multiline"] if _REGEX_NEWLINE.search(pattern) else []
            words += around + (["--glob", _quoted(glob)] if glob else []) + flag + [_quoted(pattern), native]
            expected.add(f"set -o pipefail; {' '.join(words)} | head -n {fetch}")
            glob_expr = f" --glob {_quoted(glob)}" if glob else ""
            prunes = " ".join(f"--glob {_quoted('!' + prefix + name + '/**')}" for name in _SEARCH_HINT_PRUNES for prefix in ("", "**/"))
            flags = ["-i", "--hidden --no-ignore"] + (["-F"] if re.search(r"[.\[\](){}?*+^$\\|]", pattern) else [])
            for hint_flag in flags:
                filters = f"{glob_expr} {prunes}" if hint_flag.startswith("--hidden") else glob_expr
                expected.add(f"{rg} {hint_flag} --count-matches {filters} {_quoted(pattern)} {native} 2>/dev/null | head -n 50")
        relative = shell_root.removeprefix("./")
        anchored = root.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", root) is not None
        here = quoted if anchored else '"$PWD"' + ("" if relative in {"", "."} else f"/{_quoted(relative)}")
        words = ["grep", "-rnHE", "--exclude-dir='.*'"] + around + (["--include", _quoted(glob)] if glob else [])
        expected.add(f"set -o pipefail; {' '.join(words + flag + [_quoted(pattern), here])} | head -n {fetch}{cut}")
        start = _quoted(shell_root or ".")
        words = ["find", "-H", start, f"\\( -type d -name '.*' ! -path {start} \\) -prune", "-o", "-type f"]
        words += (["-name", _quoted(glob)] if glob else []) + ["-exec", "grep", "-nHE"] + around + flag
        expected.add(f"set -o pipefail; {' '.join(words + [_quoted(pattern), '{}', '+'])} | head -n {fetch}{cut}")
    return command in expected


def _registry_command(command: str) -> tuple[str, str] | None:
    """Core's own background kill, liveness probe, exit read or log read, matched whole
    (process_registry.py:1427, 1460, 1465, 2246): ``("kill", pid)`` or ``(kind, registry session)``.
    None for any other command, however much of a job file it names."""
    kill = _BACKGROUND_KILL.fullmatch(command)
    if kill is not None:
        return "kill", kill.group(1)
    probe = _BACKGROUND_PROBE.fullmatch(command)
    if probe is not None:
        job = _job_file(probe.group(1), "pid")
        return None if job is None else ("probe", job)
    exit_read = _BACKGROUND_EXIT.fullmatch(command)
    if exit_read is not None:
        job = _job_file(exit_read.group(1), "exit")
        return None if job is None else ("exit", job)
    poll = _BACKGROUND_LOG.match(command)
    if poll is not None and command == _log_delta_command(poll.group(2), int(poll.group(1))):
        job = _job_file(poll.group(2), "log")
        return None if job is None else ("log", job)
    return None


class DeviceEnvironment(BaseEnvironment):
    """A paired device: core's spawn-per-call flow, with every bash run sent to the device as a job."""

    # stdin (write_file and patch content) travels beside the script, so the device's deny-list
    # sees only the command (base.py:268-272, 701-705, 727).
    _stdin_mode = "payload"

    def __init__(
        self,
        name: str,
        *,
        cwd: str,
        timeout: int,
        home: str | None,
        windows: bool,
        inline_limit: int,
    ):
        super().__init__(cwd=cwd, timeout=timeout)
        self.name = name
        self.home = (
            home  # the home it reported at pairing, Git Bash form; None for an unknown device
        )
        self.windows = windows
        self.inline_limit = inline_limit
        gateway_home = _gateway_home()
        self._gateway_home = (
            gateway_home if gateway_home and home and gateway_home != home else None
        )
        self._init_lock = threading.Lock()
        self._session_started = False

    def _file_path(self, path: str, mapping: dict[str, str] | None = None) -> str:
        """A file-tool path as the device names it: a gateway-home prefix, which is where core's file
        tools expanded a model's ``~``, becomes the device home (the target note gives the model that
        home), and on Windows a drive path core joined onto the base becomes its ``/c/...`` form."""
        if mapping is not None:
            return mapping.get(path, path)
        gateway = self._gateway_home
        if gateway is not None and (path == gateway or path.startswith(gateway + "/")):
            path = self.home + path[len(gateway) :]
        if self.windows:
            drive = _JOINED_DRIVE.search(path)
            # Only onto an absolute base, which every base core joins on is: the session's record,
            # a workspace, terminal.cwd or the sandbox home (file_tools_paths.py:131-144, 276-278).
            if drive is not None and path[: drive.start()].startswith("/"):
                path = device_path(drive.group(1))
        return path

    def _word(self, match: re.Match, mapping: dict[str, str] | None = None) -> str:
        """One shell word: single-quoted as core quotes paths, or bare where ``shlex.quote`` left a
        safe path unquoted (image_source.py:279)."""
        quoted, bare = match.groups()
        value = bare if quoted is None else quoted.replace("'\"'\"'", "'")
        mapped = self._file_path(value, mapping)
        return match.group(0) if mapped == value else (_quoted(mapped) if quoted is not None and mapping is not None else shlex.quote(mapped))

    def _python_snippet(self, match: re.Match, mapping: dict[str, str] | None = None) -> str:
        """Core's python snippet with its path as the device names it. Native Windows Python reads
        ``/c/Users/x`` as ``C:\\c\\Users\\x`` (and a delete then succeeds without deleting anything), so
        there the device's own Git Bash converts the path (``cygpath -m``) and Python takes it from argv."""
        python, encoded = match.groups()
        program = base64.b64decode(encoded).decode("utf-8")
        literal = _SNIPPET_PATH.search(program)
        if literal is None:
            return match.group(0)
        path = json.loads(literal.group(1))
        mapped = self._file_path(path, mapping)
        argument = ""
        if self.windows and mapped.startswith("/"):
            replacement = '__import__("sys").argv[1]'
            argument = f' "$(cygpath -m {shlex.quote(mapped)})"'
        elif mapped != path:
            replacement = json.dumps(mapped)
        else:
            return match.group(0)
        program = program[: literal.start(1)] + replacement + program[literal.end(1) :]
        encoded = base64.b64encode(program.encode("utf-8")).decode("ascii")
        return (
            f"{python} -c \"import base64; exec(base64.b64decode('{encoded}').decode())\"{argument}"
        )

    def _file_command(self, command: str, mapping: dict[str, str] | None = None) -> str:
        """A file-tool command with its paths as the device names them (:meth:`_file_path`), each
        substituted path quoted for its place. Core builds every path argument as one single-quoted
        word (file_operations.py:535-557), and its python snippets carry theirs inside base64."""
        lint = _LINTER.fullmatch(command)
        if lint is not None:
            path = shlex.split(lint.group(2))[0]
            if lint.group(2) != _quoted(path):
                return command
            mapped = self._file_path(path, mapping)
            if self.windows and mapped.startswith("/") and re.fullmatch(r"/[A-Za-z](?:/.*)?", mapped) is None:
                return f'{lint.group(1)} "$(cygpath -m {shlex.quote(mapped)})" 2>&1'
            return f"{lint.group(1)} {_quoted(_native_linter_path(mapped, self.windows))} 2>&1"
        snippet = _PYTHON_SNIPPET.fullmatch(command)
        if snippet is not None:
            return self._python_snippet(snippet, mapping)
        if _SEARCH.match(command):
            # Its quoted words are patterns and globs, and its path is the model's own, unexpanded
            # (file_tools.py:1102, file_operations_search.py:1360-1362, 1379).
            return command
        mapped = _WORD.sub(lambda word: self._word(word, mapping), command)
        write = _ATOMIC_WRITE.match(mapped)
        if write is not None and mapped != command:
            # Core took the parent from the path as it gave it (file_operations.py:587); a Windows
            # path joined onto the base has its real parent only once mapped.
            target = shlex.split(write.group(2))[0]
            parent = (_quoted if mapping is not None else shlex.quote)(posixpath.dirname(target) or ".")
            mapped = f"{mapped[: write.start(1)]}{parent}{mapped[write.end(1) :]}"
        return mapped

    def _prepare_command(self, command: str) -> tuple[str, None]:
        """The command unchanged. Core's version (base.py:807-819) adds SUDO_PASSWORD or the cached
        sudo password to stdin (terminal_tool_sudo.py:471-500) and rewrites ``open`` when the gateway
        runs macOS (terminal_tool_macos_open.py:154): both describe the gateway host, not the device,
        and the device's deny-list refuses sudo anyway."""
        return command, None

    def _run_bash(
        self,
        cmd_string: str,
        *,
        login: bool = False,
        timeout: int = 120,
        stdin_data: str | None = None,
    ) -> RemoteProcessHandle:
        return RemoteProcessHandle(
            self.name,
            cmd_string,
            login=login,
            timeout=timeout,
            inline_limit=_INLINE_LIMIT.get(),
            stdin=stdin_data,
            file_op=_FILE_OP.get(),
        )

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        """Capture the device's login shell on first use, not at construction (no network there). A
        bootstrap that got no usable shell (device offline, relay down) is retried on the next call.
        Only terminal-tool calls (``bounded_capture``, base.py:679-681) get the inline output limit:
        file reads through ``cat`` need every byte. Only file-tool calls get their paths mapped
        (:meth:`_file_command`): a terminal command or a background job runs exactly as approved."""
        with self._init_lock:
            if not self._session_started:
                self.init_session()
                self._session_started = self._snapshot_ready or self._prefer_nonlogin
        terminal = kwargs.get("bounded_capture")
        mapped = kwargs.pop("_hands_mapped", False)
        if not terminal and not mapped and (
            _file_tool() or (_registry_command(command) is None and _LAUNCH_WRAPPER.fullmatch(command) is None)
        ):
            command = self._file_command(command)
        file_op = (not terminal) and _file_tool()
        token = _INLINE_LIMIT.set(self.inline_limit if terminal else None)
        file_token = _FILE_OP.set(file_op)
        try:
            return super().execute(command, cwd, **kwargs)
        finally:
            _INLINE_LIMIT.reset(token)
            _FILE_OP.reset(file_token)

    def _quote_cwd_for_cd(self, cwd: str) -> str:
        return BaseEnvironment._quote_cwd_for_cd(device_path(cwd) if self.windows else cwd)

    def _quote_shell_path(self, path: str) -> str:
        return shlex.quote(device_path(path) if self.windows else path)

    def cleanup(self):
        """Nothing to release on the gateway; the device keeps its snapshot file in its own temp dir."""


class HandsEnvironment(BaseEnvironment):
    """``terminal.backend: hands``. ``BaseEnvironment.__init__`` is deliberately not called: it assigns
    ``cwd`` and ``env``, which here are proxies to the current target's sub-environment, and the
    snapshot state it sets up belongs to each sub-environment."""

    # Keeps core from tearing the backend down after every turn (terminal_tool_lifecycle.py:258-271,
    # agent/chat_completion_helpers.py:2334-2353); the idle reaper and AIAgent.close still clean up.
    _persistent = True

    def __init__(self, ctx, *, cwd: str, timeout: int, task_id: str = "default"):
        self._ctx = ctx
        self._requested_cwd = cwd
        self._timeout = timeout
        self._lock = threading.Lock()
        # Sub-environments are dropped only by cleanup(), so a background job's still exists after
        # any /hands use; core cleans up only an idle environment, and a running background job
        # keeps it active (terminal_tool_lifecycle.py:143-152).
        self._subs: dict[str, BaseEnvironment] = {}
        # registry session id -> the target it runs on and its pid there
        self._background: dict[str, tuple[str, int | None]] = {}
        self._background_artifacts: dict[str, tuple[str, str, str]] = {}
        # A live job's pid -> the targets it runs on: pids repeat across machines.
        self._background_pids: dict[int, set[str]] = {}
        self._store_failure_logged = False
        # The target and conversation (session id: /new keeps the session key) last given the note.
        self._noted: tuple[str, str] | None = None
        self._record_key = get_session_env("HERMES_SESSION_KEY", "") or task_id
        self._session_cwd = _SESSION_CWDS.setdefault(self._record_key, {})
        # Create the first target now so ``cwd`` is already absolute when core stamps the sandbox
        # home right after create_environment (terminal_tool_backends.py:213-233, 256).
        self._current()

    # --- target resolution -----------------------------------------------------------------
    def _store_failed(self) -> None:
        if not self._store_failure_logged:
            self._store_failure_logged = True
            logger.warning("hermes-hands: the device store is unreadable", exc_info=True)

    def _sub(self, target: str) -> tuple[str, BaseEnvironment]:
        with self._lock:
            sub = self._subs.get(target)
            if sub is None:
                sub = self._subs[target] = self._create(target)
        return target, sub

    def _resolve(self) -> tuple[str, BaseEnvironment]:
        """This call's target and its sub-environment; raises ``sqlite3.Error`` if the store is unreadable."""
        return self._sub(resolve_current_target(self._ctx))

    def _current(self) -> tuple[str, BaseEnvironment]:
        """``_resolve`` for core's attribute reads, which must never raise (file_operations.py:238-239,
        terminal_tool.py:358-362, terminal_tool_backends.py:226): with the store unreadable the server
        sub-environment answers them, while :meth:`execute` refuses to run anything."""
        try:
            return self._resolve()
        except sqlite3.Error:
            self._store_failed()
            return self._sub(targets.SERVER)

    def _create(self, target: str) -> BaseEnvironment:
        """A target starts where its last recorded terminal command ended, which outlives an
        idle-reaped object. Otherwise ``terminal.cwd`` (or a Desktop or ACP workspace) is a directory on
        the gateway host, so only the server starts there; a device starts in its paired home."""
        if target == targets.SERVER:
            requested = None if self._requested_cwd == "~" else self._requested_cwd
            persistent = os.getenv("TERMINAL_LOCAL_PERSISTENT", "true").strip().lower() in {
                "true",
                "1",
                "yes",
            }
            # Core drops a terminal.cwd under /home, /Users or a drive for a container backend
            # (terminal_tool.py:805-809); for the server it is this host's, as on the local backend,
            # and the file tools anchor on it (file_tools_paths.py:106-112, 144).
            cwd = (
                self._session_cwd.get(target)
                or requested
                or _configured_cwd()
                or os.getenv("MESSAGING_CWD")
                or os.getcwd()
            )
            # The relay seed is blank in every command: core strips the provider's strip_env_keys
            # from background and helper processes (local.py:333-337) but not from the terminal's
            # own spawn env, which takes this env last (local.py:776-787, 1136).
            return LocalEnvironment(
                cwd=cwd,
                timeout=self._timeout,
                env={"HANDS_RELAY_SEED": ""},
                persistent=persistent,
            )
        device = store.get_device(target)
        home = device_path(device["home"]) if device is not None else None
        return DeviceEnvironment(
            target,
            cwd=self._session_cwd.get(target) or home or "~",
            timeout=self._timeout,
            home=home,
            windows=device is not None and device["os"].lower().startswith("windows"),
            inline_limit=int(self._ctx.get_config("inline_output_limit_bytes", 1048576)),
        )

    def _background_owner(self, command: str) -> tuple[str, str, str] | None:
        """The target one of core's own registry commands belongs to, whatever the session chose
        since, with what :func:`_registry_command` read from it. Core's kill names only the pid
        (process_registry.py:2245-2246): a pid launched on two targets is refused, which core reports
        as a failed kill and keeps the job tracked (:2156-2220). A registry command for a job that
        has ended, or that this object never launched, runs nowhere: core records a poll that raises
        as a lost job, which keeps a kill's own result (:1471-1475, 642-650)."""
        registry = _registry_command(command)
        if registry is None:
            return None
        kind, value = registry
        with self._lock:
            if kind == "kill":
                owners = sorted(self._background_pids.get(int(value), ()))
            else:
                known = self._background.get(value)
                owners = [] if known is None else [known[0]]
        if len(owners) > 1:
            raise RuntimeError(messages.ambiguous_pid(int(value), owners))
        if not owners:
            raise RuntimeError(messages.BACKGROUND_JOB_ENDED)
        return owners[0], kind, value

    def _record_background(self, session_id: str, target: str, result: dict, artifacts: tuple[str, str, str]) -> None:
        """A launch: remember where it runs and its pid, parsed as core parses it
        (process_registry.py:1291)."""
        lines = map(str.strip, (result.get("output") or "").splitlines())
        pid = next((int(line) for line in lines if line.isdigit()), None)
        with self._lock:
            self._background[session_id] = (target, pid)
            self._background_artifacts[session_id] = artifacts
            if pid is not None:
                self._background_pids.setdefault(pid, set()).add(target)

    def _job_ended(self, session_ids: list[str]) -> None:
        """Ended jobs lose their route, and their pids stop counting, so a pid shared with one of them
        routes again."""
        with self._lock:
            for session_id in session_ids:
                target, pid = self._background.pop(session_id, (None, None))
                self._background_artifacts.pop(session_id, None)
                owners = self._background_pids.get(pid)
                if owners is not None:
                    owners.discard(target)
                    if not owners:
                        del self._background_pids[pid]

    def _routed(
        self, owner: str, kind: str, value: str, command: str, cwd: str, kwargs: dict
    ) -> dict:
        """A registry poll or kill on the target that runs the job (process_registry.py:1418-1470,
        2245-2246). A result the gateway half made up is never read as the job's state: core takes
        anything but "0" from the liveness probe as an exit and writes "killed" whatever the kill
        printed. A device that cannot answer for now reads as alive; one that is gone for good, or a
        kill that never reached the device, raises, which core records as a lost job or a failed kill
        (:1471-1475, 2219-2220)."""
        sub = self._sub(owner)[1]
        with self._lock:
            artifacts = self._background_artifacts.get(value)
        expected = set()
        if kind == "kill":
            expected.add(f"kill {value} 2>/dev/null")
        elif artifacts is not None:
            log, exited, pid = artifacts
            if kind == "log":
                poll = _BACKGROUND_LOG.match(command)
                if poll is not None:
                    expected.add(_log_delta_command(log, int(poll.group(1))))
            elif kind == "exit":
                expected.add(f"cat {exited} 2>/dev/null")
            elif kind == "probe":
                expected.add(f'kill -0 "$(cat {pid} 2>/dev/null)" 2>/dev/null; echo $?')
        if (
            command not in expected or cwd != ""
            or set(kwargs) - {"timeout", "stdin_data", "rewrite_compound_background", "bounded_capture", "yield_handler"}
            or kwargs.get("stdin_data") is not None or kwargs.get("yield_handler") is not None
            or kwargs.get("bounded_capture", False) is not False
            or kwargs.get("rewrite_compound_background", True) is not True
            or (kwargs.get("timeout") or sub.timeout) != (10 if kind == "log" else 5)
            or (isinstance(sub, DeviceEnvironment) and sub.env)
        ):
            return {"output": messages.WITNESS_CALL_CHANGED, "returncode": UNREACHABLE}
        result = sub.execute(command, cwd, **kwargs)
        output = result.get("output") or ""
        lines = output.strip().splitlines()
        if kind == "kill":
            if _hands_failure(result):
                raise RuntimeError(lines[-1])
            with self._lock:
                killed = [
                    job for job, run in self._background.items() if run == (owner, int(value))
                ]
            self._job_ended(killed)
            return result
        if kind != "probe":
            if kind == "exit":
                self._job_ended([value])
            return result
        if result.get("returncode") == 0 and lines and lines[-1].strip().lstrip("-").isdigit():
            return result
        if any(text in output for text in self._gone(owner)):
            self._job_ended([value])  # core records the job as lost
            raise RuntimeError(lines[-1])
        return {"output": "0", "returncode": 0}

    @staticmethod
    def _gone(target: str) -> tuple[str, ...]:
        """The refusals that do not pass: the device was revoked, or this gateway has no relay seed."""
        return (messages.unknown_device(target), messages.revoked(target), messages.NOT_SET_UP)

    def _note(self, target: str) -> str:
        if target == targets.SERVER:
            return messages.TARGET_NOTE_SERVER
        device = store.get_device(target)
        if device is None:
            return messages.target_note(target, None, None)
        return messages.target_note(target, device["os"], device_path(device["home"]))

    def _command_cwd(self, target: str, sub: BaseEnvironment, cwd: str) -> tuple[str, bool]:
        """Where a terminal command or a background launch runs ("" keeps the target's own cwd), and
        whether core records where it ends. Core passes ``workdir=``, which it never records, else the
        session's recorded cwd, else the configured default (terminal_tool.py:1014-1061,
        terminal_tool_background.py:173-176, terminal_tool_result.py:222-225), and tells the
        environment nothing about which (:1373-1377). Its record outlives /new under the session key,
        so a cwd that is another target's last one and not this target's is that target's record:
        this target keeps its own. Core passes ``terminal.cwd`` only while there is no record, a
        gateway directory unless it is under a device's home, so a device that has none keeps its
        own there too. Anything else runs where it says."""
        known = self._session_cwd.get(target)
        if cwd == "~":
            # Core drops a /home or /Users record outside the sandbox home (terminal_tool.py:
            # 1041-1059); the session's cwd on this target is still where it was.
            return known or "", True
        if cwd == known:
            return cwd, True
        if any(seen == cwd for other, seen in self._session_cwd.items() if other != target):
            return known or "", True
        if (
            known is None
            and target != targets.SERVER
            and cwd == _configured_cwd()
            and not self._in_home(sub, cwd)
        ):
            return "", True
        return cwd, False  # workdir=

    @staticmethod
    def _in_home(sub: BaseEnvironment, cwd: str) -> bool:
        home = getattr(sub, "home", None)
        return bool(home) and (cwd == home or cwd.startswith(home.rstrip("/") + "/"))

    @staticmethod
    def _destination(sub: DeviceEnvironment, raw: str) -> str:
        if raw == "~" or raw.startswith("~/"):
            return posixpath.normpath((sub.home or "~") + raw[1:])
        if _DRIVE_PATH.match(raw) and not sub.windows:
            return raw
        path = device_path(raw) if sub.windows else raw
        return posixpath.normpath(posixpath.join(sub.cwd, path))

    def _approved_command(self, shown: tuple[str, dict], sub: BaseEnvironment, command: str) -> str:
        tool, args = shown
        if not isinstance(sub, DeviceEnvironment) or tool == "terminal":
            return command
        raw = args.get(witness._DESTINATION_KEYS.get(tool, ""))
        if not isinstance(raw, str):
            return command
        destination = self._destination(sub, raw)
        sources = {raw, _expand_tilde(raw)}
        absolute = absolute_file_path(raw)
        if absolute is not None:
            sources.add(absolute)
        if raw == "~" or raw.startswith("~/"):
            sources.add((sub.home or "~") + raw[1:])
        if not posixpath.isabs(raw) and not raw.startswith("~"):
            configured = _configured_cwd()
            if configured is not None:
                sources.add(posixpath.normpath(posixpath.join(configured, raw)))
        if sub.windows and _DRIVE_PATH.match(raw):
            sources.add(posixpath.join(sub.cwd, raw))
        if os.name == "nt":
            sources |= {source.replace("\\", "/") for source in sources}
        sources |= {posixpath.normpath(source) for source in sources if posixpath.isabs(source)}
        mapping = {posixpath.dirname(source): posixpath.dirname(destination) for source in sources if posixpath.isabs(source)}
        mapping.update({source: destination for source in sources})
        if _LINTER.fullmatch(command) is not None:
            mapping.update({_native_linter_path(source, os.name == "nt"): destination for source in sources})
        return sub._file_command(command, mapping)

    def _execution_inputs_changed(self, shown: tuple[str, dict], sub: DeviceEnvironment, command: str, kwargs: dict) -> bool:
        tool, args = shown
        background = tool == "terminal" and args.get("background") is True
        terminal = tool == "terminal" and not background
        allowed = {"timeout", "stdin_data", "rewrite_compound_background", "bounded_capture", "yield_handler"}
        if set(kwargs) - allowed or sub.env:
            return True
        if kwargs.get("bounded_capture", False) is not terminal:
            return True
        if kwargs.get("rewrite_compound_background", True) is not (not background):
            return True
        if kwargs.get("yield_handler") is not None:
            return True
        timeout = sub.timeout
        if tool == "terminal":
            timeout = 10 if background else args.get("timeout") or self._timeout
        elif tool == "search_files" and _SEARCH.match(command):
            timeout = 60 if command.startswith("set -o pipefail; ") else 30
        elif tool in {"write_file", "patch"} and re.match(r"(?:node --check|npx tsc|go vet|rustfmt --check) ", command):
            timeout = 30
        if (kwargs.get("timeout") or sub.timeout) != timeout:
            return True
        return kwargs.get("stdin_data") is not None and not (
            tool in {"write_file", "patch"} and _ATOMIC_WRITE.match(command)
        )

    def _unshown(
        self, shown: tuple[str, dict], target: str, sub: BaseEnvironment, command: str, cwd: str, kwargs: dict
    ) -> bool:
        """Whether a command of a witness call is not what its approval card showed. A terminal
        command must be the approved one, in the approved workdir or none. A write or patch names
        the approved absolute path, which core only normalizes (file_tools_paths.py:157-163); a
        read, search or vision call must match a complete rebuilt core command with its
        approved path and parameters. Mapping happens before this check and the same final
        string executes. Core's random fence tokens are data, never executable text."""
        tool, args = shown
        terminal = bool(kwargs.get("bounded_capture"))
        if not isinstance(sub, DeviceEnvironment):
            return True
        if self._execution_inputs_changed(shown, sub, command, kwargs):
            return True
        if tool == "terminal":
            approved = args.get("command")
            if args.get("background") is True:
                launch = _LAUNCH_WRAPPER.fullmatch(command)
                if terminal or launch is None:
                    return True
                folder, embedded, log, exited, pid = launch.groups()
                job = _job_file(pid, "pid")
                temp = sub.get_temp_dir().rstrip("/") or "/"
                if (
                    job is None or re.fullmatch(r"proc_[0-9a-f]{12}", job) is None
                    or folder != shlex.quote(temp) or embedded != shlex.quote(approved)
                    or (log, exited, pid) != tuple(shlex.quote(f"{temp}/hermes_bg_{job}.{ext}") for ext in ("log", "exit", "pid"))
                ):
                    return True
            elif not terminal or command != approved:
                return True
            if "workdir" in args:
                return cwd != args["workdir"]
            return not self._command_cwd(target, sub, cwd)[1]
        raw = args.get(witness._DESTINATION_KEYS.get(tool, ""))
        if terminal or not isinstance(raw, str) or (cwd or sub.cwd) != sub.cwd:
            return True
        if tool == "search_files" and args.get("target") in {"files", "find"} and args.get("order", "discovery") not in {"discovery", "modified"}:
            return True
        if (raw == "~" or raw.startswith("~/")) and command == "echo $HOME":
            return False
        if tool in {"write_file", "patch"} and (
            absolute_file_path(raw) is None or (_DRIVE_PATH.match(raw) and not sub.windows)
        ):
            return True
        paths = {self._destination(sub, raw)}
        if tool == "search_files":
            paths.add(raw)
            if raw == "~" or raw.startswith("~/"):
                paths.add((sub.home or "~") + raw[1:])
        if tool == "patch" and args.get("mode", "replace") != "replace":
            return True
        if tool == "search_files" and _SEARCH.match(command) is not None:
            roots = {(sub.home or "~") + raw[1:]} if raw == "~" or raw.startswith("~/") else {raw}
            return not _searched(args, command, roots)
        candidates = {
            sub._file_command(candidate, {})
            for path in paths
            for candidate in _file_candidates(tool, args, path, command)
        }
        return command not in candidates

    @staticmethod
    def _device_bytes(sub: BaseEnvironment, command: str, cwd: str) -> bytes | None:
        """The bytes of the file an atomic write replaces, read again through this call's own job."""
        read = sub.execute(f"base64 < {_ATOMIC_WRITE.match(command).group(2)}", cwd, _hands_mapped=True)
        try:
            raw = base64.b64decode("".join((read.get("output") or "").split()), validate=True)
        except ValueError:
            return None
        return raw if read.get("returncode") == 0 else None

    @staticmethod
    def _patched(sub: BaseEnvironment, command: str, cwd: str, args: dict, stdin) -> bool:
        """Whether a patch's write is exactly what core writes when the approved old_string is found
        once (or every occurrence with replace_all) in the file as it is now.
        Core's matcher also accepts fuzzy matches (fuzzy_match.py), so
        the file is read again. Core matches on the file without its BOM, writes every line end as
        the file's own, and puts the BOM back (file_operations.py:1547-1552, 1625-1660); in a file with
        no line end the text is compared byte for byte."""
        old, new = args.get("old_string"), args.get("new_string")
        raw = HandsEnvironment._device_bytes(sub, command, cwd)
        if not (isinstance(old, str) and isinstance(new, str) and isinstance(stdin, str)) or raw is None:
            return False
        current = raw.decode("utf-8", "surrogateescape").removeprefix("\ufeff")
        ending = "\r\n" if "\r\n" in current[:4096] else "\n" if "\n" in current[:4096] else None
        if ending is not None:
            current, old, new = (text.replace("\r\n", "\n").replace("\r", "\n") for text in (current, old, new))
        count = current.count(old)
        if not old or count == 0 or (count != 1 and args.get("replace_all") is not True):
            return False
        expected = current.replace(old, new)
        if ending == "\r\n":
            expected = expected.replace("\n", "\r\n")
        if raw.startswith(b"\xef\xbb\xbf") and not expected.startswith("\ufeff"):
            expected = "\ufeff" + expected
        return stdin == expected

    @staticmethod
    def _written(sub: BaseEnvironment, command: str, cwd: str, args: dict, stdin) -> bool:
        """Whether a write delivers exactly the approved content. Core changes it only for a file
        that exists: every line end to CRLF when the file has CRLF, and a BOM in front when the file
        starts with one (file_operations.py:1547-1552), both read again from the device here. Any
        other difference, or a BOM or CR the file does not have, is refused."""
        content = args.get("content")
        if not (isinstance(content, str) and isinstance(stdin, str)):
            return False
        if stdin == content:
            return True
        raw = HandsEnvironment._device_bytes(sub, command, cwd)
        if raw is None:
            return False
        if "\r\n" in raw.decode("utf-8", "surrogateescape")[:4096]:
            content = content.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        if raw.startswith(b"\xef\xbb\xbf") and not content.startswith("\ufeff"):
            content = "\ufeff" + content
        return stdin == content

    # --- delegated surface -----------------------------------------------------------------
    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        # Only the foreground terminal tool sets bounded_capture (base.py:679-681): its command runs on
        # this conversation's target exactly as approved, and only it moves the session's cwd record.
        terminal = bool(kwargs.get("bounded_capture"))
        # A file tool's command can name a job file, but only the registry polls and kills a job.
        registry = not terminal and not _file_tool()
        launch = _LAUNCH_WRAPPER.fullmatch(command) if registry else None
        owner = self._background_owner(command) if registry and launch is None else None
        if owner is not None:
            # The process registry polls and kills through this object (process_registry.py:1279,
            # 1418-1466, 2245-2246); its job lives on the sub-environment that launched it.
            return self._routed(*owner, command, cwd, kwargs)
        note = None
        try:
            # Every store read happens before the command runs: an error after it would make the
            # terminal tool retry, i.e. run the command again (terminal_tool.py:1363-1390).
            target, sub = self._resolve()
            if not terminal and not client.call_running() and witness._witness_device(self._ctx):
                # Outside every call it is core's oversized-result spill (tool_result_storage.py:
                # 350-385), which no one approved; core keeps the result inline (:434-437).
                return {"output": messages.WITNESS_RESULT_KEPT, "returncode": 1}
            # The file tools parse their raw output, so the note never goes there.
            noted = (target, get_session_env("HERMES_SESSION_ID", ""))
            if terminal and noted != self._noted:
                note = self._note(target)
        except sqlite3.Error:
            self._store_failed()
            return {"output": messages.STORE_DOWN, "returncode": UNREACHABLE}
        # Record paged/whole reads, pipefail searches and the mandatory search path check.
        # Core aborts at that check; optional hints and lookups must not replace its result.
        primary = (
            client.current_tool() == "read_file"
            and bool(_SED_PAGE.search(command) or _PYTHON_SNIPPET.fullmatch(command) or _WHOLE_READ.fullmatch(command))
        ) or (
            client.current_tool() == "search_files"
            and ((command.startswith("set -o pipefail; ") and _SEARCH.match(command) is not None) or re.fullmatch(
                rf"test -e ({_SHELL_WORD}) && echo exists \|\| echo not_found", command
            ) is not None)
        )
        if not terminal and _file_tool():
            search = _SEARCH.match(command)
            if isinstance(sub, DeviceEnvironment) and search is not None:
                path = device_path(shlex.split(search.group("executable"))[0])
                if posixpath.isabs(path) and re.search(r"/rg(?:\.exe)?$", path, re.I):
                    if primary:
                        client.record_refusal(messages.DEVICE_RG_UNAVAILABLE)
                    raise client.HandsError(messages.DEVICE_RG_UNAVAILABLE)
        try:
            shown = client.shown_call(lambda shown: not self._unshown(
                shown, target, sub, self._approved_command(shown, sub, command), cwd, kwargs
            ))
            if shown is not None:
                command = self._approved_command(shown, sub, command)
            elif isinstance(sub, DeviceEnvironment) and not terminal and launch is None:
                command = sub._file_command(command)
        except ValueError:
            if primary:
                client.record_refusal(messages.WITNESS_CALL_CHANGED)
            return {"output": messages.WITNESS_CALL_CHANGED, "returncode": UNREACHABLE}
        except client.HandsError as exc:
            if primary:
                client.record_refusal(str(exc))
            return {"output": str(exc), "returncode": UNREACHABLE}
        if shown is not None and self._unshown(shown, target, sub, command, cwd, kwargs):
            if primary:
                client.record_refusal(messages.WITNESS_CALL_CHANGED)
            return {"output": messages.WITNESS_CALL_CHANGED, "returncode": UNREACHABLE}
        if isinstance(sub, DeviceEnvironment) and command == "command -v rg 2>/dev/null":
            return {"output": "", "returncode": 1}
        if (
            shown is not None
            and shown[0] == "patch"
            and _ATOMIC_WRITE.match(command)
            and not self._patched(sub, command, cwd, shown[1], kwargs.get("stdin_data"))
        ):
            message = messages.WITNESS_PATCH_ALL_NOT_EXACT if shown[1].get("replace_all") is True else messages.WITNESS_PATCH_NOT_EXACT
            return {"output": message, "returncode": UNREACHABLE}
        if (
            shown is not None
            and shown[0] == "write_file"
            and _ATOMIC_WRITE.match(command)
            and not self._written(sub, command, cwd, shown[1], kwargs.get("stdin_data"))
        ):
            return {"output": messages.WITNESS_CALL_CHANGED, "returncode": UNREACHABLE}
        records = terminal
        if shown is not None and shown[0] == "terminal" and "workdir" in shown[1]:
            # The approved workdir, which _unshown matched, runs as given: another target's record
            # of the same folder must not move it. Core never records a workdir= run.
            records = False
        elif terminal or launch is not None:
            cwd, records = self._command_cwd(target, sub, cwd)
            records = records and terminal
        if note is not None:
            self._noted = noted
        targets.mark_ran(noted[1])
        before = sub.cwd
        if isinstance(sub, DeviceEnvironment):
            kwargs["_hands_mapped"] = True
        result = sub.execute(command, cwd, **kwargs)
        if result.get("cwd_observed"):
            if records:
                self._session_cwd[target] = result["cwd"]
            elif sub.cwd == result.get("cwd"):
                # Core records the cwd only after a terminal command without workdir=; execute_code
                # (cwd "/", code_execution_tool.py:674, code_execution_rpc.py:210-227), a file tool
                # or a workdir must not move where this target's next terminal command starts.
                sub.cwd = before
        if launch is not None:
            launched = _BACKGROUND_FILE.search(launch.group(5))
            if launched is not None:
                self._record_background(launched.group(1), target, result, (launch.group(3), launch.group(4), launch.group(5)))
        if note is not None:
            result["output"] = f"{note}\n{result.get('output', '')}"
        return result

    def _media_source(self) -> BaseEnvironment | None:
        """The target a MEDIA: line in the model's reply is fetched from (gateway/media_fetch.py:
        99-108). The fetch passes no tool call and so no approval, so an active witness device gives
        none: core skips a path that resolves to None and delivers nothing, after its own local
        check has already failed (gateway/platforms/base.py:1111-1114)."""
        sub = self._resolve()[1]
        if witness._witness_device(self._ctx) is not None:
            logger.warning(messages.WITNESS_MEDIA_BLOCKED)
            return None
        return sub

    def fetch_file(self, remote_path, local_dest, *, max_bytes: int) -> None:
        source = self._media_source()
        if source is None:
            raise RuntimeError(messages.WITNESS_MEDIA_BLOCKED)
        source.fetch_file(remote_path, local_dest, max_bytes=max_bytes)

    def fetch_realpath(self, remote_path: str) -> str | None:
        source = self._media_source()
        return None if source is None else source.fetch_realpath(remote_path)

    def get_temp_dir(self) -> str:
        return self._current()[1].get_temp_dir()

    @property
    def cwd(self) -> str:
        return self._current()[1].cwd

    @cwd.setter
    def cwd(self, value: str) -> None:
        """A workspace override (terminal_tool.py:350-362), which core also records as the session's
        cwd, names a gateway directory: the server starts there from now, and a device, to which
        it is then the server's cwd (:meth:`_command_cwd`), keeps its own."""
        target, sub = self._current()
        self._session_cwd[targets.SERVER] = value
        if target == targets.SERVER:
            sub.cwd = value

    @property
    def env(self) -> dict:
        return self._current()[1].env

    @property
    def is_local(self) -> bool:
        try:
            return self._resolve()[1].is_local
        except sqlite3.Error:
            self._store_failed()
            return False

    @property
    def uses_host_filesystem(self) -> bool:
        """False while the store is unreadable, so the file tools go through :meth:`execute`, which
        refuses, instead of reading the gateway's own files (file_operations.py:912-922)."""
        try:
            return self._resolve()[1].uses_host_filesystem
        except sqlite3.Error:
            self._store_failed()
            return False

    @property
    def _hermes_sandbox_home(self) -> str | None:
        """The current target's terminal cwd, which core reads to anchor relative file-tool paths when
        it finds no cwd record under the tool's task id, as in the gateway (file_tools_paths.py:
        131-144, 276-301), and to keep recorded cwds (terminal_tool.py:1041-1047). Reads pass a
        relative path to the shell, which runs in this same cwd (file_tools.py:685), so writes,
        patches, reads and searches all land where the terminal is, as on the local backend."""
        target, sub = self._current()
        cwd = self._session_cwd.get(target) or sub.cwd
        if not posixpath.isabs(device_path(cwd)):
            return None  # "~": a device never paired
        # Core refuses "/" as a home and would anchor on the gateway's own cwd instead
        # (terminal_tool_config.py:188-192, file_tools_paths.py:276-278); "/." names the same folder.
        return "/." if cwd == "/" else cwd

    @_hermes_sandbox_home.setter
    def _hermes_sandbox_home(self, value: str) -> None:
        """Ignored: core stamps the first target's home once (terminal_tool_backends.py:213-233), and
        the home has to follow /hands use."""

    def cleanup(self):
        with self._lock:
            subs = list(self._subs.values())
            self._subs.clear()
        for sub in subs:
            sub.cleanup()


class ProbeEnvironment(BaseEnvironment):
    """What core's prompt-build backend probe gets (agent/prompt_builder.py:836-877). Run for real, it
    would start the session's device before the model has done anything, and its answer is cached
    for every session in the process (:880-895). It runs nothing, so core describes the backend with
    ``env_description`` instead."""

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        return {"output": "", "returncode": UNREACHABLE}

    def cleanup(self):
        """Nothing to release."""
