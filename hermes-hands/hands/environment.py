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
import sys
import sqlite3
import threading
import weakref

from gateway.session_context import get_session_env
from tools.environments.base import BaseEnvironment, FileFetchError
from tools.environments.local import LocalEnvironment
from tools.process_registry_env_log import log_delta_command

from . import messages, store, targets, witness
from .handle import RemoteProcessHandle
from .relay import UNREACHABLE

logger = logging.getLogger(__name__)

_DRIVE_PATH = re.compile(r"^([A-Za-z]):[\\/]*(.*)$")
# Core's background launcher and poller name their files after the registry session
# (process_registry.py:1271-1300, 1418-1466) and kill by pid (:2245-2246).
_BACKGROUND_FILE = re.compile(r"hermes_bg_([\w-]+)\.(?:log|pid|exit)\b")
_BACKGROUND_KILL = re.compile(r"kill (\d+) 2>/dev/null")
# The end of the launcher itself, which prints the pid it wrote (process_registry.py:1282-1288).
_BACKGROUND_LAUNCH = re.compile(r"\) & echo \$! > (.+) && cat \1\Z")
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
_WORD = re.compile(r"'((?:[^']|'\"'\"')*)'|(?<![^\s<>|;&(])([\w@%+=:,./-]+)(?=[\s<>|;&)]|\Z)")
# The start of core's atomic write (file_operations.py:586-606): its parent and target.
_ATOMIC_WRITE = re.compile(rf"set -e; d=({_SHELL_WORD}); t=({_SHELL_WORD}); ")
# A search_files command (file_operations_search.py:688-693, 1221, 1328): rg, grep or find first.
# The executable is bare, or single-quoted when its path has a space (file_operations_search.py:695-702).
_SEARCH = re.compile(
    r"(?:set -o pipefail; )?(?:cd \S.*? && )?"
    r"(?:'(?:[^']|'\"'\"')*/(?:rg|rg\.exe)'|(?:[^'\s]*/)?(?:rg|rg\.exe|grep|find)) "
)
# A Windows path core joined onto the base, which it does to anything not POSIX-absolute for a
# container backend (file_tools_paths.py:157-163): ``<home>/C:\Users\x`` or ``<home>/C:/Users/x``.
_JOINED_DRIVE = re.compile(r"/([A-Za-z]:(?:[\\/].*)?)\Z", re.S)
# Core's python snippets (file_operations.py:722-737) and the path they act on (:748, :1317).
_PYTHON_SNIPPET = re.compile(
    r"(python3?) -c \"import base64; exec\(base64\.b64decode\('([A-Za-z0-9+/=]*)'\)\.decode\(\)\)\""
)
_SNIPPET_PATH = re.compile(r"^p = (?:pathlib\.Path\()?(\"(?:[^\"\\]|\\.)*\")", re.M)
# Set by DeviceEnvironment.execute for one call and read in _run_bash, which core runs on its wait
# worker in a copy of the caller's context (agent/deadline.py:340-361).
# Core's container key -> target -> where the target's last terminal command that core records
# ended. Kept per process, not per object: core's own cwd record outlives an idle-reaped
# environment (terminal_tool.py:255-283), and this has to as well.
_SESSION_CWDS: dict[str, dict[str, str]] = {}
# The live environments, for target_changed.
_LIVE: weakref.WeakSet[HandsEnvironment] = weakref.WeakSet()
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


def _gateway_home() -> str | None:
    """The home core's file tools put in place of a model's ``~`` (file_tools_paths.py:32-49, 147-154),
    when it is a POSIX path; a Windows gateway's home could never appear in a device command."""
    from hermes_constants import get_subprocess_home

    home = (get_subprocess_home() or os.path.expanduser("~")).rstrip("/")
    return home if home and posixpath.isabs(home) else None


def resolve_current_target(ctx) -> str:
    return targets.resolve_target(
        session_key=get_session_env("HERMES_SESSION_KEY", ""),
        in_cron=ctx.current_cron_execution() is not None,
        default_target=str(ctx.get_config("default_target", targets.SERVER)),
    )


def _hands_failure(result: dict) -> bool:
    """A result the gateway half made up (handle.py, relay.py): a non-zero exit with a ``hands:`` line."""
    output = result.get("output") or ""
    return result.get("returncode") != 0 and any(
        line.startswith("hands:") for line in output.splitlines()
    )


def _called_from(module: str) -> bool:
    """Whether core's ``module`` made this call. File tools do not name the call (file_operations.py:
    229-239), nor does the oversized-result spill (tool_result_storage.py:225-246, 323-345). A
    terminal command and execute_code keep the full deny-list."""
    frame = sys._getframe()
    while frame is not None:
        if str(frame.f_globals.get("__name__", "")).startswith(module):
            return True
        frame = frame.f_back
    return False


def _job_file(word: str, ext: str) -> str | None:
    """The registry session a job file names, when ``word`` is that file exactly as core quotes it."""
    path = shlex.split(word)[0]
    name = re.fullmatch(rf"hermes_bg_([\w-]+)\.{ext}", posixpath.basename(path))
    return name.group(1) if name is not None and shlex.quote(path) == word else None


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
    if poll is not None and command == log_delta_command(poll.group(2), int(poll.group(1))):
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

    def _file_path(self, path: str) -> str:
        """A file-tool path as the device names it: a gateway-home prefix, which is where core's file
        tools expanded a model's ``~``, becomes the device home (the target note gives the model that
        home), and on Windows a drive path core joined onto the base becomes its ``/c/...`` form."""
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

    def _word(self, match: re.Match) -> str:
        """One shell word: single-quoted as core quotes paths, or bare where ``shlex.quote`` left a
        safe path unquoted (image_source.py:279)."""
        quoted, bare = match.groups()
        value = bare if quoted is None else quoted.replace("'\"'\"'", "'")
        mapped = self._file_path(value)
        return match.group(0) if mapped == value else shlex.quote(mapped)

    def _python_snippet(self, match: re.Match) -> str:
        """Core's python snippet with its path as the device names it. Native Windows Python reads
        ``/c/Users/x`` as ``C:\\c\\Users\\x`` (and a delete then succeeds without deleting anything), so
        there the device's own Git Bash converts the path (``cygpath -m``) and Python takes it from argv."""
        python, encoded = match.groups()
        program = base64.b64decode(encoded).decode("utf-8")
        literal = _SNIPPET_PATH.search(program)
        if literal is None:
            return match.group(0)
        path = json.loads(literal.group(1))
        mapped = self._file_path(path)
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

    def _file_command(self, command: str) -> str:
        """A file-tool command with its paths as the device names them (:meth:`_file_path`), each
        substituted path quoted for its place. Core builds every path argument as one single-quoted
        word (file_operations.py:535-557), and its python snippets carry theirs inside base64."""
        snippet = _PYTHON_SNIPPET.fullmatch(command)
        if snippet is not None:
            return self._python_snippet(snippet)
        if _SEARCH.match(command):
            # Its quoted words are patterns and globs, and its path is the model's own, unexpanded
            # (file_tools.py:1102, file_operations_search.py:1360-1362, 1379).
            return command
        mapped = _WORD.sub(self._word, command)
        write = _ATOMIC_WRITE.match(mapped)
        if write is not None and mapped != command:
            # Core took the parent from the path as it gave it (file_operations.py:587); a Windows
            # path joined onto the base has its real parent only once mapped.
            target = shlex.split(write.group(2))[0]
            parent = shlex.quote(posixpath.dirname(target) or ".")
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
        if not terminal and _BACKGROUND_FILE.search(command) is None:
            command = self._file_command(command)
        file_op = (not terminal) and _called_from("tools.file_operations")
        token = _INLINE_LIMIT.set(self.inline_limit if terminal else None)
        file_token = _FILE_OP.set(file_op)
        try:
            return super().execute(command, cwd, **kwargs)
        finally:
            _INLINE_LIMIT.reset(token)
            _FILE_OP.reset(file_token)

    @staticmethod
    def _quote_cwd_for_cd(cwd: str) -> str:
        return BaseEnvironment._quote_cwd_for_cd(device_path(cwd))

    def _quote_shell_path(self, path: str) -> str:
        return shlex.quote(device_path(path))

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
        self._task_id = task_id
        self._lock = threading.Lock()
        # Sub-environments are dropped only by cleanup(), so a background job's still exists after
        # any /hands use; core cleans up only an idle environment, and a running background job
        # keeps it active (terminal_tool_lifecycle.py:143-152).
        self._subs: dict[str, BaseEnvironment] = {}
        # registry session id -> the target it runs on and its pid there
        self._background: dict[str, tuple[str, int | None]] = {}
        # A live job's pid -> the targets it runs on: pids repeat across machines.
        self._background_pids: dict[int, set[str]] = {}
        self._store_failure_logged = False
        # The target and conversation (session id: /new keeps the session key) last given the note.
        self._noted: tuple[str, str] | None = None
        # The target whose terminal command wrote core's cwd record for this session. It comes from
        # the store: this object may be new since then (idle reaper, gateway restart).
        session_key = get_session_env("HERMES_SESSION_KEY", "")
        try:
            self._record_owner = store.get_last_run(session_key) if session_key else None
        except sqlite3.Error:
            self._store_failed()
            self._record_owner = None
        self._files_target: str | None = None
        self._session_key = session_key
        self._replaced: str | None = None
        self._session_cwd = _SESSION_CWDS.setdefault(task_id, {})
        _LIVE.add(self)
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
        target, sub = self._sub(resolve_current_target(self._ctx))
        if target != self._files_target:
            if self._files_target is not None:
                self._switched(target, sub)
            self._files_target = target
        return target, sub

    def _forget_file_ops(self) -> None:
        """Core keeps one ShellFileOperations per environment, caching which executables exist and
        where rg is for whichever machine answered first (file_operations.py:225-227,
        file_operations_search.py:518-590), and a 60 s not-found cache per task (file_tools_read_
        tracking.py:118-140). Both describe another machine once the target changes; core's public
        calls drop them (file_tools.py:377-399, file_tools_read_tracking.py:192-206)."""
        from tools import file_tools
        from tools.file_tools_read_tracking import notify_other_tool_call

        file_tools.clear_file_ops_cache(self._task_id)
        session_id = get_session_env("HERMES_SESSION_ID", "")
        if session_id:
            notify_other_tool_call(session_id)

    def _switched(self, target: str, sub: BaseEnvironment) -> None:
        """The conversation moved to ``target``. Core anchors relative file-tool paths on its cwd
        record before anything this object reports (file_tools_paths.py:131-144), so the record is
        set to where ``target`` was, through core's own call (terminal_tool.py:266-276)."""
        from tools.approval import get_current_session_key
        from tools.terminal_tool import get_session_cwd, record_session_cwd

        self._forget_file_ops()
        session_key = get_current_session_key(default=self._session_key)
        cwd = self._session_cwd.get(target) or sub.cwd
        if session_key and posixpath.isabs(device_path(cwd)):
            # A terminal call that is resolving its cwd has already read the old record.
            self._replaced = get_session_cwd(session_key)
            record_session_cwd(session_key, cwd)
            self._recorded_on(target)

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
            from tools.file_tools_paths import _configured_terminal_cwd

            cwd = (
                self._session_cwd.get(target)
                or requested
                or _configured_terminal_cwd()
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

    def _record_background(self, session_id: str, target: str, result: dict) -> None:
        """A launch: remember where it runs and its pid, parsed as core parses it
        (process_registry.py:1291)."""
        lines = map(str.strip, (result.get("output") or "").splitlines())
        pid = next((int(line) for line in lines if line.isdigit()), None)
        with self._lock:
            self._background[session_id] = (target, pid)
            if pid is not None:
                self._background_pids.setdefault(pid, set()).add(target)

    def _job_ended(self, session_ids: list[str]) -> None:
        """Ended jobs lose their route, and their pids stop counting, so a pid shared with one of them
        routes again."""
        with self._lock:
            for session_id in session_ids:
                target, pid = self._background.pop(session_id, (None, None))
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
        result = self._sub(owner)[1].execute(command, cwd, **kwargs)
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
        session's recorded cwd, else the configured default or workspace (terminal_tool.py:1014-1061,
        terminal_tool_background.py:173-176, terminal_tool_result.py:222-225), and tells the
        environment nothing about which (:1373-1377). So a cwd is changed only when it is provably
        not a workdir=: core's record of another target, or a gateway default on a device. Anything
        else runs where it says. Without a session key core keys the record by a task id this object
        never sees (:1528-1530); the cwd each target's last recorded command ended in stands in."""
        from tools.approval import get_current_session_key
        from tools.terminal_tool import _get_env_config, get_session_cwd, resolve_task_overrides

        session_key = get_current_session_key(default="")
        key = session_key or self._task_id
        recorded = get_session_cwd(key)
        known = self._session_cwd.get(target)
        if cwd == "~":
            # Core drops a /home or /Users record outside the sandbox home (terminal_tool.py:
            # 1041-1059); the session's cwd on this target is still where it was.
            if known is None and target == targets.SERVER and self._record_owner == targets.SERVER:
                known = recorded if recorded and os.path.isdir(recorded) else None
            return known or "", True
        if cwd == known:
            return cwd, True
        replaced, self._replaced = self._replaced, None
        if cwd == replaced:
            return known or "", True  # the record core read before this call moved it to the target
        owners = {other for other, seen in self._session_cwd.items() if seen == cwd}
        is_record = cwd == recorded if session_key else bool(owners)
        if is_record:
            # The session's record: written after a command on its owner's target.
            owner = next(iter(owners), self._record_owner)
            return (cwd if owner in (None, target) else known or ""), True
        defaults = {_get_env_config().get("cwd"), resolve_task_overrides(key).get("cwd")}
        if recorded is None and cwd in defaults:
            # Core's default with no record: terminal.cwd or a Desktop, TUI or ACP workspace,
            # a gateway directory unless it is under a device's home.
            return (cwd if target == targets.SERVER or self._in_home(sub, cwd) else ""), True
        return cwd, False  # workdir=

    @staticmethod
    def _in_home(sub: BaseEnvironment, cwd: str) -> bool:
        home = getattr(sub, "home", None)
        return bool(home) and (cwd == home or cwd.startswith(home.rstrip("/") + "/"))

    # --- delegated surface -----------------------------------------------------------------
    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        # Only the foreground terminal tool sets bounded_capture (base.py:679-681): its command runs on
        # this conversation's target exactly as approved, and only it moves the session's cwd record.
        terminal = bool(kwargs.get("bounded_capture"))
        # A file tool's command can name a job file, but only the registry polls and kills a job.
        registry = not terminal and not _called_from("tools.file_operations")
        launch = _BACKGROUND_LAUNCH.search(command) if registry else None
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
            if _called_from("tools.tool_result_storage") and witness._witness_device(self._ctx):
                # Core keeps the oversized result inline instead (tool_result_storage.py:434-437).
                return {"output": messages.WITNESS_RESULT_KEPT, "returncode": 1}
            # The file tools parse their raw output, so the note never goes there.
            noted = (target, get_session_env("HERMES_SESSION_ID", ""))
            if terminal and noted != self._noted:
                note = self._note(target)
        except sqlite3.Error:
            self._store_failed()
            return {"output": messages.STORE_DOWN, "returncode": UNREACHABLE}
        records = terminal
        if terminal or launch is not None:
            cwd, records = self._command_cwd(target, sub, cwd)
            records = records and terminal
        else:
            self._replaced = None  # core reads the record after this call, already moved
        if note is not None:
            self._noted = noted
        before = sub.cwd
        result = sub.execute(command, cwd, **kwargs)
        if result.get("cwd_observed"):
            if records:
                self._session_cwd[target] = result["cwd"]
                self._recorded_on(target)
            elif sub.cwd == result.get("cwd"):
                # Core records the cwd only after a terminal command without workdir=; execute_code
                # (cwd "/", code_execution_tool.py:674, code_execution_rpc.py:210-227), a file tool
                # or a workdir must not move where this target's next terminal command starts.
                sub.cwd = before
        if launch is not None:
            launched = _BACKGROUND_FILE.search(launch.group(1))
            if launched is not None:
                self._record_background(launched.group(1), target, result)
        if note is not None:
            result["output"] = f"{note}\n{result.get('output', '')}"
        return result

    def _recorded_on(self, target: str) -> None:
        """Core is about to record this command's cwd for the session (terminal_tool_result.py:
        222-225). The store keeps the owner for a later object; a store error here is logged rather
        than raised, since the command has already run."""
        if target == self._record_owner:
            return
        self._record_owner = target
        session_key = get_session_env("HERMES_SESSION_KEY", "")
        if not session_key:
            return
        try:
            store.set_last_run(session_key, target)
        except sqlite3.Error:
            self._store_failed()

    def _media_source(self) -> BaseEnvironment:
        """The target a MEDIA: line in the model's reply is fetched from (gateway/media_fetch.py:
        99-108). The fetch passes no tool call and so no approval, so an active witness device
        refuses it; the gateway logs the refusal and delivers nothing."""
        sub = self._resolve()[1]
        if witness._witness_device(self._ctx) is not None:
            raise FileFetchError(messages.WITNESS_MEDIA_BLOCKED)
        return sub

    def fetch_file(self, remote_path, local_dest, *, max_bytes: int) -> None:
        self._media_source().fetch_file(remote_path, local_dest, max_bytes=max_bytes)

    def fetch_realpath(self, remote_path: str) -> str | None:
        return self._media_source().fetch_realpath(remote_path)

    def get_temp_dir(self) -> str:
        return self._current()[1].get_temp_dir()

    @property
    def cwd(self) -> str:
        return self._current()[1].cwd

    @cwd.setter
    def cwd(self, value: str) -> None:
        """A workspace override (terminal_tool.py:350-362), which core also records as the session's
        cwd, names a gateway directory: devices keep theirs."""
        from tools.approval import get_current_session_key
        from tools.terminal_tool import record_session_cwd

        target, sub = self._current()
        self._session_cwd[targets.SERVER] = value  # where the server starts from now
        if target == targets.SERVER:
            sub.cwd = value
            self._recorded_on(targets.SERVER)
            return
        session_key = get_current_session_key(default="")
        cwd = self._session_cwd.get(target) or sub.cwd
        if session_key and posixpath.isabs(device_path(cwd)):
            record_session_cwd(session_key, cwd)  # core just recorded the workspace (:350-352)

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


def target_changed(session_key: str) -> None:
    """For ``/hands use``: move core's cwd record before its next tool call and clear old file caches."""
    from tools.terminal_tool_lifecycle import get_active_env

    active = get_active_env(session_key)
    for env in list(_LIVE):
        if env._session_key == session_key:
            if env is not active:
                env._forget_file_ops()
                continue
            try:
                env._resolve()
                # The target's cwd is now core's record. The next workdir= must pass through even if
                # it equals the cwd that belonged to the old target.
                env._replaced = None
            except sqlite3.Error:
                env._store_failed()
                env._forget_file_ops()
targets.bind_target_changed(target_changed)
