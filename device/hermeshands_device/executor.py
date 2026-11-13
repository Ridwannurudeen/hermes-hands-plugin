from __future__ import annotations

import os
import json
import logging
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import tempfile
import time
import select
from pathlib import Path
from typing import Iterator

import psutil

MAX_OUTPUT = 64 * 1024 * 1024
CHUNK_SIZE = 16 * 1024
PIPE_DRAIN_GRACE = 0.2
POST_EXIT_DRAIN_LIMIT = 2
OUTPUT_QUEUE_SIZE = 8
TASKKILL_TIMEOUT = 10
_PROBED: dict[str, tuple[int, int, int]] = {}  # file identity for candidates whose probe passed
_WINDOWS_JOBS: dict[int, int] = {}
_WINDOWS_JOBS_LOCK = threading.Lock()
_WINDOWS_REAPING: dict[int, int] = {}
_WINDOWS_REAPER: threading.Thread | None = None
_CREATE_SUSPENDED = 0x00000004
_POSIX_GROUPS: dict[int, float] = {}
_POSIX_MEMBERS: dict[int, dict[int, float]] = {}
_POSIX_GROUPS_LOCK = threading.Lock()
_POSIX_GUARDIAN: subprocess.Popen | None = None
_POSIX_GUARDIAN_TIMEOUT = 2.0
_POSIX_CONTINUITY_WINDOW = 1.0
_LINUX = sys.platform.startswith("linux")
_POSIX_LAUNCH_CODE = (
    "import os,signal,sys; fd=int(sys.argv[1]); ready=os.read(fd,1); os.close(fd); ready == b'1' or sys.exit(130); "
    "[signal.signal(getattr(signal, name), signal.SIG_DFL) for name in ('SIGPIPE', 'SIGXFSZ') if hasattr(signal, name)]; "
    "os.execv(sys.argv[2],sys.argv[2:])"
)
_POSIX_GUARDIAN_CODE = f"window = {_POSIX_CONTINUITY_WINDOW!r}\n" + r'''
import json, os, select, signal, sys, time
import psutil
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
linux = sys.platform.startswith("linux")
groups = {}
seen = {}
def start(pid):
    if linux:
        with open("/proc/%d/stat" % pid, "rb") as stat:
            return float(stat.read().rsplit(b")", 1)[1].split()[19])
    return psutil.Process(pid).create_time()
def refresh_all(targets):
    found = {}
    for pgid, members in targets.items():
        live = {}
        for pid, created in members.items():
            try:
                current = start(pid)
                if (current == created if linux else abs(current - created) <= 0.01) and os.getpgid(pid) == pgid:
                    live[pid] = created
            except (psutil.Error, OSError):
                pass
        # The pgid number stays reserved while any process uses it as a group or session id, so a group
        # seen moments ago is still ours while its session has members, even after every recorded one exited.
        continued = not live and members and time.monotonic() - seen.get(pgid, float("-inf")) <= window and not psutil.pid_exists(pgid)
        found[pgid] = (live, continued)
    # One process scan serves every group. It runs after the recorded members were checked, so a child
    # forked before they exited is in it; each candidate is checked again below.
    candidates = {}
    if any(live or continued for live, continued in found.values()):
        for proc in psutil.process_iter():
            try:
                candidates.setdefault(os.getpgid(proc.pid), []).append(proc.pid)
            except (psutil.Error, OSError):
                pass
    for pgid, (live, continued) in found.items():
        for pid in candidates.get(pgid, ()) if live or continued else ():
            try:
                if os.getpgid(pid) == pgid and (not continued or os.getsid(pid) == pgid):
                    live[pid] = start(pid)
            except (psutil.Error, OSError):
                pass
        if live:
            seen[pgid] = time.monotonic()
        else:
            seen.pop(pgid, None)
    return {pgid: live for pgid, (live, _) in found.items()}
def refresh(pgid, members):
    return refresh_all({pgid: members})[pgid]
def kill(targets):
    for pgid, live in refresh_all(targets).items():
        if live:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
print("ready", flush=True)
next_pass = float("-inf")
try:
    while True:
        if time.monotonic() >= next_pass:
            groups.update(refresh_all(groups))
            next_pass = time.monotonic() + 0.1
        ready, _, _ = select.select([sys.stdin], [], [], max(0, next_pass - time.monotonic()))
        if not ready:
            continue
        line = sys.stdin.readline()
        if not line:
            break
        action, pgid, *created = line.split()
        pgid = int(pgid)
        if action in ("add", "set"):
            members = {int(pid): value for pid, value in json.loads(created[1]).items()} if len(created) > 1 else {pgid: float(created[0])}
            if action == "add":
                seen.pop(pgid, None)
            groups[pgid] = refresh(pgid, members)
        elif action == "check" and pgid in groups:
            groups[pgid] = refresh(pgid, groups[pgid])
        elif action == "checkall":
            groups.update(refresh_all(groups))
        elif action == "kill":
            kill({pgid: groups.pop(pgid, {})})
        elif action == "killall":
            kill(groups)
            groups.clear()
        elif action == "del":
            groups.pop(pgid, None)
        print("ack " + json.dumps(groups if action == "checkall" else groups.get(pgid, {})), flush=True)
finally:
    kill(groups)
'''


def _is_stub(path: str) -> bool:
    lowered = os.path.normcase(os.path.normpath(path)).lower().replace("/", "\\")
    return "\\system32\\" in lowered or "\\windowsapps\\" in lowered


def resolve_bash() -> str | None:
    candidates: list[str] = []
    if os.name == "nt":
        env = os.environ
        if env.get("HERMES_HANDS_BASH"):
            candidates.append(env["HERMES_HANDS_BASH"])
        pf = env.get("ProgramFiles", r"C:\Program Files")
        roots = [os.path.join(pf, "Git")]
        if env.get("ProgramFiles(x86)"):
            roots.append(os.path.join(env["ProgramFiles(x86)"], "Git"))
        if env.get("LOCALAPPDATA"):
            roots.append(os.path.join(env["LOCALAPPDATA"], "Programs", "Git"))
        for root in roots:
            candidates.extend((os.path.join(root, "bin", "bash.exe"), os.path.join(root, "usr", "bin", "bash.exe")))
    which = shutil.which("bash")
    if which and (os.name != "nt" or not _is_stub(which)):
        candidates.append(which)
    for candidate in dict.fromkeys(candidates):
        if os.name == "nt" and _is_stub(candidate):
            continue
        try:
            stat = os.stat(candidate)
        except OSError:
            continue
        identity = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
        if candidate in _PROBED:
            if _PROBED[candidate] == identity:
                return candidate
            del _PROBED[candidate]
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            probe = subprocess.run([candidate, "-c", "exit 0"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, creationflags=flags, check=False)
            if probe.returncode == 0:
                _PROBED[candidate] = identity
                return candidate
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def _terminate(proc: subprocess.Popen, start_time: float) -> None:
    if os.name == "nt":
        terminate_recorded(proc.pid, start_time)
        return
    if not _posix_group_is_ours(proc.pid, start_time):
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only branch
    except ProcessLookupError:
        return
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Could not kill process group %s: %s", proc.pid, exc
        )


def _start_time(pid: int) -> float:
    # Linux start ticks count from boot, so a wall clock step cannot change them as it changes create_time.
    if _LINUX:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            return float(stat.read().rsplit(b")", 1)[1].split()[19])
    return psutil.Process(pid).create_time()


def _same_start(pid: int, start_time: float) -> bool:
    current = _start_time(pid)
    return current == start_time if _LINUX else abs(current - start_time) <= 0.01


def _boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return None


def _posix_group_is_ours(pgid: int, start_time: float, scan: bool = True) -> bool:
    members = _POSIX_MEMBERS.get(pgid, {pgid: start_time})
    live = {}
    for pid, created in members.items():
        try:
            if _same_start(pid, created) and os.getpgid(pid) == pgid:
                live[pid] = created
        except (psutil.Error, OSError):
            continue
    if not live:
        _POSIX_MEMBERS.pop(pgid, None)
        return False
    for process in psutil.process_iter() if scan else ():
        try:
            if os.getpgid(process.pid) == pgid:
                live[process.pid] = _start_time(process.pid)
        except (psutil.Error, OSError):
            continue
    _POSIX_MEMBERS[pgid] = live
    return True


def _forget_posix_group(pgid: int) -> None:
    _POSIX_GROUPS.pop(pgid, None)
    _POSIX_MEMBERS.pop(pgid, None)
    for process in psutil.process_iter():
        try:
            if os.getpgid(process.pid) == pgid:
                logging.getLogger(__name__).warning("Process group %s still has processes the agent cannot prove it started; they are left running", pgid)
                return
        except (psutil.Error, OSError):
            continue


def _leader_running(proc: subprocess.Popen, start_time: float) -> bool:
    # Only run() reaps the leader, so until then its pid cannot belong to another process.
    if os.name == "nt" or proc.returncode is not None:
        return proc.poll() is None
    try:
        return psutil.Process(proc.pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _record_posix_group_at_exit(pgid: int, start_time: float) -> None:
    # The exited leader is still unreaped, so no other group can hold its id while we scan.
    try:
        if psutil.Process(pgid).status() != psutil.STATUS_ZOMBIE:
            return
    except psutil.Error:
        return
    members = {pgid: start_time}
    for process in psutil.process_iter():
        try:
            if os.getpgid(process.pid) == pgid:
                members[process.pid] = _start_time(process.pid)
        except (psutil.Error, OSError):
            continue
    with _POSIX_GROUPS_LOCK:
        if _POSIX_GROUPS.get(pgid) != start_time:
            return
        _POSIX_MEMBERS[pgid] = members
        if len(members) > 1:
            try:
                _send_to_posix_guardian(f"set {pgid} {start_time!r}\n")
            except RuntimeError as exc:
                logging.getLogger(__name__).warning("Could not update job guardian: %s", exc)


class _GuardianStalled(RuntimeError):
    pass


def _guardian_ack(expected: str, deadline: float) -> str:
    guardian = _POSIX_GUARDIAN
    ready, _, _ = select.select([guardian.stdout], [], [], max(0, deadline - time.monotonic()))
    if not ready:
        raise _GuardianStalled("The job guardian did not answer in time")
    response = guardian.stdout.readline().strip()
    if response.split(" ", 1)[0] != expected:
        raise RuntimeError("The job guardian did not acknowledge protection")
    return response


def _send_to_posix_guardian(line: str, deadline: float | None = None) -> None:
    global _POSIX_GUARDIAN
    if deadline is None:
        deadline = time.monotonic() + _POSIX_GUARDIAN_TIMEOUT
    commands = [(command, True) for command in line.splitlines()]
    try:
        if _POSIX_GUARDIAN is None or _POSIX_GUARDIAN.poll() is not None:
            _POSIX_GUARDIAN = subprocess.Popen(
                [sys.executable, "-I", "-u", "-c", _POSIX_GUARDIAN_CODE],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                start_new_session=True, text=True, bufsize=1,
            )
            _guardian_ack("ready", deadline)
            registering = {int(command.split()[1]) for command, _ in commands if command.split()[0] in ("add", "set")}
            restored = []
            for pgid, created in list(_POSIX_GROUPS.items()):
                if pgid in registering:
                    continue
                if _posix_group_is_ours(pgid, created):
                    restored.append((f"add {pgid} {created!r}", False))
                else:
                    _forget_posix_group(pgid)
            commands = restored + commands
        for command, required in commands:
            parts = command.split()
            if parts[0] in ("add", "set"):
                pgid = int(parts[1])
                members = _POSIX_MEMBERS.get(pgid, {pgid: float(parts[2])})
                command += " " + json.dumps(members, separators=(",", ":"))
            _POSIX_GUARDIAN.stdin.write(command + "\n")
            _POSIX_GUARDIAN.stdin.flush()
            response = _guardian_ack("ack", deadline)
            members = json.loads(response.split(" ", 1)[1])
            if parts[0] == "checkall":
                for old in _POSIX_GROUPS:
                    _POSIX_MEMBERS[old] = {int(pid): created for pid, created in members.get(str(old), {}).items()}
                continue
            pgid = int(parts[1])
            if parts[0] == "add" and not members:
                if required:
                    raise RuntimeError("The job guardian could not identify the protected process")
                _forget_posix_group(pgid)
                continue
            _POSIX_MEMBERS[pgid] = {int(pid): created for pid, created in members.items()}
    except (OSError, ValueError, RuntimeError) as exc:
        guardian, _POSIX_GUARDIAN = _POSIX_GUARDIAN, None
        # A guardian that only answered late about earlier jobs is killed outright, so its exit cleanup cannot
        # end those jobs; they stay tracked and the next job's guardian takes them back if they are still ours.
        stalled = isinstance(exc, _GuardianStalled) and bool(commands) and all(command.split()[0] in ("checkall", "del") for command, _ in commands)
        if guardian is not None and stalled:
            try:
                guardian.kill()
                guardian.wait(timeout=0.2)
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                logging.getLogger(__name__).warning("Could not finish job guardian cleanup: %s", cleanup_error)
            finally:
                guardian.stdin.close()
                guardian.stdout.close()
            raise RuntimeError("Could not establish job guardian protection") from exc
        if guardian is not None:
            try:
                guardian.stdin.close()
                guardian.wait(timeout=max(0, min(0.2, deadline - time.monotonic())))
            except (OSError, subprocess.TimeoutExpired):
                try:
                    guardian.kill()
                    guardian.wait(timeout=max(0, min(0.2, deadline - time.monotonic())))
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    logging.getLogger(__name__).warning("Could not finish job guardian cleanup: %s", cleanup_error)
            finally:
                guardian.stdout.close()
        for pgid, created in list(_POSIX_GROUPS.items()):
            if not _posix_group_is_ours(pgid, created):
                _forget_posix_group(pgid)
                continue
            try:
                os.killpg(pgid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only caller
            except OSError as kill_error:
                logging.getLogger(__name__).warning("Could not kill process group %s: %s", pgid, kill_error)
        raise RuntimeError("Could not establish job guardian protection") from exc


def _track_posix_group(pgid: int, start_time: float) -> None:
    with _POSIX_GROUPS_LOCK:
        deadline = time.monotonic() + _POSIX_GUARDIAN_TIMEOUT
        if _POSIX_GROUPS:
            _send_to_posix_guardian("checkall 0\n", deadline)
        for old, old_start in list(_POSIX_GROUPS.items()):
            if not _posix_group_is_ours(old, old_start, scan=False):
                _POSIX_GROUPS.pop(old, None)
                _send_to_posix_guardian(f"del {old}\n", deadline)
        _POSIX_GROUPS[pgid] = start_time
        _POSIX_MEMBERS[pgid] = {pgid: start_time}
        _posix_group_is_ours(pgid, start_time)
        _send_to_posix_guardian(f"add {pgid} {start_time!r}\n", time.monotonic() + _POSIX_GUARDIAN_TIMEOUT)


def _terminate_posix_groups(deadline: float | None = None) -> None:
    if os.name == "nt":
        return
    if deadline is None:
        deadline = time.monotonic() + _POSIX_GUARDIAN_TIMEOUT
    if not _POSIX_GROUPS_LOCK.acquire(timeout=max(0, deadline - time.monotonic())):
        guardian = _POSIX_GUARDIAN
        if guardian is not None:
            try:
                guardian.stdin.close()
            except (OSError, ValueError) as exc:
                logging.getLogger(__name__).warning("Could not close job guardian input during cleanup: %s", exc)
        logging.getLogger(__name__).warning("Process group cleanup reached its deadline; the guardian will finish cleanup")
        return
    try:
        for pgid, start_time in list(_POSIX_GROUPS.items()):
            if _posix_group_is_ours(pgid, start_time):
                try:
                    os.killpg(pgid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only branch
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    logging.getLogger(__name__).warning("Could not kill process group %s: %s", pgid, exc)
            del _POSIX_GROUPS[pgid]
            _POSIX_MEMBERS.pop(pgid, None)
        if _POSIX_GUARDIAN is not None:
            try:
                _send_to_posix_guardian("killall 0\n", deadline)
                _POSIX_MEMBERS.pop(0, None)
            except RuntimeError as exc:
                logging.getLogger(__name__).warning("Could not reach job guardian during cleanup: %s", exc)
    finally:
        _POSIX_GROUPS_LOCK.release()


def _windows_job_name(pid: int, start_time: float) -> str:
    return f"Local\\hermes-hands-{pid}-{int(start_time * 1000)}"


def _open_windows_job(pid: int, start_time: float) -> int | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    job = kernel32.OpenJobObjectW(0x0008, False, _windows_job_name(pid, start_time))
    return int(job if isinstance(job, int) else job.value) if job else None


def _terminate_windows_job(pid: int, start_time: float) -> bool:
    with _WINDOWS_JOBS_LOCK:
        job = _WINDOWS_JOBS.get(pid)
        opened_job = job is None
        if job is None:
            job = _open_windows_job(pid, start_time)
        if job is None:
            return False
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        terminated = bool(kernel32.TerminateJobObject(wintypes.HANDLE(job), 1))
        if opened_job:
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle(wintypes.HANDLE(job))
        return terminated


def _windows_job_has_active_processes(job: int) -> bool:
    import ctypes
    from ctypes import wintypes

    class BasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", ctypes.c_uint32),
            ("TotalProcesses", ctypes.c_uint32),
            ("ActiveProcesses", ctypes.c_uint32),
            ("TotalTerminatedProcesses", ctypes.c_uint32),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    info = BasicAccountingInformation()
    queried = kernel32.QueryInformationJobObject(wintypes.HANDLE(job), 1, ctypes.byref(info), ctypes.sizeof(info), None)
    return bool(queried and info.ActiveProcesses)


def _wait_for_windows_job_exit() -> None:
    global _WINDOWS_REAPER
    while True:
        with _WINDOWS_JOBS_LOCK:
            for pid, job in list(_WINDOWS_REAPING.items()):
                if _WINDOWS_JOBS.get(pid) != job:
                    del _WINDOWS_REAPING[pid]
                    continue
                try:
                    if _windows_job_has_active_processes(job):
                        continue
                    import ctypes
                    from ctypes import wintypes

                    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                    kernel32.CloseHandle(wintypes.HANDLE(job))
                    del _WINDOWS_JOBS[pid]
                    del _WINDOWS_REAPING[pid]
                except OSError as exc:
                    logging.getLogger(__name__).warning("Could not reap Windows job %s: %s", pid, exc)
            if not _WINDOWS_REAPING:
                _WINDOWS_REAPER = None
                return
        time.sleep(0.1)


def _create_windows_job(proc: subprocess.Popen, start_time: float) -> int | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, _windows_job_name(proc.pid, start_time))
    if not job:
        raise OSError(ctypes.get_last_error(), "Could not create Windows job object")

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    job_value = int(job if isinstance(job, int) else job.value)
    job_handle = wintypes.HANDLE(job_value)

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    limits = ExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x00002000
    try:
        if not kernel32.SetInformationJobObject(job_handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError(ctypes.get_last_error(), "Could not set Windows job object limits")
        process_handle = wintypes.HANDLE(int(proc._handle))
        if not kernel32.AssignProcessToJobObject(job_handle, process_handle):
            raise OSError(ctypes.get_last_error(), "Could not assign process to Windows job object")
    except BaseException:
        kernel32.CloseHandle(job_handle)
        raise

    with _WINDOWS_JOBS_LOCK:
        _WINDOWS_JOBS[proc.pid] = job_value
    return job_value


def _resume_windows_process(proc: subprocess.Popen) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    threads = psutil.Process(proc.pid).threads()
    if len(threads) != 1:
        raise RuntimeError("Could not identify the suspended device process thread")
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    thread = kernel32.OpenThread(0x0002, False, threads[0].id)
    if not thread:
        raise OSError(ctypes.get_last_error(), "Could not open the suspended device process thread")
    thread_value = int(thread if isinstance(thread, int) else thread.value)
    thread_handle = wintypes.HANDLE(thread_value)
    try:
        previous_suspend_count = kernel32.ResumeThread(thread_handle)
        if previous_suspend_count == 0xFFFFFFFF:
            raise OSError(ctypes.get_last_error(), "Could not resume the device process thread")
        if previous_suspend_count != 1:
            raise RuntimeError("The device process thread was not suspended exactly once")
    finally:
        kernel32.CloseHandle(thread_handle)


def _close_windows_job(proc: subprocess.Popen | None, job: int | None, *, keep_active: bool = False) -> None:
    global _WINDOWS_REAPER
    if proc is None or os.name != "nt":
        return
    with _WINDOWS_JOBS_LOCK:
        current_job = _WINDOWS_JOBS.get(proc.pid)
        if current_job is None or (job is not None and current_job != job):
            return
        if keep_active and _windows_job_has_active_processes(current_job):
            _WINDOWS_REAPING[proc.pid] = current_job
            if _WINDOWS_REAPER is None:
                _WINDOWS_REAPER = threading.Thread(target=_wait_for_windows_job_exit, daemon=True)
                _WINDOWS_REAPER.start()
        else:
            del _WINDOWS_JOBS[proc.pid]
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle(wintypes.HANDLE(current_job))


def _terminate_windows_jobs(deadline: float | None = None) -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    if deadline is None:
        deadline = time.monotonic() + TASKKILL_TIMEOUT
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    while True:
        if not _WINDOWS_JOBS_LOCK.acquire(timeout=max(0, deadline - time.monotonic())):
            logging.getLogger(__name__).warning("Windows job cleanup reached its deadline while waiting for a handle")
            return
        try:
            for pid, job in list(_WINDOWS_JOBS.items()):
                close_job = time.monotonic() >= deadline
                try:
                    if not close_job:
                        close_job = not _windows_job_has_active_processes(job)
                    if not close_job and not kernel32.TerminateJobObject(wintypes.HANDLE(job), 1):
                        logging.getLogger(__name__).warning("Could not terminate Windows job %s", pid)
                        close_job = True
                except OSError as exc:
                    logging.getLogger(__name__).warning("Could not terminate Windows job %s: %s", pid, exc)
                    close_job = True
                if close_job:
                    try:
                        kernel32.CloseHandle(wintypes.HANDLE(job))
                    except OSError as exc:
                        logging.getLogger(__name__).warning("Could not close Windows job %s: %s", pid, exc)
                    else:
                        del _WINDOWS_JOBS[pid]
                        _WINDOWS_REAPING.pop(pid, None)
            if not _WINDOWS_JOBS:
                return
        finally:
            _WINDOWS_JOBS_LOCK.release()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logging.getLogger(__name__).warning("Windows job cleanup reached its deadline")
            return
        time.sleep(min(0.05, remaining))


def terminate_recorded(pid: int, start_time: float) -> None:
    try:
        process = psutil.Process(pid)
        if not _same_start(pid, start_time):
            return
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return
    if os.name == "nt":
        try:
            descendants = [
                (child.pid, child.create_time())
                for child in process.children(recursive=True)
            ]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            descendants = []
        _terminate_windows_job(pid, start_time)
        for child_pid, child_start in reversed(descendants):
            try:
                child = psutil.Process(child_pid)
                if abs(child.create_time() - child_start) <= 0.01:
                    child.kill()
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, OSError) as exc:
                logging.getLogger(__name__).warning(
                    "Could not reap job child %s: %s", child_pid, exc
                )
        try:
            if abs(process.create_time() - start_time) <= 0.01:
                process.kill()
        except psutil.NoSuchProcess:
            return
        except (psutil.AccessDenied, OSError) as exc:
            logging.getLogger(__name__).warning(
                "Could not reap process %s: %s", pid, exc
            )
    else:
        try:
            os.killpg(pid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only branch
        except ProcessLookupError:
            pass


def record_path(job_id: str) -> Path:
    return Path.home() / ".hermes-hands" / "out" / f"{job_id}.process.json"


def record_process(job_id: str, pid: int, start_time: float) -> None:
    path = record_path(job_id)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f"{job_id}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as record:
            json.dump({"pid": pid, "create_time": start_time, **({"boot_id": _boot_id()} if _LINUX else {})}, record)
            record.flush()
            os.fsync(record.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reap_recorded_processes() -> None:
    out_dir = Path.home() / ".hermes-hands" / "out"
    if not out_dir.exists():
        return
    boot_id = _boot_id() if _LINUX else None
    for path in out_dir.glob("*.process.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8-sig"))
            # Linux start ticks restart at each boot, so a record from an earlier boot names nothing of ours.
            if not _LINUX or (boot_id is not None and record.get("boot_id") == boot_id):
                terminate_recorded(int(record["pid"]), float(record["create_time"]))
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
            import logging

            logging.getLogger(__name__).warning("Could not reap process record %s: %s", path.name, exc)
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                import logging

                logging.getLogger(__name__).warning("Could not remove process record %s: %s", path.name, exc)
    for path in out_dir.glob("*.stdin"):
        path.unlink(missing_ok=True)


def run(script: str, *, login: bool = False, timeout: int = 120, job_id: str = "job", stdin: str | None = None, stdin_b64: str | None = None, on_start=None, on_exit=None, on_capped=None, on_truncated=None, cancel_event: threading.Event | None = None) -> Iterator[bytes]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job_id):
        raise ValueError("invalid job id")
    if stdin is not None and stdin_b64 is not None:
        raise ValueError("stdin and stdin_b64 cannot both be provided")
    bash = resolve_bash()
    if not bash:
        raise RuntimeError("Git Bash was not found or failed its probe")
    script_dir = Path.home() / ".hermes-hands" / "out"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = None
    stdin_path = None
    stdin_handle = subprocess.DEVNULL
    proc = None
    created = None
    windows_job = None
    record_written = False
    launch_pipe = None
    try:
        if stdin_b64 is not None:
            import base64

            try:
                stdin_bytes = base64.b64decode(stdin_b64, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("stdin_b64 must be valid base64") from exc
        elif stdin is not None:
            stdin_bytes = stdin.encode("utf-8", errors="surrogateescape")
        else:
            stdin_bytes = None
        if stdin_bytes is not None:
            with tempfile.NamedTemporaryFile("wb", prefix=f"{job_id}.", suffix=".stdin", dir=script_dir, delete=False) as stdin_file:
                stdin_path = Path(stdin_file.name)
                stdin_file.write(stdin_bytes)
            stdin_handle = stdin_path.open("rb")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", suffix=".sh", dir=script_dir, delete=False) as script_file:
            script_file.write(script)
            script_path = Path(script_file.name)
        args = [bash, *(["-l"] if login else []), str(script_path)]
        kwargs = {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0) | _CREATE_SUSPENDED} if os.name == "nt" else {"start_new_session": True}
        env = os.environ.copy()
        env["HERMES_HANDS_JOB"] = "1"
        if os.name == "nt":
            env.setdefault("PYTHONUTF8", "1")
            env.setdefault("PYTHONIOENCODING", "utf-8")
        else:
            with _POSIX_GROUPS_LOCK:
                _send_to_posix_guardian("")
            launch_pipe = os.pipe()
            kwargs["pass_fds"] = (launch_pipe[0],)
            args = [sys.executable, "-I", "-c", _POSIX_LAUNCH_CODE, str(launch_pipe[0]), *args]
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("The device job was cancelled before launch")
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=stdin_handle, env=env, **kwargs)
        if stdin_bytes is not None:
            stdin_handle.close()
        created = _start_time(proc.pid)
        windows_job = _create_windows_job(proc, created)
        if os.name != "nt":
            _track_posix_group(proc.pid, created)
        if on_start:
            record_process(job_id, proc.pid, created)
            record_written = True
            on_start(proc, created)
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("The device job was cancelled before launch")
        if windows_job is not None and proc.poll() is None:
            _resume_windows_process(proc)
        if launch_pipe is not None:
            os.write(launch_pipe[1], b"1")
    except BaseException:
        if launch_pipe is not None:
            for fd in launch_pipe:
                os.close(fd)
            launch_pipe = None
        if stdin_handle != subprocess.DEVNULL:
            stdin_handle.close()
        if proc is not None and proc.poll() is None:
            if created is not None:
                _terminate(proc, created)
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired as exc:
                logging.getLogger(__name__).warning("Could not finish cancelled job cleanup: %s", exc)
        if script_path is not None:
            script_path.unlink(missing_ok=True)
        if stdin_path is not None:
            stdin_path.unlink(missing_ok=True)
        _close_windows_job(proc, windows_job)
        if record_written:
            record_path(job_id).unlink(missing_ok=True)
        raise
    finally:
        if launch_pipe is not None:
            for fd in launch_pipe:
                os.close(fd)
    chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=OUTPUT_QUEUE_SIZE)
    deadline = time.monotonic() + timeout
    total = 0
    capped = threading.Event()
    exited = threading.Event()
    timed_out = threading.Event()
    reader_stop = threading.Event()
    termination_started = threading.Event()
    truncated = threading.Event()

    def terminate_once() -> None:
        if not termination_started.is_set():
            _terminate(proc, created)
            termination_started.set()

    def kill_at_deadline() -> None:
        timed_out.set()
        if _leader_running(proc, created) or proc.pid in _WINDOWS_JOBS:
            terminate_once()

    timer = threading.Timer(max(0, deadline - time.monotonic()), kill_at_deadline)
    timer.daemon = True
    timer.start()

    def read_output() -> None:
        nonlocal total
        idle_deadline = None
        post_exit_started = None
        backpressure = 0.0

        def post_exit_limit_reached() -> bool:
            nonlocal post_exit_started, backpressure
            if _leader_running(proc, created):
                return False
            if post_exit_started is None:
                post_exit_started = time.monotonic()
                backpressure = 0.0
            return time.monotonic() - post_exit_started - backpressure >= POST_EXIT_DRAIN_LIMIT

        def truncate_post_exit() -> None:
            truncated.set()
            if on_truncated:
                on_truncated()
            send_end()

        def send_end() -> None:
            while not reader_stop.is_set():
                try:
                    chunks.put(None, timeout=0.05)
                    return
                except queue.Full:
                    if exited.is_set():
                        return

        while True:
            if reader_stop.is_set():
                return
            if timed_out.is_set():
                return
            if os.name == "nt":
                import ctypes
                import msvcrt

                available_bytes = ctypes.c_ulong()
                ready = ctypes.windll.kernel32.PeekNamedPipe(
                    msvcrt.get_osfhandle(proc.stdout.fileno()), None, 0, None, ctypes.byref(available_bytes), None
                )
                if not ready:
                    chunk = os.read(proc.stdout.fileno(), CHUNK_SIZE)
                elif available_bytes.value == 0:
                    if proc.poll() is not None:
                        if idle_deadline is None:
                            idle_deadline = time.monotonic() + PIPE_DRAIN_GRACE
                        elif time.monotonic() >= idle_deadline:
                            send_end()
                            return
                    time.sleep(0.05)
                    continue
                else:
                    chunk = os.read(proc.stdout.fileno(), min(CHUNK_SIZE, available_bytes.value))
            else:
                ready, _, _ = select.select([proc.stdout], [], [], 0.05)
                chunk = os.read(proc.stdout.fileno(), CHUNK_SIZE) if ready else None
                if chunk is None:
                    if not _leader_running(proc, created):
                        if idle_deadline is None:
                            idle_deadline = time.monotonic() + PIPE_DRAIN_GRACE
                        elif time.monotonic() >= idle_deadline:
                            send_end()
                            return
                    continue
            if not chunk:
                send_end()
                return
            idle_deadline = None
            available = MAX_OUTPUT - total
            if len(chunk) > available:
                chunk = chunk[:available]
                capped.set()
            total += len(chunk)
            blocked_at = time.monotonic()
            while True:
                if reader_stop.is_set():
                    return
                try:
                    chunks.put(chunk, timeout=0.05)
                    backpressure += time.monotonic() - blocked_at
                    break
                except queue.Full:
                    if exited.is_set():
                        return
            if capped.is_set():
                terminate_once()
                send_end()
                return
            if post_exit_limit_reached():
                truncate_post_exit()
                return

    def record_group_before_reaping() -> None:
        if os.name != "nt" and proc.returncode is None and not _leader_running(proc, created):
            _record_posix_group_at_exit(proc.pid, created)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    output_path = Path.home() / ".hermes-hands" / "out" / f"{job_id}.log"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = False
    try:
        with output_path.open("wb") as log:
            while True:
                now = time.monotonic()
                if timed_out.is_set() or (now >= deadline and _leader_running(proc, created)):
                    terminate_once()
                    if on_exit:
                        on_exit(124)
                    yield b"[device timeout]\n"
                    return
                try:
                    chunk = chunks.get(timeout=0.1)
                except queue.Empty:
                    continue
                if chunk is None:
                    break
                log.write(chunk)
                yield chunk
            if timed_out.is_set():
                if on_exit:
                    on_exit(124)
                yield b"[device timeout]\n"
                return
            if capped.is_set():
                if on_capped:
                    on_capped()
                if on_exit:
                    on_exit(1)
                yield b"[output truncated at 64 MiB]\n"
                return
            if truncated.is_set():
                completed = True
                if on_exit:
                    on_exit(1)
                yield b"[output truncated after the post-exit idle limit]\n"
                return
        if os.name != "nt":
            while _leader_running(proc, created) and time.monotonic() < deadline:
                time.sleep(0.01)
            record_group_before_reaping()
        proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        if timed_out.is_set():
            if on_exit:
                on_exit(124)
            yield b"[device timeout]\n"
        elif on_exit:
            on_exit(proc.returncode)
        completed = True
    finally:
        exited.set()
        reader_stop.set()
        timer.cancel()
        timer.join(timeout=TASKKILL_TIMEOUT + 1)
        record_group_before_reaping()
        if proc.poll() is None or (not completed and proc.pid in _WINDOWS_JOBS):
            terminate_once()
            if proc.poll() is None:
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        reader.join(timeout=0.2)
        if proc.stdout is not None:
            proc.stdout.close()
        if script_path is not None:
            script_path.unlink(missing_ok=True)
        if stdin_path is not None:
            stdin_path.unlink(missing_ok=True)
        record_path(job_id).unlink(missing_ok=True)
        if os.name != "nt":
            _posix_group_is_ours(proc.pid, created)
        if proc is not None:
            _close_windows_job(proc, windows_job, keep_active=completed and not timed_out.is_set() and not termination_started.is_set())
