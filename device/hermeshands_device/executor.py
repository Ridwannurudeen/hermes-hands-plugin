from __future__ import annotations

import os
import json
import logging
import queue
import re
import shutil
import signal
import subprocess
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
_CREATE_SUSPENDED = 0x00000004


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
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # windows-footgun: ok -- POSIX-only branch
    except ProcessLookupError:
        return
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Could not kill process group %s: %s", proc.pid, exc
        )


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


def _wait_for_windows_job_exit(pid: int, job: int) -> None:
    while True:
        with _WINDOWS_JOBS_LOCK:
            if _WINDOWS_JOBS.get(pid) != job:
                return
            if not _windows_job_has_active_processes(job):
                del _WINDOWS_JOBS[pid]
                import ctypes
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel32.CloseHandle(wintypes.HANDLE(job))
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
    return job_value


def _close_windows_job(proc: subprocess.Popen, job: int | None, *, keep_active: bool = False) -> None:
    reap_later = False
    with _WINDOWS_JOBS_LOCK:
        current_job = _WINDOWS_JOBS.get(proc.pid)
        if current_job is None or (job is not None and current_job != job):
            return
        if keep_active and _windows_job_has_active_processes(current_job):
            reap_later = True
        else:
            del _WINDOWS_JOBS[proc.pid]
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle(wintypes.HANDLE(current_job))
    if reap_later:
        watcher = threading.Thread(target=_wait_for_windows_job_exit, args=(proc.pid, current_job), daemon=True)
        watcher.start()


def _terminate_windows_jobs() -> None:
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    while True:
        with _WINDOWS_JOBS_LOCK:
            for pid, job in list(_WINDOWS_JOBS.items()):
                if not _windows_job_has_active_processes(job):
                    if _WINDOWS_JOBS.get(pid) == job:
                        del _WINDOWS_JOBS[pid]
                        kernel32.CloseHandle(wintypes.HANDLE(job))
                    continue
                if not kernel32.TerminateJobObject(wintypes.HANDLE(job), 1) and _windows_job_has_active_processes(job):
                    raise OSError(ctypes.get_last_error(), "Could not terminate Windows job object")
            if not _WINDOWS_JOBS:
                return
        time.sleep(0.05)


def terminate_recorded(pid: int, start_time: float) -> None:
    try:
        process = psutil.Process(pid)
        current = process.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return
    if abs(current - start_time) > 0.01:
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
            json.dump({"pid": pid, "create_time": start_time}, record)
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
    for path in out_dir.glob("*.process.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8-sig"))
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


def run(script: str, *, login: bool = False, timeout: int = 120, job_id: str = "job", stdin: str | None = None, stdin_b64: str | None = None, on_start=None, on_exit=None, on_capped=None, on_truncated=None) -> Iterator[bytes]:
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
    windows_job = None
    record_written = False
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
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=stdin_handle, env=env, **kwargs)
        if stdin_bytes is not None:
            stdin_handle.close()
        created = psutil.Process(proc.pid).create_time()
        windows_job = _create_windows_job(proc, created)
        if on_start:
            record_process(job_id, proc.pid, created)
            record_written = True
            on_start(proc, created)
    except BaseException:
        if stdin_handle != subprocess.DEVNULL:
            stdin_handle.close()
        if proc is not None and proc.poll() is None:
            _terminate(proc, psutil.Process(proc.pid).create_time())
            proc.wait()
        if script_path is not None:
            script_path.unlink(missing_ok=True)
        if stdin_path is not None:
            stdin_path.unlink(missing_ok=True)
        _close_windows_job(proc, windows_job)
        if record_written:
            record_path(job_id).unlink(missing_ok=True)
        raise
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
        if proc.poll() is None or proc.pid in _WINDOWS_JOBS:
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
            if proc.poll() is None:
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
                    if proc.poll() is not None:
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

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    output_path = Path.home() / ".hermes-hands" / "out" / f"{job_id}.log"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = False
    try:
        with output_path.open("wb") as log:
            while True:
                now = time.monotonic()
                if timed_out.is_set() or (proc.poll() is None and now >= deadline):
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
        if proc is not None:
            _close_windows_job(proc, windows_job, keep_active=completed and not timed_out.is_set() and not termination_started.is_set())
