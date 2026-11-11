import subprocess
import sys
import threading
import time
from datetime import datetime
from types import SimpleNamespace

import pytest

from hermeshands_device import checkup, executor


def _quiet_probes(monkeypatch):
    monkeypatch.setattr(
        checkup.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1000, used=800, free=200),
    )
    monkeypatch.setattr(
        checkup.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=1000, available=300, percent=70),
    )
    monkeypatch.setattr(checkup.psutil, "process_iter", lambda attrs=None: iter(()))
    monkeypatch.setattr(checkup.psutil, "net_if_stats", lambda: {})
    monkeypatch.setattr(checkup.psutil, "boot_time", lambda: 1_000_000_000)
    monkeypatch.setattr(checkup.psutil, "sensors_battery", lambda: None)
    monkeypatch.setattr(checkup.socket, "getaddrinfo", lambda *args, **kwargs: [object()])

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(checkup.socket, "create_connection", lambda *args, **kwargs: Connection())
    monkeypatch.setattr(
        checkup,
        "_run_windows_probe",
        lambda name, deadline: {"print_queue_jobs": 0, "print_queue_count": 2},
        raising=False,
    )


def _facts(result):
    return {fact["id"]: fact for fact in result["facts"]}


def test_checkup_uses_the_frozen_v1_fact_schema(monkeypatch):
    _quiet_probes(monkeypatch)

    result = checkup.collect()

    assert set(result) == {"schema_version", "observed_at", "platform", "facts", "inferences"}
    assert result["schema_version"] == 1
    assert result["platform"]
    datetime.fromisoformat(result["observed_at"].replace("Z", "+00:00"))
    assert isinstance(result["facts"], list)
    assert isinstance(result["inferences"], list)
    for fact in result["facts"]:
        assert set(fact) == {
            "id",
            "label",
            "value",
            "unit",
            "status",
            "availability",
            "source",
        }
        assert isinstance(fact["id"], str)
        assert isinstance(fact["label"], str)
        assert fact["value"] is None or type(fact["value"]) in (str, int, float, bool)
        assert fact["unit"] is None or isinstance(fact["unit"], str)
        assert fact["status"] in {"ok", "warn", "bad", "unknown"}
        assert fact["availability"] in {"observed", "unsupported", "error"}
        assert isinstance(fact["source"], str)


@pytest.mark.parametrize(
    ("free", "used_memory", "disk_status", "memory_status"),
    [
        (20, 79, "warn", "ok"),
        (10, 80, "bad", "warn"),
        (21, 95, "ok", "bad"),
    ],
)
def test_disk_and_memory_facts_use_fixed_thresholds(
    monkeypatch, free, used_memory, disk_status, memory_status
):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(
        checkup.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=100, used=100 - free, free=free),
    )
    monkeypatch.setattr(
        checkup.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=100, available=100 - used_memory, percent=used_memory),
    )

    facts = _facts(checkup.collect())

    assert facts["disk_free_percent"]["status"] == disk_status
    assert facts["memory_used_percent"]["status"] == memory_status


def test_checkup_keeps_unsupported_and_failed_facts_explicit(monkeypatch):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(
        checkup.psutil,
        "disk_usage",
        lambda path: (_ for _ in ()).throw(PermissionError("inaccessible")),
    )
    monkeypatch.setattr(checkup.psutil, "sensors_battery", lambda: None)

    facts = _facts(checkup.collect())

    assert facts["disk_free_percent"]["value"] is None
    assert facts["disk_free_percent"]["status"] == "unknown"
    assert facts["disk_free_percent"]["availability"] == "error"
    assert facts["battery_percent"]["value"] is None
    assert facts["battery_percent"]["status"] == "unknown"
    assert facts["battery_percent"]["availability"] == "unsupported"


def test_windows_print_queue_has_observed_count(monkeypatch):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        checkup,
        "_run_windows_probe",
        lambda name, deadline: {"print_queue_jobs": 3, "print_queue_count": 2},
    )

    facts = _facts(checkup.collect())

    assert facts["print_queue_jobs"]["value"] == 3
    assert facts["print_queue_jobs"]["status"] == "warn"
    assert facts["print_queue_jobs"]["availability"] == "observed"
    assert "2 queues" in facts["print_queue_jobs"]["source"]


@pytest.mark.parametrize("prefix", [b"", b"\xef\xbb\xbf"])
def test_dns_servers_include_first_nameserver_with_or_without_utf8_bom(monkeypatch, tmp_path, prefix):
    resolv = tmp_path / "resolv.conf"
    resolv.write_bytes(prefix + b"nameserver 1.1.1.1\n")
    monkeypatch.setattr(checkup, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(checkup, "Path", lambda path: resolv)

    fact = checkup._dns_servers_fact()

    assert fact["value"] == "1.1.1.1"
    assert fact["availability"] == "observed"


def test_windows_print_queue_slow_probe_is_bounded_and_says_when_unavailable(monkeypatch):
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    monkeypatch.setitem(checkup._WINDOWS_PROBE_TIMEOUTS, "print_queue", 0.05)
    release = threading.Event()

    def slow_probe(name, deadline):
        release.wait()
        return {"print_queue_jobs": 0, "print_queue_count": 2}

    monkeypatch.setattr(checkup, "_run_windows_probe", slow_probe)
    timer = threading.Timer(0.8, release.set)
    timer.start()
    started = time.monotonic()
    try:
        fact = checkup._print_queue_fact(time.monotonic() + 2)
    finally:
        release.set()
        timer.cancel()

    assert time.monotonic() - started < 0.4
    assert fact["value"] == "could not be read in time"
    assert fact["status"] == "unknown"
    assert fact["availability"] == "error"


@pytest.mark.parametrize(
    ("marker_path", "rename_operations"),
    [
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            None,
        ),
        (None, [r"\??\C:\old-file", r"\??\C:\new-file"]),
    ],
)
def test_windows_pending_reboot_reads_registry_markers_without_shell(
    monkeypatch, marker_path, rename_operations
):
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    opened = []
    machine = object()
    session_manager = r"SYSTEM\CurrentControlSet\Control\Session Manager"

    class Key:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def open_key(root, path):
        opened.append(path)
        if path == session_manager or path == marker_path:
            return Key(path)
        raise FileNotFoundError(path)

    def query_value(key, name):
        if key.path == session_manager and name == "PendingFileRenameOperations" and rename_operations:
            return rename_operations, 7
        raise FileNotFoundError(name)

    monkeypatch.setitem(
        sys.modules,
        "winreg",
        SimpleNamespace(HKEY_LOCAL_MACHINE=machine, OpenKey=open_key, QueryValueEx=query_value),
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("shell probe used"))

    fact = checkup._pending_reboot_fact(time.monotonic() + 1)

    assert fact["value"] is True
    assert fact["availability"] == "observed"
    assert "registry markers" in fact["source"]
    if marker_path:
        assert marker_path in opened
    else:
        assert session_manager in opened


def test_windows_pending_reboot_respects_the_checkup_deadline(monkeypatch):
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    release = threading.Event()

    def blocked_registry_read():
        release.wait(0.5)
        return False

    monkeypatch.setattr(checkup, "_read_windows_reboot_markers", blocked_registry_read, raising=False)
    try:
        fact = checkup._pending_reboot_fact(time.monotonic() + 0.05)
    finally:
        release.set()

    assert fact["value"] is None
    assert fact["availability"] == "error"
    assert "TimeoutError" in fact["source"]


def test_windows_pending_update_catalog_is_unsupported_without_a_bounded_query(monkeypatch):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    calls = []

    def run_windows_probe(name, deadline):
        calls.append(name)
        if name == "print_queue":
            return {"print_queue_jobs": 0, "print_queue_count": 2}
        raise TimeoutError("Windows Update Agent search timed out")

    monkeypatch.setattr(checkup, "_run_windows_probe", run_windows_probe)

    fact = _facts(checkup.collect())["pending_updates"]

    assert fact["value"] is None
    assert fact["availability"] == "unsupported"
    assert calls == ["print_queue"]


def test_folder_size_is_unsupported_when_an_entry_is_inaccessible(monkeypatch, tmp_path):
    temp = tmp_path / "Temp"
    temp.mkdir()

    class InaccessibleEntry:
        def is_dir(self, follow_symlinks=False):
            raise PermissionError("entry metadata is inaccessible")

    class Entries:
        def __enter__(self):
            return iter((InaccessibleEntry(),))

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(checkup.os, "scandir", lambda path: Entries())

    size, availability, source = checkup._folder_size(temp, time.monotonic() + 2)

    assert size is None
    assert availability == "unsupported"
    assert "complete size unavailable" in source


def test_linux_print_queue_and_pending_updates_are_explicitly_unsupported(monkeypatch):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(checkup.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        checkup,
        "_run_windows_probe",
        lambda *args, **kwargs: pytest.fail("Windows probe used on Linux"),
    )

    facts = _facts(checkup.collect())

    for fact_id in ("print_queue_jobs", "pending_updates"):
        assert facts[fact_id]["value"] is None
        assert facts[fact_id]["status"] == "unknown"
        assert facts[fact_id]["availability"] == "unsupported"
    assert facts["pending_updates"]["label"] == "Pending software updates"
    assert "Windows" not in facts["pending_updates"]["source"]


def test_windows_print_queue_uses_in_process_probe_without_shell(monkeypatch):
    _quiet_probes(monkeypatch)
    monkeypatch.setattr(checkup.platform, "system", lambda: "Windows")
    calls = []

    def run(probe_name, deadline):
        calls.append(probe_name)
        assert probe_name == "print_queue"
        assert deadline > time.monotonic()
        return {"print_queue_jobs": 0, "print_queue_count": 2}

    monkeypatch.setattr(checkup, "_run_windows_probe", run)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("subprocess used"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("Popen used"))
    monkeypatch.setattr(subprocess, "call", lambda *args, **kwargs: pytest.fail("subprocess.call used"))
    monkeypatch.setattr(checkup.os, "system", lambda *args, **kwargs: pytest.fail("os.system used"))
    monkeypatch.setattr(checkup.os, "popen", lambda *args, **kwargs: pytest.fail("os.popen used"))

    facts = _facts(checkup.collect())

    assert calls == ["print_queue"]
    assert facts["print_queue_jobs"]["availability"] == "observed"
    assert facts["pending_updates"]["availability"] == "unsupported"


def test_process_facts_never_request_or_read_command_lines(monkeypatch):
    _quiet_probes(monkeypatch)
    requested = []

    class Process:
        info = {
            "name": "safe-process.exe",
            "memory_info": SimpleNamespace(rss=1024 * 1024),
        }

        @property
        def cmdline(self):
            raise AssertionError("process command lines must not be read")

    def process_iter(attrs=None):
        requested.extend(attrs or [])
        yield Process()

    monkeypatch.setattr(checkup.psutil, "process_iter", process_iter)

    facts = _facts(checkup.collect())

    assert "cmdline" not in requested
    assert facts["top_process_1"]["value"].startswith("safe-process.exe:")


def test_folder_size_scan_stops_at_its_entry_limit(monkeypatch, tmp_path):
    _quiet_probes(monkeypatch)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    for index in range(10):
        (downloads / f"file-{index}.bin").write_bytes(b"x")
    monkeypatch.setattr(checkup.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(checkup, "MAX_FOLDER_ENTRIES", 3)
    monkeypatch.setattr(checkup, "MAX_FOLDER_SECONDS", 5)

    fact = _facts(checkup.collect())["folder_downloads_bytes"]

    assert 0 < fact["value"] <= 3
    assert fact["status"] == "warn"
    assert fact["availability"] == "observed"
    assert "entry limit" in fact["source"]


def test_checkup_folder_paths_cannot_inject_shell_commands(monkeypatch, tmp_path):
    _quiet_probes(monkeypatch)
    marker = tmp_path / "shell-ran"
    injected_temp = tmp_path / f"temp; touch {marker.name}"
    injected_temp.mkdir()
    monkeypatch.setenv("TEMP", str(injected_temp))
    monkeypatch.setattr(executor, "run", lambda *args, **kwargs: pytest.fail("executor shell used"))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("subprocess shell used"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("subprocess shell used"))
    monkeypatch.setattr(subprocess, "call", lambda *args, **kwargs: pytest.fail("subprocess shell used"))
    monkeypatch.setattr(checkup.os, "system", lambda *args, **kwargs: pytest.fail("OS shell used"))
    monkeypatch.setattr(checkup.os, "popen", lambda *args, **kwargs: pytest.fail("OS shell used"))

    result = checkup.collect()

    assert _facts(result)["folder_temp_bytes"]["availability"] == "observed"
    assert not marker.exists()
