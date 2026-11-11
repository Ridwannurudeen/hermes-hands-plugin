from __future__ import annotations

import os
import platform
import queue
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import psutil

MAX_FOLDER_ENTRIES = 2048
MAX_FOLDER_DEPTH = 8
MAX_FOLDER_SECONDS = 0.5
MAX_PROCESS_SAMPLE = 128
MAX_CHECKUP_SECONDS = 9.0
_DNS_TIMEOUT = 1.0
_REACHABILITY_TIMEOUT = 0.75
_WINDOWS_PROBE_TIMEOUTS = {"print_queue": 1.5}
_WINDOWS_REBOOT_TIMEOUT = 0.5
_WINDOWS_PRINT_PROBE_SLOTS = threading.BoundedSemaphore(1)
_REACHABILITY_TARGETS = (
    ("reachability_cloudflare", "1.1.1.1", 443),
    ("reachability_google", "8.8.8.8", 443),
    ("reachability_quad9", "9.9.9.9", 443),
)
_FOLDER_SCAN_SLOTS = threading.BoundedSemaphore(4)

Status = Literal["ok", "warn", "bad", "unknown"]
Availability = Literal["observed", "unsupported", "error"]


def _fact(
    fact_id: str,
    label: str,
    value: str | int | float | bool | None,
    unit: str | None,
    status: Status,
    availability: Availability,
    source: str,
) -> dict[str, object]:
    return {
        "id": fact_id,
        "label": label,
        "value": value,
        "unit": unit,
        "status": status,
        "availability": availability,
        "source": source,
    }


def _error_fact(fact_id: str, label: str, unit: str | None, source: str, error: Exception) -> dict[str, object]:
    return _fact(
        fact_id,
        label,
        None,
        unit,
        "unknown",
        "error",
        f"{source} ({type(error).__name__})",
    )


def _unsupported_fact(fact_id: str, label: str, unit: str | None, source: str) -> dict[str, object]:
    return _fact(fact_id, label, None, unit, "unknown", "unsupported", source)


def _disk_status(free_percent: float) -> Status:
    if free_percent <= 10:
        return "bad"
    if free_percent <= 20:
        return "warn"
    return "ok"


def _memory_status(used_percent: float) -> Status:
    if used_percent >= 95:
        return "bad"
    if used_percent >= 80:
        return "warn"
    return "ok"


def _disk_facts() -> list[dict[str, object]]:
    try:
        usage = psutil.disk_usage(str(Path.home()))
        if usage.total <= 0:
            raise ValueError("disk total is unavailable")
    except Exception as exc:
        return [
            _error_fact("disk_free_percent", "Device home volume free space", "%", "psutil.disk_usage", exc),
            _error_fact("disk_free_bytes", "Device home volume free space", "bytes", "psutil.disk_usage", exc),
        ]
    free_percent = round(usage.free * 100 / usage.total, 1)
    status = _disk_status(free_percent)
    return [
        _fact(
            "disk_free_percent",
            "Device home volume free space",
            free_percent,
            "%",
            status,
            "observed",
            "psutil.disk_usage",
        ),
        _fact(
            "disk_free_bytes",
            "Device home volume free space",
            int(usage.free),
            "bytes",
            status,
            "observed",
            "psutil.disk_usage",
        ),
    ]


def _memory_facts() -> list[dict[str, object]]:
    try:
        memory = psutil.virtual_memory()
        if memory.total <= 0:
            raise ValueError("memory total is unavailable")
    except Exception as exc:
        return [
            _error_fact("memory_used_percent", "Memory in use", "%", "psutil.virtual_memory", exc),
            _error_fact("memory_available_bytes", "Available memory", "bytes", "psutil.virtual_memory", exc),
        ]
    used_percent = round(float(memory.percent), 1)
    status = _memory_status(used_percent)
    return [
        _fact(
            "memory_used_percent",
            "Memory in use",
            used_percent,
            "%",
            status,
            "observed",
            "psutil.virtual_memory",
        ),
        _fact(
            "memory_available_bytes",
            "Available memory",
            int(memory.available),
            "bytes",
            status,
            "observed",
            "psutil.virtual_memory",
        ),
    ]


def _process_facts(deadline: float) -> list[dict[str, object]]:
    sample: list[tuple[str, int]] = []
    sampled = 0
    limited = False
    failure: Exception | None = None
    try:
        processes = psutil.process_iter(attrs=["name", "memory_info"])
        for process in processes:
            if sampled >= MAX_PROCESS_SAMPLE or time.monotonic() >= deadline:
                limited = True
                break
            sampled += 1
            try:
                info = process.info
                memory_info = info.get("memory_info")
                if memory_info is None:
                    continue
                name = info.get("name") or "unknown process"
                name = "".join(char for char in str(name) if char.isprintable()).strip()[:80]
                sample.append((name or "unknown process", int(memory_info.rss)))
            except (psutil.Error, OSError, AttributeError, KeyError, TypeError) as exc:
                failure = exc
    except Exception as exc:
        failure = exc

    source = f"psutil.process_iter(name,memory_info), sample limit {MAX_PROCESS_SAMPLE}; command lines not requested"
    if limited:
        source += "; sample may be partial"
    if failure is not None:
        source += "; some process records were unavailable"
    if failure is not None and not sample:
        return [
            _error_fact("top_process_count", "Sampled process count", "processes", source, failure),
            *[
                _error_fact(f"top_process_{index}", f"Top process {index}", None, source, failure)
                for index in range(1, 6)
            ],
        ]

    sample.sort(key=lambda item: item[1], reverse=True)
    availability: Availability = "error" if failure is not None else "observed"
    facts = [
        _fact(
            "top_process_count",
            "Sampled process count",
            len(sample),
            "processes",
            "unknown",
            availability,
            source,
        )
    ]
    for index in range(1, 6):
        if index <= len(sample):
            name, resident_bytes = sample[index - 1]
            value = f"{name}: {resident_bytes / (1024 * 1024):.1f} MiB resident memory"
            facts.append(
                _fact(f"top_process_{index}", f"Top process {index}", value, None, "unknown", availability, source)
            )
        else:
            facts.append(
                _unsupported_fact(f"top_process_{index}", f"Top process {index}", None, source)
            )
    return facts


def _scan_folder_size(path: Path, probe_deadline: float) -> tuple[int | None, Availability, str]:
    source = "bounded in-process directory traversal"
    try:
        if path.is_symlink():
            return None, "unsupported", f"{source}; folder is a symbolic link"
        if not path.is_dir():
            return None, "unsupported", f"{source}; folder is unavailable"
    except OSError as exc:
        return None, "error", f"{source} ({type(exc).__name__})"

    total = 0
    visited = 0
    stack = [(path, 0)]
    limited = False
    failed = False
    while stack:
        if time.monotonic() >= probe_deadline:
            limited = True
            break
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if visited >= MAX_FOLDER_ENTRIES or time.monotonic() >= probe_deadline:
                        limited = True
                        break
                    visited += 1
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if depth >= MAX_FOLDER_DEPTH:
                                limited = True
                            else:
                                stack.append((Path(entry.path), depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        failed = True
                if limited:
                    break
        except OSError:
            failed = True

    if limited:
        source += "; entry limit or traversal time/depth bound reached"
    if failed:
        source += "; some entries were inaccessible; complete size unavailable"
        return None, "unsupported", source
    return total, "observed", source


def _folder_size(path: Path, deadline: float) -> tuple[int | None, Availability, str]:
    source = "bounded in-process directory traversal"
    probe_budget = min(MAX_FOLDER_SECONDS, deadline - time.monotonic())
    if probe_budget <= 0:
        return None, "error", f"{source}; total checkup time budget expired"
    if not _FOLDER_SCAN_SLOTS.acquire(blocking=False):
        return None, "error", f"{source}; folder scan worker limit reached"
    result: queue.Queue[tuple[int | None, Availability, str]] = queue.Queue(maxsize=1)

    def scan() -> None:
        try:
            result.put(_scan_folder_size(path, time.monotonic() + probe_budget))
        except Exception as exc:
            result.put((None, "error", f"{source} ({type(exc).__name__})"))
        finally:
            _FOLDER_SCAN_SLOTS.release()

    threading.Thread(target=scan, name="hermes-hands-checkup-folder", daemon=True).start()
    try:
        return result.get(timeout=probe_budget)
    except queue.Empty:
        return None, "error", f"{source}; per-folder time budget expired"


def _folder_facts(deadline: float) -> list[dict[str, object]]:
    home = Path.home()
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or os.environ.get("TMPDIR") or tempfile.gettempdir()
    folders = (
        ("folder_temp_bytes", "TEMP folder size", Path(temp)),
        ("folder_downloads_bytes", "Downloads folder size", home / "Downloads"),
        ("folder_desktop_bytes", "Desktop folder size", home / "Desktop"),
        ("folder_documents_bytes", "Documents folder size", home / "Documents"),
    )
    facts = []
    for fact_id, label, path in folders:
        size, availability, source = _folder_size(path, deadline)
        status: Status = "warn" if "; entry limit" in source else "unknown"
        if availability == "error":
            status = "unknown"
        elif availability == "unsupported":
            facts.append(_unsupported_fact(fact_id, label, "bytes", source))
            continue
        facts.append(_fact(fact_id, label, size, "bytes", status, availability, source))
    return facts


def _wifi_fact() -> dict[str, object]:
    metadata_error: Exception | None = None
    try:
        interfaces = psutil.net_if_stats()
        names = {
            name
            for name in interfaces
            if any(marker in name.casefold() for marker in ("wi-fi", "wifi", "wlan", "wireless"))
        }
        if platform.system() == "Linux":
            try:
                names.update(
                    item.name
                    for item in Path("/sys/class/net").iterdir()
                    if (item / "wireless").exists()
                )
            except OSError as exc:
                metadata_error = exc
        if not names:
            if metadata_error is not None:
                return _error_fact(
                    "wifi_status", "Wi-Fi interface status", None, "Linux wireless metadata", metadata_error
                )
            return _unsupported_fact(
                "wifi_status", "Wi-Fi interface status", None, "psutil interfaces and Linux wireless metadata"
            )
        values = []
        up = False
        for name in sorted(names):
            stats = interfaces.get(name)
            state = "connected" if stats is not None and stats.isup else "disconnected"
            up = up or state == "connected"
            values.append(f"{name}: {state}")
        return _fact(
            "wifi_status",
            "Wi-Fi interface status",
            "; ".join(values),
            None,
            "ok" if up else "warn",
            "observed",
            "psutil interfaces and Linux wireless metadata",
        )
    except Exception as exc:
        return _error_fact("wifi_status", "Wi-Fi interface status", None, "psutil.net_if_stats", exc)


def _dns_tokens(value: object) -> list[str]:
    if isinstance(value, str):
        return value.replace(",", " ").split()
    if isinstance(value, (tuple, list)):
        return [token for part in value if isinstance(part, str) for token in _dns_tokens(part)]
    return []


def _dns_servers_fact() -> dict[str, object]:
    servers: list[str] = []
    if os.name == "nt":
        try:
            import winreg

            root_paths = (
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
            )
            for root_path in root_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path) as key:
                        for value_name in ("NameServer", "DhcpNameServer"):
                            try:
                                value, _ = winreg.QueryValueEx(key, value_name)
                            except FileNotFoundError:
                                continue
                            servers.extend(_dns_tokens(value))
                except FileNotFoundError:
                    continue
                interface_path = root_path + r"\Interfaces"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interface_path) as interfaces:
                        for index in range(128):
                            try:
                                interface_name = winreg.EnumKey(interfaces, index)
                            except OSError as exc:
                                if getattr(exc, "winerror", None) == 259:
                                    break
                                raise
                            try:
                                with winreg.OpenKey(interfaces, interface_name) as interface:
                                    for value_name in ("NameServer", "DhcpNameServer"):
                                        try:
                                            value, _ = winreg.QueryValueEx(interface, value_name)
                                        except FileNotFoundError:
                                            continue
                                        servers.extend(_dns_tokens(value))
                            except FileNotFoundError:
                                continue
                except FileNotFoundError:
                    continue
        except ImportError:
            return _unsupported_fact("dns_servers", "Configured DNS servers", None, "Windows DNS registry API")
        except OSError as exc:
            return _error_fact("dns_servers", "Configured DNS servers", None, "Windows DNS registry", exc)
        source = "Windows TCP/IP DNS registry; at most 128 interfaces sampled"
    else:
        path = Path("/etc/resolv.conf")
        try:
            for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                fields = line.split("#", 1)[0].split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    servers.append(fields[1])
        except FileNotFoundError:
            return _unsupported_fact("dns_servers", "Configured DNS servers", None, "/etc/resolv.conf is unavailable")
        except OSError as exc:
            return _error_fact("dns_servers", "Configured DNS servers", None, "/etc/resolv.conf", exc)
        source = "/etc/resolv.conf nameserver entries"

    unique = list(dict.fromkeys(server.strip()[:128] for server in servers if server.strip()))[:16]
    value = ", ".join(unique)
    return _fact(
        "dns_servers",
        "Configured DNS servers",
        value,
        None,
        "ok" if unique else "unknown",
        "observed",
        source,
    )


def _dns_resolution_fact(deadline: float) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _error_fact(
            "dns_resolution", "Fixed DNS lookup", None, "socket.getaddrinfo(example.com:443)", TimeoutError()
        )
    result: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put((True, socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))

    threading.Thread(target=resolve, name="hermes-hands-checkup-dns", daemon=True).start()
    try:
        succeeded, value = result.get(timeout=min(_DNS_TIMEOUT, remaining))
    except queue.Empty:
        return _error_fact(
            "dns_resolution", "Fixed DNS lookup", None, "socket.getaddrinfo(example.com:443)", TimeoutError()
        )
    if not succeeded:
        error = value if isinstance(value, Exception) else RuntimeError("DNS lookup failed")
        return _error_fact("dns_resolution", "Fixed DNS lookup", None, "socket.getaddrinfo(example.com:443)", error)
    resolved = bool(value)
    return _fact(
        "dns_resolution",
        "Fixed DNS lookup",
        resolved,
        None,
        "ok" if resolved else "warn",
        "observed",
        "socket.getaddrinfo(example.com:443)",
    )


def _reachability_facts(deadline: float) -> list[dict[str, object]]:
    facts = []
    for fact_id, address, port in _REACHABILITY_TARGETS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            facts.append(
                _error_fact(fact_id, f"Reachability to {address}", None, "fixed TCP connect probe", TimeoutError())
            )
            continue
        try:
            with socket.create_connection((address, port), timeout=min(_REACHABILITY_TIMEOUT, remaining)):
                reachable = True
        except OSError:
            reachable = False
        facts.append(
            _fact(
                fact_id,
                f"Reachability to {address}",
                reachable,
                None,
                "ok" if reachable else "warn",
                "observed",
                f"fixed TCP connect probe to {address}:{port}",
            )
        )
    return facts


def _run_windows_probe(probe_name: str, deadline: float) -> dict[str, int]:
    if probe_name != "print_queue":
        raise ValueError("unknown Windows checkup probe")
    if time.monotonic() >= deadline:
        raise TimeoutError("checkup time budget expired")
    import ctypes
    from ctypes import wintypes

    class PrinterInfo2(ctypes.Structure):
        _fields_ = [
            ("pServerName", wintypes.LPWSTR),
            ("pPrinterName", wintypes.LPWSTR),
            ("pShareName", wintypes.LPWSTR),
            ("pPortName", wintypes.LPWSTR),
            ("pDriverName", wintypes.LPWSTR),
            ("pComment", wintypes.LPWSTR),
            ("pLocation", wintypes.LPWSTR),
            ("pDevMode", ctypes.c_void_p),
            ("pSepFile", wintypes.LPWSTR),
            ("pPrintProcessor", wintypes.LPWSTR),
            ("pDatatype", wintypes.LPWSTR),
            ("pParameters", wintypes.LPWSTR),
            ("pSecurityDescriptor", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
            ("Priority", wintypes.DWORD),
            ("DefaultPriority", wintypes.DWORD),
            ("StartTime", wintypes.DWORD),
            ("UntilTime", wintypes.DWORD),
            ("Status", wintypes.DWORD),
            ("cJobs", wintypes.DWORD),
            ("AveragePPM", wintypes.DWORD),
        ]

    enum_printers = ctypes.WinDLL("winspool.drv", use_last_error=True).EnumPrintersW
    enum_printers.argtypes = [
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    enum_printers.restype = wintypes.BOOL

    flags = 0x00000002 | 0x00000004
    needed = wintypes.DWORD()
    returned = wintypes.DWORD()
    succeeded = enum_printers(
        flags, None, 2, None, 0, ctypes.byref(needed), ctypes.byref(returned)
    )
    error = ctypes.get_last_error()
    if not succeeded and error not in (0, 122):
        raise ctypes.WinError(error)
    if needed.value == 0:
        return {"print_queue_jobs": 0, "print_queue_count": 0}

    buffer = ctypes.create_string_buffer(needed.value)
    if not enum_printers(
        flags, None, 2, buffer, needed.value, ctypes.byref(needed), ctypes.byref(returned)
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    printers = ctypes.cast(buffer, ctypes.POINTER(PrinterInfo2))
    count = int(returned.value)
    jobs = sum(int(printers[index].cJobs) for index in range(count))
    return {"print_queue_jobs": jobs, "print_queue_count": count}


def _print_queue_fact(deadline: float) -> dict[str, object]:
    fact_id = "print_queue_jobs"
    label = "Print queue job count"
    if platform.system() != "Windows":
        return _unsupported_fact(
            fact_id,
            label,
            "jobs",
            "Windows PrintManagement is unavailable on Linux; WSL does not expose Windows print queues",
        )
    source = "Windows Winspool EnumPrintersW level 2; only queue and job counts are retained"
    timeout = min(_WINDOWS_PROBE_TIMEOUTS["print_queue"], deadline - time.monotonic())

    def timeout_fact(reason: str) -> dict[str, object]:
        return _fact(
            fact_id,
            label,
            "could not be read in time",
            "jobs",
            "unknown",
            "error",
            f"{source}; {reason}",
        )

    if timeout <= 0:
        return timeout_fact("overall checkup time budget expired")
    if not _WINDOWS_PRINT_PROBE_SLOTS.acquire(blocking=False):
        return timeout_fact("a previous print queue probe is still running")

    result_queue: queue.Queue[tuple[bool, dict[str, int] | Exception]] = queue.Queue(maxsize=1)

    def probe() -> None:
        try:
            outcome = (True, _run_windows_probe("print_queue", deadline))
        except Exception as exc:
            outcome = (False, exc)
        finally:
            _WINDOWS_PRINT_PROBE_SLOTS.release()
        result_queue.put(outcome)

    worker = threading.Thread(target=probe, name="hermes-hands-checkup-print-queue", daemon=True)
    try:
        worker.start()
    except RuntimeError as exc:
        _WINDOWS_PRINT_PROBE_SLOTS.release()
        return _error_fact(fact_id, label, "jobs", source, exc)
    try:
        succeeded, value = result_queue.get(timeout=timeout)
    except queue.Empty:
        return timeout_fact("probe did not finish within its time budget")
    if not succeeded:
        error = value if isinstance(value, Exception) else RuntimeError("Windows print queue probe failed")
        if isinstance(error, TimeoutError):
            return timeout_fact("probe time budget expired")
        return _error_fact(fact_id, label, "jobs", source, error)
    result = value
    if not isinstance(result, dict):
        return _error_fact(fact_id, label, "jobs", source, ValueError("invalid Windows print queue result"))
    jobs = result["print_queue_jobs"]
    queues = result["print_queue_count"]
    status: Status = "warn" if jobs > 0 or queues == 0 else "ok"
    queue_word = "queue" if queues == 1 else "queues"
    return _fact(fact_id, label, jobs, "jobs", status, "observed", f"{source}; {queues} {queue_word} queried")


def _uptime_fact() -> dict[str, object]:
    try:
        boot_time = psutil.boot_time()
        uptime_days = max(0.0, (time.time() - boot_time) / 86400)
    except Exception as exc:
        return _error_fact("uptime_days", "System uptime", "days", "psutil.boot_time", exc)
    status: Status = "warn" if uptime_days >= 30 else "ok"
    return _fact(
        "uptime_days",
        "System uptime",
        round(uptime_days, 1),
        "days",
        status,
        "observed",
        "psutil.boot_time and system clock",
    )


def _read_windows_reboot_markers() -> bool:
    import winreg

    markers = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
    )
    for root, path in markers:
        try:
            with winreg.OpenKey(root, path):
                return True
        except FileNotFoundError:
            continue

    value = None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
        ) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "PendingFileRenameOperations")
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass
    return bool(value)


def _pending_reboot_fact(deadline: float) -> dict[str, object]:
    if platform.system() == "Windows":
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _error_fact(
                "pending_reboot", "Known pending reboot marker", None, "Windows reboot registry markers", TimeoutError()
            )

        result: queue.Queue[tuple[bool, bool | Exception]] = queue.Queue(maxsize=1)

        def read_markers() -> None:
            try:
                result.put((True, _read_windows_reboot_markers()))
            except Exception as exc:
                result.put((False, exc))

        threading.Thread(target=read_markers, name="hermes-hands-checkup-reboot", daemon=True).start()
        try:
            succeeded, value = result.get(timeout=min(_WINDOWS_REBOOT_TIMEOUT, remaining))
        except queue.Empty:
            return _error_fact(
                "pending_reboot", "Known pending reboot marker", None, "Windows reboot registry markers", TimeoutError()
            )
        if not succeeded:
            error = value if isinstance(value, Exception) else RuntimeError("Windows registry read failed")
            if isinstance(error, ImportError):
                return _unsupported_fact("pending_reboot", "Known pending reboot marker", None, "Windows registry API")
            return _error_fact(
                "pending_reboot", "Known pending reboot marker", None, "Windows reboot registry markers", error
            )
        pending = bool(value)
        source = "Windows servicing and update reboot registry markers, including pending file rename operations"
    elif platform.system() == "Linux":
        markers = (Path("/var/run/reboot-required"), Path("/run/reboot-required"))
        try:
            pending = any(marker.is_file() for marker in markers)
        except OSError as exc:
            return _error_fact("pending_reboot", "Known pending reboot marker", None, "Linux reboot marker files", exc)
        source = "/var/run/reboot-required and /run/reboot-required"
    else:
        return _unsupported_fact("pending_reboot", "Known pending reboot marker", None, "No in-process reboot marker for this platform")
    return _fact(
        "pending_reboot",
        "Known pending reboot marker",
        pending,
        None,
        "warn" if pending else "ok",
        "observed",
        source,
    )


def _pending_updates_fact() -> dict[str, object]:
    fact_id = "pending_updates"
    label = "Pending Windows software updates"
    if platform.system() == "Windows":
        source = "No bounded in-process Windows Update catalog query is available; known reboot markers are reported separately"
    else:
        label = "Pending software updates"
        source = "Software update checks depend on this operating system and are not queried by this device checkup"
    return _unsupported_fact(fact_id, label, "updates", source)


def _battery_facts() -> list[dict[str, object]]:
    try:
        battery = psutil.sensors_battery()
    except Exception as exc:
        return [
            _error_fact("battery_percent", "Battery charge", "%", "psutil.sensors_battery", exc),
            _error_fact("battery_charging", "Battery charging", None, "psutil.sensors_battery", exc),
        ]
    if battery is None:
        return [
            _unsupported_fact("battery_percent", "Battery charge", "%", "psutil.sensors_battery reports no battery"),
            _unsupported_fact("battery_charging", "Battery charging", None, "psutil.sensors_battery reports no battery"),
        ]
    percent = battery.percent
    plugged = battery.power_plugged
    if percent is None:
        percent_status: Status = "unknown"
        percent_availability: Availability = "unsupported"
    else:
        percent_status = "bad" if percent <= 10 and not plugged else "warn" if percent <= 20 and not plugged else "ok"
        percent_availability = "observed"
    charging_availability: Availability = "observed" if plugged is not None else "unsupported"
    return [
        _fact(
            "battery_percent",
            "Battery charge",
            None if percent is None else round(float(percent), 1),
            "%",
            percent_status,
            percent_availability,
            "psutil.sensors_battery",
        ),
        _fact(
            "battery_charging",
            "Battery charging",
            None if plugged is None else bool(plugged),
            None,
            "unknown" if plugged is None else "ok",
            charging_availability,
            "psutil.sensors_battery",
        ),
    ]


def _directory_entry_count(path: Path, limit: int) -> tuple[int, bool, Exception | None]:
    try:
        if not path.is_dir():
            return 0, False, None
        count = 0
        with os.scandir(path) as entries:
            for _ in entries:
                if count >= limit:
                    return count, True, None
                count += 1
        return count, False, None
    except OSError as exc:
        return 0, False, exc


def _startup_item_fact() -> dict[str, object]:
    if os.name == "nt":
        local = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
        common = Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
        directories = (local, common)
        try:
            import winreg

            registry_keys = (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            )
            registry_count = 0
            for root, path in registry_keys:
                try:
                    with winreg.OpenKey(root, path) as key:
                        registry_count += min(winreg.QueryInfoKey(key)[1], 128)
                except FileNotFoundError:
                    continue
        except ImportError:
            return _unsupported_fact("startup_item_count", "Startup item count", "items", "Windows registry API")
        except OSError as exc:
            return _error_fact("startup_item_count", "Startup item count", "items", "Windows Run registry keys", exc)
        source = "Windows Startup folders and Run registry value names; command values not read"
    elif platform.system() == "Linux":
        directories = (Path.home() / ".config/autostart", Path("/etc/xdg/autostart"))
        registry_count = 0
        source = "Linux XDG autostart directory entries"
    elif platform.system() == "Darwin":
        directories = (Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"))
        registry_count = 0
        source = "macOS LaunchAgents directory entries"
    else:
        return _unsupported_fact("startup_item_count", "Startup item count", "items", "No startup item source for this platform")

    count = registry_count
    partial = False
    failure = None
    for directory in directories:
        found, limited, error = _directory_entry_count(directory, 256)
        count += found
        partial = partial or limited
        failure = failure or error
    if partial:
        source += "; directory entry limit reached"
    if failure is not None and count == 0:
        return _error_fact("startup_item_count", "Startup item count", "items", source, failure)
    availability: Availability = "error" if failure is not None else "observed"
    return _fact("startup_item_count", "Startup item count", count, "items", "unknown", availability, source)


def collect() -> dict[str, object]:
    started = time.monotonic()
    deadline = started + MAX_CHECKUP_SECONDS
    facts: list[dict[str, object]] = []
    facts.extend(_disk_facts())
    facts.extend(_memory_facts())
    facts.extend(_process_facts(deadline))
    facts.append(_print_queue_fact(deadline))
    facts.append(_pending_updates_fact())
    facts.extend(_folder_facts(deadline))
    facts.append(_wifi_fact())
    facts.append(_dns_servers_fact())
    facts.append(_dns_resolution_fact(deadline))
    facts.extend(_reachability_facts(deadline))
    facts.append(_uptime_fact())
    facts.append(_pending_reboot_fact(deadline))
    facts.extend(_battery_facts())
    facts.append(_startup_item_fact())
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "observed_at": observed_at,
        "platform": platform.platform(),
        "facts": facts,
        "inferences": [],
    }
