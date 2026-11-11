from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree

from .console import sanitize_text

TASK_NAME = "HermesHands"


def command(*, xml_path: str = "", remove: bool = False) -> list[str]:
    if remove:
        return ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
    return ["schtasks", "/Create", "/XML", xml_path, "/TN", TASK_NAME, "/F"]


def task_xml(*, executable: str, username: str, allow_screen: bool = False) -> bytes:
    task = ElementTree.Element("Task", {"version": "1.4", "xmlns": "http://schemas.microsoft.com/windows/2004/02/mit/task"})
    registration = ElementTree.SubElement(task, "RegistrationInfo")
    ElementTree.SubElement(registration, "URI").text = f"\\{TASK_NAME}"
    triggers = ElementTree.SubElement(task, "Triggers")
    trigger = ElementTree.SubElement(triggers, "LogonTrigger")
    ElementTree.SubElement(trigger, "Enabled").text = "true"
    ElementTree.SubElement(trigger, "UserId").text = username
    principals = ElementTree.SubElement(task, "Principals")
    principal = ElementTree.SubElement(principals, "Principal", {"id": "Author"})
    ElementTree.SubElement(principal, "UserId").text = username
    ElementTree.SubElement(principal, "LogonType").text = "InteractiveToken"
    ElementTree.SubElement(principal, "RunLevel").text = "LeastPrivilege"
    settings = ElementTree.SubElement(task, "Settings")
    ElementTree.SubElement(settings, "MultipleInstancesPolicy").text = "IgnoreNew"
    ElementTree.SubElement(settings, "DisallowStartIfOnBatteries").text = "false"
    ElementTree.SubElement(settings, "StopIfGoingOnBatteries").text = "false"
    ElementTree.SubElement(settings, "ExecutionTimeLimit").text = "PT0S"
    restart = ElementTree.SubElement(settings, "RestartOnFailure")
    ElementTree.SubElement(restart, "Interval").text = "PT1M"
    ElementTree.SubElement(restart, "Count").text = "3"
    actions = ElementTree.SubElement(task, "Actions", {"Context": "Author"})
    exec_action = ElementTree.SubElement(actions, "Exec")
    execute = ElementTree.SubElement(exec_action, "Command")
    execute.text = executable
    ElementTree.SubElement(exec_action, "WorkingDirectory").text = str(Path.home())
    arguments = ElementTree.SubElement(exec_action, "Arguments")
    if allow_screen:
        arguments.text = "-I -m hermeshands_device.cli serve --allow-screen --service"
    else:
        arguments.text = "-I -m hermeshands_device.cli serve --service"
    declaration = '<?xml version="1.0" encoding="UTF-16"?>\n'
    return (declaration + ElementTree.tostring(task, encoding="unicode")).encode("utf-16")


def _scheduler_text(output: bytes) -> str:
    text = re.sub(r"\r+\n", "\n", output.decode("oem", errors="replace"))
    return sanitize_text(text, keep="\n\t").rstrip("\n")


def install(*, dry_run: bool = False, remove: bool = False, allow_screen: bool = False) -> int:
    if "HERMES_HANDS_JOB" in os.environ:
        print("install-service is unavailable from a Hermes Hands device job", file=sys.stderr)
        return 1
    if sys.platform != "win32":
        print("install-service is not supported in v0.2.0 on this platform", file=sys.stderr)
        return 1
    if remove:
        args = command(remove=True)
    else:
        python = Path(sys.executable)
        if not python.is_absolute():
            print("Python executable path is not absolute; cannot install service", file=sys.stderr)
            return 1
        pythonw = python.with_name("pythonw.exe")
        if not pythonw.is_file():
            print("pythonw.exe was not found next to the active Python interpreter", file=sys.stderr)
            return 1
        executable = str(pythonw)
        username = f"{os.environ['USERDOMAIN']}\\{os.environ['USERNAME']}"
        with tempfile.TemporaryDirectory(prefix="hermes-hands-") as temp_dir:
            xml_path = Path(temp_dir) / "task.xml"
            xml_path.write_bytes(task_xml(executable=executable, username=username, allow_screen=allow_screen))
            args = command(xml_path=str(xml_path))
            print(sanitize_text(subprocess.list2cmdline(args), keep="\n\t"))
            if dry_run:
                print(sanitize_text(xml_path.read_text(encoding="utf-16"), keep="\n\t"))
                return 0
            result = subprocess.run(args, check=False, capture_output=True)
            if result.stdout:
                print(_scheduler_text(result.stdout))
            if result.stderr:
                print(_scheduler_text(result.stderr), file=sys.stderr)
            return result.returncode
    print(sanitize_text(subprocess.list2cmdline(args), keep="\n\t"))
    if dry_run:
        return 0
    result = subprocess.run(args, check=False, capture_output=True)
    if result.stdout:
        print(_scheduler_text(result.stdout))
    if result.stderr:
        print(_scheduler_text(result.stderr), file=sys.stderr)
    return result.returncode
