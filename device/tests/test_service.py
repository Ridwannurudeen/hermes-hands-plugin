import shutil
import subprocess
from xml.etree import ElementTree

from hermeshands_device import service


def _set_python_interpreter(monkeypatch, tmp_path):
    interpreter = tmp_path / "A User" / "Scripts" / "python.exe"
    interpreter.parent.mkdir(parents=True)
    pythonw = interpreter.with_name("pythonw.exe")
    pythonw.write_bytes(b"")
    monkeypatch.setattr(service.sys, "executable", str(interpreter))
    return pythonw


def test_install_service_calls_schtasks_with_xml(monkeypatch, tmp_path):
    monkeypatch.setattr(service.sys, "platform", "win32")
    _set_python_interpreter(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "A User"})
    monkeypatch.setattr(service.Path, "home", lambda: service.Path(r"C:\Users\A User"))
    calls = []
    monkeypatch.setattr(service.subprocess, "run", lambda args, check: calls.append((args, check)) or subprocess.CompletedProcess(args, 0))
    assert service.install() == 0
    assert calls[0][0][:3] == ["schtasks", "/Create", "/XML"]
    assert calls[0][0][3].endswith("task.xml")
    assert calls[0][0][-3:] == ["/TN", "HermesHands", "/F"]
    assert calls[0][1] is False


def test_install_service_uses_absolute_pythonw_and_ignores_cwd_command(monkeypatch, tmp_path):
    monkeypatch.setattr(service.sys, "platform", "win32")
    pythonw = _set_python_interpreter(monkeypatch, tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: "hermes-hands.exe")
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "A User"})
    monkeypatch.setattr(service.Path, "home", lambda: service.Path(r"C:\Users\A User"))
    calls = []

    def run(args, check):
        xml = ElementTree.fromstring(service.Path(args[3]).read_bytes())
        calls.append((args, check, xml))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(service.subprocess, "run", run)
    assert service.install() == 0
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    command = calls[0][2].findtext("t:Actions/t:Exec/t:Command", namespaces=ns)
    arguments = calls[0][2].findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns)
    assert command == str(pythonw)
    assert service.Path(command).is_absolute()
    assert arguments == "-I -m hermeshands_device.cli serve --service"


def test_install_service_dry_run_prints_command_without_running(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(service.sys, "platform", "win32")
    pythonw = _set_python_interpreter(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "A User"})
    monkeypatch.setattr(service.Path, "home", lambda: service.Path(r"C:\Users\A User"))
    monkeypatch.setattr(service.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run")))
    assert service.install(dry_run=True) == 0
    output = capsys.readouterr().out
    assert 'schtasks /Create /XML ' in output
    assert "DisallowStartIfOnBatteries" in output and ">false<" in output
    assert "StopIfGoingOnBatteries" in output
    assert "ExecutionTimeLimit" in output and ">PT0S<" in output
    assert "RestartOnFailure" in output and "<Count>3</Count>" in output
    assert "LAPTOP\\A User" in output
    assert str(pythonw) in output
    assert "-I -m hermeshands_device.cli serve --service" in output


def test_install_service_passes_allow_screen_to_task(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(service.sys, "platform", "win32")
    pythonw = _set_python_interpreter(monkeypatch, tmp_path)
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "user"})
    monkeypatch.setattr(service.Path, "home", lambda: service.Path(r"C:\Users\user"))
    assert service.install(dry_run=True, allow_screen=True) == 0
    output = capsys.readouterr().out
    assert str(pythonw) in output
    assert "-I -m hermeshands_device.cli serve --allow-screen --service" in output


def test_install_service_refuses_relative_python_executable(monkeypatch, capsys):
    monkeypatch.setattr(service.sys, "platform", "win32")
    monkeypatch.setattr(service.sys, "executable", "python.exe")
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "user"})
    assert service.install(dry_run=True) == 1
    assert "absolute" in capsys.readouterr().err.lower()


def test_install_service_refuses_without_pythonw(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(service.sys, "platform", "win32")
    interpreter = tmp_path / "Scripts" / "python.exe"
    interpreter.parent.mkdir()
    monkeypatch.setattr(service.sys, "executable", str(interpreter))
    monkeypatch.setattr(service.os, "environ", {"USERDOMAIN": "LAPTOP", "USERNAME": "user"})
    assert service.install(dry_run=True) == 1
    assert "pythonw.exe" in capsys.readouterr().err


def test_remove_service_command(monkeypatch):
    monkeypatch.setattr(service.sys, "platform", "win32")
    calls = []
    monkeypatch.setattr(service.subprocess, "run", lambda args, check: calls.append(args) or subprocess.CompletedProcess(args, 0))
    assert service.install(remove=True) == 0
    assert calls == [["schtasks", "/Delete", "/TN", "HermesHands", "/F"]]


def test_task_xml_has_current_user_logon_and_unlimited_restartable_settings():
    xml = service.task_xml(executable=r"C:\Program Files\pythonw.exe", username="LAPTOP\\A User")
    root = ElementTree.fromstring(xml)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert root.findtext("t:Triggers/t:LogonTrigger/t:UserId", namespaces=ns) == "LAPTOP\\A User"
    assert root.findtext("t:Principals/t:Principal/t:UserId", namespaces=ns) == "LAPTOP\\A User"
    assert root.findtext("t:Settings/t:DisallowStartIfOnBatteries", namespaces=ns) == "false"
    assert root.findtext("t:Settings/t:StopIfGoingOnBatteries", namespaces=ns) == "false"
    assert root.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=ns) == "PT0S"
    assert root.findtext("t:Settings/t:RestartOnFailure/t:Count", namespaces=ns) == "3"
    assert root.findtext("t:Actions/t:Exec/t:Command", namespaces=ns) == r"C:\Program Files\pythonw.exe"
    assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns) == "-I -m hermeshands_device.cli serve --service"
    assert root.findtext("t:Actions/t:Exec/t:WorkingDirectory", namespaces=ns) == str(service.Path.home())


def test_task_xml_uses_utf16_bom_and_declaration():
    xml = service.task_xml(executable="hermes-hands.exe", username="LAPTOP\\A User")
    assert xml.startswith(b"\xff\xfe")
    assert '<?xml version="1.0" encoding="UTF-16"?>' in xml.decode("utf-16")


def test_install_service_refuses_non_windows(monkeypatch, capsys):
    monkeypatch.setattr(service.sys, "platform", "linux")
    assert service.install() == 1
    assert "not supported in v0.2.0" in capsys.readouterr().err


def test_install_service_refuses_from_device_job(monkeypatch, capsys):
    monkeypatch.setenv("HERMES_HANDS_JOB", "1")
    monkeypatch.setattr(service.sys, "platform", "win32")
    monkeypatch.setattr(service.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scheduler must not run")))

    assert service.install() == 1

    assert "device job" in capsys.readouterr().err
