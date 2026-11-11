import os
import builtins
import importlib
import sys
import tomllib
import types
from pathlib import Path

import pytest

from hermeshands_device import config, keys, receipt, screen
from hermeshands_device.protocol import generate_keypair


def test_posix_file_key_is_created_private_before_writing(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    calls = []
    real_open = os.open

    def private_open(path, flags, mode=0o777):
        calls.append((path, flags, mode))
        return real_open(path, flags, mode)

    monkeypatch.setattr(keys, "os", types.SimpleNamespace(**{**vars(os), "name": "posix", "open": private_open}))
    keys.get_or_create()
    [(path, flags, mode)] = calls
    assert Path(path).parent == tmp_path and Path(path) != config.KEY_PATH
    assert (flags, mode) == (os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    assert config.KEY_PATH.exists() and not Path(path).exists()


def test_posix_key_write_interrupted_before_the_rename_leaves_no_key_file(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")

    def full_disk(fd, *args, **kwargs):
        os.close(fd)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(keys, "os", types.SimpleNamespace(**{**vars(os), "name": "posix", "fdopen": full_disk}))
    with pytest.raises(OSError, match="No space left"):
        keys.get_or_create()
    assert not config.KEY_PATH.exists()
    assert list(tmp_path.iterdir()) == []
    monkeypatch.setattr(keys, "os", types.SimpleNamespace(**{**vars(os), "name": "posix"}))
    private, public = keys.get_or_create()
    assert keys.get_or_create() == (private, public)


def test_file_key_fallback_is_private_on_posix(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    private, public = keys.get_or_create()
    assert len(private) == len(public) == 32
    assert keys.get_or_create() == (private, public)
    if os.name != "nt":
        assert config.KEY_PATH.stat().st_mode & 0o777 == 0o600


def test_keyring_backend_error_refuses_to_mint_a_new_key(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    monkeypatch.setattr(sys, "stderr", None)

    class KeyringError(Exception):
        pass

    class BrokenKeyring:
        errors = types.SimpleNamespace(KeyringError=KeyringError)

        @staticmethod
        def get_password(service, username):
            raise KeyringError("no backend")

        @staticmethod
        def set_password(service, username, password):
            raise KeyringError("no backend")

    monkeypatch.setattr(keys, "_keyring", lambda: BrokenKeyring)
    with pytest.raises(RuntimeError, match="refusing to create a new device identity"):
        keys.get_or_create()
    assert not config.KEY_PATH.exists()
    log = tmp_path / "out" / "device.log"
    contents = log.read_text(encoding="utf-8-sig")
    assert "device key" in contents
    assert "RuntimeError" in contents


def test_non_keyring_error_while_loading_key_refuses_to_mint_a_new_key(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")

    class KeyringError(Exception):
        pass

    class BrokenKeyring:
        errors = types.SimpleNamespace(KeyringError=KeyringError)

        @staticmethod
        def get_password(service, username):
            raise RuntimeError("keyring backend failed unexpectedly")

    monkeypatch.setattr(keys, "_keyring", lambda: BrokenKeyring)
    with pytest.raises(RuntimeError, match="refusing to create a new device identity"):
        keys.get_or_create()
    assert not config.KEY_PATH.exists()


def test_existing_file_key_is_authoritative_when_keyring_appears(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    original = keys.get_or_create()

    class WorkingKeyring:
        errors = types.SimpleNamespace(KeyringError=Exception)

        @staticmethod
        def get_password(service, username):
            raise AssertionError("file key should be checked first")

    monkeypatch.setattr(keys, "_keyring", lambda: WorkingKeyring)
    assert keys.get_or_create() == original


def test_working_keyring_remains_in_use(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    stored = {}

    class WorkingKeyring:
        errors = types.SimpleNamespace(KeyringError=Exception)

        @staticmethod
        def get_password(service, username):
            return stored.get((service, username))

        @staticmethod
        def set_password(service, username, password):
            stored[(service, username)] = password

    monkeypatch.setattr(keys, "_keyring", lambda: WorkingKeyring)
    pair = keys.get_or_create()
    assert keys.get_or_create() == pair
    assert not config.KEY_PATH.exists()
    assert stored


def test_keyring_set_error_falls_back_to_file(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")

    class KeyringError(Exception):
        pass

    class WriteFailingKeyring:
        errors = types.SimpleNamespace(KeyringError=KeyringError)

        @staticmethod
        def get_password(service, username):
            return None

        @staticmethod
        def set_password(service, username, password):
            raise KeyringError("read only backend")

    monkeypatch.setattr(keys, "_keyring", lambda: WriteFailingKeyring)
    pair = keys.get_or_create()
    assert config.KEY_PATH.exists()
    assert keys.get_or_create() == pair


def test_non_keyring_error_while_saving_key_falls_back_to_file(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")

    class KeyringError(Exception):
        pass

    class BrokenKeyring:
        errors = types.SimpleNamespace(KeyringError=KeyringError)

        @staticmethod
        def get_password(service, username):
            return None

        @staticmethod
        def set_password(service, username, password):
            raise RuntimeError("keyring backend failed unexpectedly")

    monkeypatch.setattr(keys, "_keyring", lambda: BrokenKeyring)
    pair = keys.get_or_create()
    assert config.KEY_PATH.exists()
    assert keys.get_or_create() == pair
    assert "using protected device key file" in caplog.text


def test_screen_requires_explicit_flag():
    with pytest.raises(PermissionError, match="serve --allow-screen"):
        screen.capture(allow_screen=False)


def test_screenshot_dependencies_are_default_and_loaded_only_for_capture(monkeypatch):
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8-sig"))["project"]
    assert "mss>=9,<11" in project["dependencies"]
    assert "Pillow>=10,<14" in project["dependencies"]
    assert "screen" not in project["optional-dependencies"]
    imported = builtins.__import__

    def without_screen(name, *args, **kwargs):
        if name in ("mss", "PIL"):
            raise ImportError("screenshot packages are not installed")
        return imported(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_screen)
    importlib.reload(screen)
    with pytest.raises(PermissionError, match="serve --allow-screen"):
        screen.capture(allow_screen=False)
    with pytest.raises(RuntimeError, match="Reinstall hermes-hands"):
        screen.capture(allow_screen=True)


class _FakeCapture:
    monitors = [None, object()]
    shot = types.SimpleNamespace(size=(2, 2), rgb=bytes(12))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def grab(self, monitor):
        assert monitor is self.monitors[1]
        return self.shot


def test_screen_capture_uses_pillow_png_methods(monkeypatch):
    calls = []

    class Image:
        @staticmethod
        def frombytes(mode, size, data):
            calls.append(("frombytes", mode, size, data))
            return Image()

        def thumbnail(self, size):
            calls.append(("thumbnail", size))

        def save(self, output, **kwargs):
            calls.append(("save", kwargs))
            output.write(b"\x89PNG\r\n\x1a\nfake")

    monkeypatch.setitem(sys.modules, "mss", types.SimpleNamespace(mss=_FakeCapture))
    monkeypatch.setitem(sys.modules, "mss.exception", types.SimpleNamespace(ScreenShotError=RuntimeError))
    monkeypatch.setitem(sys.modules, "PIL", types.SimpleNamespace(Image=Image))
    monkeypatch.setitem(sys.modules, "PIL.Image", Image)

    assert screen.unavailable() is None
    assert screen.capture(allow_screen=True) == b"\x89PNG\r\n\x1a\nfake"
    assert calls == [
        ("frombytes", "RGB", (2, 2), bytes(12)),
        ("thumbnail", (screen.MAX_EDGE, screen.MAX_EDGE)),
        ("save", {"format": "PNG", "optimize": True}),
    ]


def test_screen_capture_encodes_a_real_png_when_the_extra_is_installed(monkeypatch):
    mss = pytest.importorskip("mss")
    pytest.importorskip("PIL.Image")
    monkeypatch.setattr(mss, "mss", _FakeCapture)
    assert screen.capture(allow_screen=True).startswith(b"\x89PNG\r\n\x1a\n")


def test_screen_reports_unavailable_without_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "mss", None)
    monkeypatch.setitem(sys.modules, "PIL", None)
    assert screen.unavailable() == screen.NOT_INSTALLED


def test_receipt_files_are_private_under_the_device_home(monkeypatch, tmp_path):
    device_home = tmp_path / ".hermes-hands"
    monkeypatch.setattr(config, "ROOT", device_home)
    private, public = generate_keypair()
    payload = {
        "schema_version": 1,
        "device_id": "device-1",
        "instance": "0123456789abcdef",
        "started_at": "2026-11-08T10:00:00Z",
        "ended_at": "2026-11-08T10:05:00Z",
        "end_reason": "stopped_by_person",
        "shutdown_delivery": "pending",
        "events": [],
    }

    json_path, text_path = receipt.write_receipt(payload, private, public)

    assert json_path.parent == text_path.parent == device_home / "receipts"
    if os.name != "nt":
        assert device_home.stat().st_mode & 0o777 == 0o700
        assert json_path.parent.stat().st_mode & 0o777 == 0o700
        assert json_path.stat().st_mode & 0o777 == 0o600
        assert text_path.stat().st_mode & 0o777 == 0o600


def test_windows_keyfile_uses_sid_acl_and_atomic_replace(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    monkeypatch.setattr(keys, "os", types.SimpleNamespace(name="nt", replace=os.replace, environ={"SystemRoot": "C:\\Windows"}, path=os.path))
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if args[0].lower().endswith("whoami.exe"):
            return types.SimpleNamespace(stdout=b'"user","S-1-5-21-123"\r\n')
        assert Path(args[1]).name != "device.json"
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(keys.subprocess, "run", run)
    monkeypatch.setattr(keys.shutil, "which", lambda name: "icacls.exe" if name == "icacls" else "whoami.exe")
    keys.get_or_create()
    assert config.KEY_PATH.exists()
    assert any("*S-1-5-21-123:F" in args for args, _ in calls)


def test_windows_acl_failure_removes_key_and_does_not_decode_output(monkeypatch, tmp_path):
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    monkeypatch.setattr(keys, "os", types.SimpleNamespace(name="nt", replace=os.replace, environ={"SystemRoot": "C:\\Windows"}, path=os.path))
    monkeypatch.setattr(keys.shutil, "which", lambda name: "icacls.exe")

    def run(args, **kwargs):
        if args[0].lower().endswith("whoami.exe"):
            return types.SimpleNamespace(stdout=b'"user","S-1-5-21-123"\r\n')
        raise keys.subprocess.CalledProcessError(1, args, output=b"\xff")

    monkeypatch.setattr(keys.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="protect the device key"):
        keys.get_or_create()
    assert not config.KEY_PATH.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_remove_always_unlinks_key_when_keyring_delete_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ROOT", tmp_path)
    monkeypatch.setattr(config, "KEY_PATH", tmp_path / "device.json")
    config.KEY_PATH.write_text("{}", encoding="utf-8")

    class BrokenKeyring:
        errors = types.SimpleNamespace(KeyringError=RuntimeError)

        @staticmethod
        def get_password(service, username):
            raise RuntimeError("unavailable")

    monkeypatch.setattr(keys, "_keyring", lambda: BrokenKeyring)
    keys.remove()
    assert not config.KEY_PATH.exists()
