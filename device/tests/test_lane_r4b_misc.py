import getpass
from pathlib import Path

DEVICE_ROOT = Path(__file__).resolve().parents[1]


def test_no_tracked_device_file_names_the_local_user_folder():
    user = getpass.getuser()
    names = (f"Users/{user}/", "Users\\" + user + "\\", f"home/{user}/")
    hits = []
    for path in DEVICE_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in (".py", ".toml", ".md", ".txt", ".cfg") or ".pytest_cache" in path.parts:
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        hits += [f"{path.relative_to(DEVICE_ROOT)}: {name}" for name in names if name in text]
    assert hits == []


class _ScreenShotError(Exception):
    pass


def _fake_mss(monkeypatch, *, connect_error=None, grab_error=None):
    import sys
    import types

    class Capture:
        monitors = [{}, {"left": 0, "top": 0, "width": 2, "height": 2}]

        def __init__(self):
            if connect_error:
                raise connect_error

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def grab(self, monitor):
            raise grab_error

    monkeypatch.setitem(sys.modules, "mss", types.SimpleNamespace(mss=Capture))
    monkeypatch.setitem(sys.modules, "mss.exception", types.SimpleNamespace(ScreenShotError=_ScreenShotError))
    monkeypatch.setitem(sys.modules, "PIL", types.SimpleNamespace(Image=object()))
    monkeypatch.setitem(sys.modules, "PIL.Image", object())


def test_a_display_less_computer_reports_screenshots_unavailable(monkeypatch):
    from hermeshands_device import screen

    _fake_mss(monkeypatch, connect_error=_ScreenShotError("$DISPLAY not set."))
    assert screen.unavailable() == screen.NO_SCREEN == "screenshot_unavailable"


def test_a_missing_capture_library_keeps_the_reinstall_sentence(monkeypatch):
    import sys

    from hermeshands_device import screen

    monkeypatch.setitem(sys.modules, "mss", None)
    assert screen.unavailable() == screen.NOT_INSTALLED


def test_a_working_display_is_available(monkeypatch):
    from hermeshands_device import screen

    _fake_mss(monkeypatch)
    assert screen.unavailable() is None


def test_a_capture_error_never_reaches_the_helper_as_raw_text(monkeypatch):
    import pytest

    from hermeshands_device import screen

    _fake_mss(monkeypatch, grab_error=_ScreenShotError("Cannot connect to display: :0"))
    with pytest.raises(RuntimeError) as raised:
        screen.capture(allow_screen=True)
    assert str(raised.value) == screen.NO_SCREEN


def _device_requirements():
    import tomllib

    from packaging.requirements import Requirement

    with (DEVICE_ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    return {Requirement(line).name.lower(): Requirement(line) for line in project["dependencies"]}


def test_the_pillow_pin_admits_the_advisory_fix_release_and_the_tested_capture_library():
    requirements = _device_requirements()
    assert requirements["pillow"].specifier.contains("13.0.0")
    assert requirements["mss"].specifier.contains("10.2.0")


def test_the_installed_capture_libraries_satisfy_the_device_pins():
    from importlib import metadata

    outside = []
    for name, requirement in _device_requirements().items():
        if name not in ("pillow", "mss"):
            continue
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
        if not requirement.specifier.contains(version, prereleases=True):
            outside.append(f"{name} {version} not in {requirement.specifier}")
    assert outside == []


def _signed_receipt():
    from hermeshands_device import receipt
    from hermeshands_device.protocol import b64u, generate_keypair

    private, public = generate_keypair()
    payload = {
        "schema_version": 1,
        "device_id": "device-1",
        "instance": "session-1",
        "started_at": "2026-11-08T10:00:00Z",
        "ended_at": "2026-11-08T10:05:00Z",
        "end_reason": "stopped_by_person",
        "shutdown_delivery": "confirmed",
        "events": [],
    }
    json_path, _ = receipt.write_receipt(payload, private, public)
    return json_path, b64u(public)


def test_receipt_verify_accepts_a_home_relative_path_that_the_shell_did_not_expand(capsys):
    from hermeshands_device import cli

    json_path, key = _signed_receipt()
    assert cli.main(["receipt", "verify", f"~/.hermes-hands/receipts/{json_path.name}", f"--key={key}"]) == 0
    assert capsys.readouterr().out.startswith("This receipt was signed by the key you gave")


def test_receipt_verify_says_when_the_file_is_missing(tmp_path, capsys):
    from hermeshands_device import cli

    _, key = _signed_receipt()
    assert cli.main(["receipt", "verify", str(tmp_path / "missing.json"), f"--key={key}"]) == 1
    assert capsys.readouterr().err == "Receipt verification failed: the receipt file was not found\n"
