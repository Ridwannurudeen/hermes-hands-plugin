import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from hermeshands_device import config, keys  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_device_home(monkeypatch, tmp_path_factory):
    """Every device test gets a temp home: nothing reads or writes the real ~/.hermes-hands or keyring."""
    home = tmp_path_factory.mktemp("device-home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = home / ".hermes-hands"
    for attr, path in (
        ("ROOT", root),
        ("CONFIG_PATH", root / "config.json"),
        ("POLICY_PATH", root / "policy.json"),
        ("KEY_PATH", root / "device.json"),
        ("OUT_DIR", root / "out"),
    ):
        monkeypatch.setattr(config, attr, path)
    monkeypatch.setattr(keys, "_keyring", lambda: None)
    return home
