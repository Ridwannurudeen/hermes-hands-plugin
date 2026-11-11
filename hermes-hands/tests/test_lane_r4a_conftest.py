import os
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = "HANDS_R4A_HOME_PROBE"


def test_reports_its_hermes_home():
    target = os.environ.get(PROBE)
    if not target:
        pytest.skip("runs only inside the subprocess below")
    Path(target).write_text(os.environ["HERMES_HOME"], encoding="utf-8")


def test_the_suite_never_uses_a_hermes_home_from_the_environment(tmp_path):
    """r3-packaging-2: a shell that exports HERMES_HOME (a live gateway home) must not be written."""
    live = tmp_path / "live-home"
    live.mkdir()
    report = tmp_path / "home.txt"
    env = {**os.environ, "HERMES_HOME": str(live), PROBE: str(report)}
    finished = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            f"{__file__}::test_reports_its_hermes_home",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(tmp_path / "inner"),
        ],
        env=env,
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert finished.returncode == 0, finished.stdout + finished.stderr
    used = Path(report.read_text(encoding="utf-8-sig"))
    assert used != live and live not in used.parents
    assert list(live.iterdir()) == []
    assert not used.exists(), "the suite left its temporary Hermes home behind"
