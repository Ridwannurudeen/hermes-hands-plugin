from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from hermeshands_device import config, janitor


def test_cleanup_removes_only_old_regular_matching_files(monkeypatch, tmp_path, caplog):
    temp_dir = tmp_path / "temp"
    out_dir = tmp_path / "out"
    temp_dir.mkdir()
    out_dir.mkdir()
    monkeypatch.setattr(janitor, "_temp_dirs", lambda: {temp_dir})
    monkeypatch.setattr(config, "OUT_DIR", out_dir)

    old_snapshot = temp_dir / "hermes-snap-old.sh"
    new_snapshot = temp_dir / "hermes-snap-new.sh"
    old_cwd = temp_dir / "hermes-cwd-old.txt"
    unrelated = temp_dir / "hermes-snap-old.txt"
    old_script = out_dir / "tmp-old.sh"
    new_script = out_dir / "tmp-new.sh"
    shared_tmp_script = temp_dir / "tmp-user.sh"
    old_log = out_dir / "old.log"
    new_log = out_dir / "new.log"
    for path in (old_snapshot, new_snapshot, old_cwd, unrelated, old_script, new_script, shared_tmp_script, old_log, new_log):
        path.write_text("content", encoding="utf-8")
    old_time = time.time() - janitor.MAX_AGE_SECONDS - 1
    for path in (old_snapshot, old_cwd, old_script, shared_tmp_script):
        os.utime(path, (old_time, old_time))
    old_log_time = time.time() - janitor.OUT_LOG_MAX_AGE_SECONDS - 1
    os.utime(old_log, (old_log_time, old_log_time))
    symlink = temp_dir / "hermes-cwd-link.txt"
    try:
        symlink.symlink_to(old_cwd)
    except OSError:
        symlink = None

    with caplog.at_level(logging.INFO, logger=janitor.__name__):
        assert janitor.cleanup() == 4

    assert not old_snapshot.exists()
    assert not old_cwd.exists()
    assert not old_script.exists()
    assert shared_tmp_script.exists()
    assert not old_log.exists()
    assert new_snapshot.exists()
    assert new_script.exists()
    assert new_log.exists()
    assert unrelated.exists()
    if symlink is not None:
        assert symlink.is_symlink()
    assert "Device temp janitor removed 4 files" in caplog.text


def test_cleanup_keeps_out_logs_newer_than_seven_days(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    monkeypatch.setattr(janitor, "_temp_dirs", lambda: set())
    monkeypatch.setattr(config, "OUT_DIR", out_dir)
    recent_log = out_dir / "recent.log"
    recent_log.write_text("content", encoding="utf-8")
    assert janitor.cleanup() == 0
    assert recent_log.exists()
