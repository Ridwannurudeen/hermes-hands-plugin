import contextvars
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Always a fresh home: an exported HERMES_HOME may be a live gateway's, and Hermes writes its
# process registry and logs there.
_PREVIOUS_HERMES_HOME = os.environ.get("HERMES_HOME")
_HERMES_HOME = tempfile.mkdtemp(prefix="hermes-home-")
os.environ["HERMES_HOME"] = _HERMES_HOME


@pytest.fixture(autouse=True)
def fresh_call_stores(monkeypatch):
    """Every test starts with none of the client's per-call records another test left behind."""
    from hands import client

    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("test_tool_session", default=None))
    monkeypatch.setattr(client, "_CALL_CELL", contextvars.ContextVar("test_call_cell", default=None))
    monkeypatch.setattr(client, "_CALL_TOOL", contextvars.ContextVar("test_call_tool", default=""))
    for store in ("_CALL_SESSIONS", "_RUNNING_CALLS", "_RUNNING_COUNTS", "_APPROVED_CALLS", "_SHOWN_CALLS", "_REFUSED_CALLS"):
        monkeypatch.setattr(client, store, {})
    monkeypatch.setattr(client, "_CLAIMED_CALLS", set())


def pytest_sessionfinish(session, exitstatus):
    if _PREVIOUS_HERMES_HOME is None:
        os.environ.pop("HERMES_HOME", None)
    else:
        os.environ["HERMES_HOME"] = _PREVIOUS_HERMES_HOME
    # Hermes may still hold a log file open here on Windows; the folder is a private temp folder.
    shutil.rmtree(_HERMES_HOME, ignore_errors=True)
