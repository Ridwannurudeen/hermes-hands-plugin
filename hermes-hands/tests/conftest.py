import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Always a fresh home: an exported HERMES_HOME may be a live gateway's, and Hermes writes its
# process registry and logs there.
_PREVIOUS_HERMES_HOME = os.environ.get("HERMES_HOME")
_HERMES_HOME = tempfile.mkdtemp(prefix="hermes-home-")
os.environ["HERMES_HOME"] = _HERMES_HOME


def pytest_sessionfinish(session, exitstatus):
    if _PREVIOUS_HERMES_HOME is None:
        os.environ.pop("HERMES_HOME", None)
    else:
        os.environ["HERMES_HOME"] = _PREVIOUS_HERMES_HOME
    # Hermes may still hold a log file open here on Windows; the folder is a private temp folder.
    shutil.rmtree(_HERMES_HOME, ignore_errors=True)
