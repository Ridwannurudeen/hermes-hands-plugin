import threading
from pathlib import Path

from hermeshands_device import config, executor, keys, loop
from hermeshands_device.protocol import generate_keypair


def test_device_home_fixture_redirects_every_device_path(isolated_device_home):
    root = isolated_device_home / ".hermes-hands"
    assert Path.home() == isolated_device_home
    assert config.ROOT == root
    assert executor.record_path("job").parent == root / "out"
    private, public = keys.get_or_create()
    assert config.KEY_PATH.exists() and config.KEY_PATH.parent == root
    assert keys._keyring() is None
    assert len(private) == len(public) == 32


def test_stopped_witness_session_writes_its_receipt_into_the_test_home(isolated_device_home):
    private, public = generate_keypair()
    agent = object.__new__(loop.DeviceLoop)
    agent.private, agent.public = private, public
    agent.device_id = "device-1"
    agent.instance = "0123456789abcdef"
    agent.capabilities = []
    agent.witness = True
    agent.session_state = "active"
    agent.session_started_at = "2026-11-08T10:00:00Z"
    agent.stop_event = threading.Event()
    agent._stop_lock = threading.Lock()
    agent.receipt_events = []
    agent.console = type("Console", (), {"write": lambda self, text: None})()
    agent._cancel_running_jobs = lambda: None
    agent._send_final_heartbeat = lambda: False
    agent._begin_stopping()
    agent._stop_and_flush()
    receipts = list((isolated_device_home / ".hermes-hands" / "receipts").glob("session-*.json"))
    assert len(receipts) == 1
