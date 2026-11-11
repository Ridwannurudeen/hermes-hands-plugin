import sys
import threading
import types

import httpx
import pytest

from hermeshands_device import config, loop
from hermeshands_device import console as console_module
from hermeshands_device.console import WITNESS_CAPABILITIES, WITNESS_START_PROMPT, ConsoleOwner
from hermeshands_device.protocol import b64u, generate_keypair
from test_console import FakeConsole, _wait_for


def _no_screen_witness_agent(monkeypatch, console):
    private, public = generate_keypair()
    pairing = {
        "gateway_url": "https://example.test/api/plugins/hermes-hands",
        "device_id": "device-1",
        "relay_public_key": b64u(public),
    }
    monkeypatch.setattr(loop, "get_or_create", lambda: (private, public))
    monkeypatch.setattr(config, "load", lambda: dict(pairing))
    monkeypatch.setattr(config, "relay_public_key", lambda: public)
    monkeypatch.setattr(loop.screen, "unavailable", lambda: loop.screen.NOT_INSTALLED)
    monkeypatch.setattr(loop.executor, "reap_recorded_processes", lambda: None)
    agent = loop.DeviceLoop(
        transport=httpx.MockTransport(lambda request: httpx.Response(204, request=request)),
        console=console,
    )
    helped = []

    def post(endpoint, body):
        agent.stop_event.wait(5)
        return httpx.Response(204)

    def send_help(text):
        helped.append(text)
        return True

    monkeypatch.setattr(agent, "_heartbeat_loop", lambda: None)
    monkeypatch.setattr(agent, "_send_final_heartbeat", lambda: True)
    monkeypatch.setattr(agent, "_post", post)
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    monkeypatch.setattr(agent, "_send_help_request", send_help)
    return agent, helped


@pytest.mark.parametrize("command", ["S", "H"])
def test_stop_and_help_work_after_consent_when_screenshots_are_unavailable(monkeypatch, command):
    console = FakeConsole("Y")
    agent, helped = _no_screen_witness_agent(monkeypatch, console)
    worker = threading.Thread(target=agent.run_forever, daemon=True)
    try:
        assert agent.console_owner.startup_consent(WITNESS_START_PROMPT) == "Y"
        agent.witness = True
        agent.session_state = "active"
        agent.capabilities = list(WITNESS_CAPABILITIES)
        worker.start()
        assert _wait_for(
            lambda: "Type S and press Enter to stop" in console.prompt_text(), timeout=2
        )
        assert _wait_for(lambda: loop._SCREENSHOTS_UNAVAILABLE in console.outputs, timeout=2)
        if command == "H":
            console.feed("H")
            assert _wait_for(lambda: "Help message" in console.prompt_text(), timeout=2)
            console.feed("Please call me.")
            assert _wait_for(lambda: helped == ["Please call me."], timeout=2)
            assert not agent.stop_event.is_set()
        console.feed("S")
        assert agent.stop_event.wait(2)
        worker.join(5)
        assert not worker.is_alive()
        assert agent.stop_reason == "stopped_by_person"
        assert agent.session_state == "stopped"
    finally:
        agent.stop_event.set()
        console.feed(None)
        worker.join(5)
        agent.client.close()


@pytest.mark.parametrize("line", ["S ", " S", " s", "s\t"])
def test_idle_prompt_stop_ignores_surrounding_spaces(line):
    console = FakeConsole(line)
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    try:
        assert stopped.wait(1)
        owner.join(1)
        assert "Stopping now...\n" in console.output()
    finally:
        owner.close()
        console.feed(None)
        owner.join(1)


def test_idle_prompt_help_ignores_surrounding_spaces():
    console = FakeConsole(" h ", "Please help.", "S")
    stopped = threading.Event()
    messages = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=messages.append)
    owner.start()
    assert stopped.wait(1)
    owner.join(1)
    assert messages == ["Please help."]


def test_idle_prompt_explains_other_input():
    console = FakeConsole("x", "S")
    stopped = threading.Event()
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert stopped.wait(1)
    owner.join(1)
    assert "Type S and press Enter to stop.\n" in console.outputs


@pytest.mark.parametrize(("line", "answer"), [("S ", "S"), (" s", "S"), (" y ", "y"), ("N\t", "N")])
def test_question_answers_ignore_surrounding_spaces(line, answer):
    console = FakeConsole()
    stopped = threading.Event()
    answers = []
    owner = ConsoleOwner(console, on_stop=stopped.set, on_help=lambda text: None)
    owner.start()
    assert console.read_started.wait(1)
    worker = threading.Thread(
        target=lambda: answers.append(
            owner.request("screen-request", "Allow screenshot?", timeout=2)
        )
    )
    worker.start()
    try:
        assert _wait_for(lambda: "Allow screenshot?" in console.output())
        console.feed(line)
        worker.join(1)
        assert answers == [answer]
        assert "Please type Y or N" not in console.output()
        assert stopped.is_set() is (answer == "S")
    finally:
        owner.close()
        console.feed(None)
        owner.join(1)
        worker.join(1)


@pytest.mark.parametrize(
    ("keys", "lines"),
    [
        (["v", "o", "i", "l", "\xe0", " ", "b", "\r"], ["voil\xe0 b"]),
        (["\xe0", "\r", "S", "\r"], ["\xe0", "S"]),
        (["\xe0", "H", "o", "k", "\r"], ["ok"]),
        (["\x00", ";", "\r"], [""]),
    ],
)
def test_windows_typed_a_grave_is_text_not_an_extended_key(monkeypatch, keys, lines):
    pending = list(keys)
    monkeypatch.setattr(console_module.os, "name", "nt")
    monkeypatch.setitem(
        sys.modules,
        "msvcrt",
        types.SimpleNamespace(
            kbhit=lambda: True, getwch=lambda: pending.pop(0) if pending else "\x1a"
        ),
    )
    terminal = console_module.TerminalConsole()
    terminal.write = lambda text: None

    assert [terminal.read_line("Prompt: ") for _ in lines] == lines


def test_slow_stop_callback_does_not_block_other_console_output():
    console = FakeConsole("S")
    release = threading.Event()
    entered = threading.Event()

    def on_stop():
        entered.set()
        release.wait(2)

    owner = ConsoleOwner(console, on_stop=on_stop, on_help=lambda text: None)
    owner.start()
    try:
        assert entered.wait(1)
        notice = threading.Thread(
            target=owner.notice, args=("Lost connection to your helper.",), daemon=True
        )
        notice.start()
        notice.join(0.5)
        assert not notice.is_alive()
        assert "Stopping now...\n" not in console.outputs
    finally:
        release.set()
        owner.join(1)
    assert console.outputs[-1] == "Stopping now...\n"


def test_sanitizer_removes_unicode_line_and_paragraph_separators():
    assert (
        console_module.sanitize_text("ls [10:05] Session stopped x") == "ls[10:05] Session stoppedx"
    )
    assert console_module.sanitize_text("a b", keep="\n\t") == "ab"
