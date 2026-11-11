import pytest

from hermeshands_device import loop
from test_lane_f2_loop import _witness_screenshot_agent
from test_loop import PromptOwner, _screenshot_agent


def _normal_agent(monkeypatch, *, allow_screen=True):
    agent = _screenshot_agent(PromptOwner([]), monkeypatch)
    agent.witness = False
    agent.allow_screen = allow_screen
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    return agent, posted


def _probe(monkeypatch, answers):
    calls = []

    def unavailable():
        calls.append(None)
        return answers[min(len(calls), len(answers)) - 1]

    monkeypatch.setattr(loop.screen, "unavailable", unavailable)
    return calls


def _captures(monkeypatch, outcomes):
    calls = []

    def capture(**kwargs):
        outcome = outcomes[len(calls)]
        calls.append(kwargs)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(loop.screen, "capture", capture)
    return calls


def _shoot(agent, count):
    for number in range(count):
        agent._run_job({"job_id": f"shot{number}", "type": "screenshot"})


def test_one_failed_capture_does_not_turn_screenshots_off_in_normal_serve(monkeypatch):
    agent, posted = _normal_agent(monkeypatch)
    _probe(monkeypatch, [None])
    captures = _captures(monkeypatch, [RuntimeError(loop.screen.NO_SCREEN), b"png", b"png"])
    _shoot(agent, 3)
    assert len(captures) == 3
    assert posted[0] == {"done": True, "returncode": 126, "error": "screenshot_failed"}
    assert [body.get("returncode") for body in posted[1:]] == [0, 0]


def test_a_lost_display_in_normal_serve_is_reported_and_tried_again_later(monkeypatch):
    agent, posted = _normal_agent(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(loop, "_session_clock", lambda: clock[0])
    probes = _probe(monkeypatch, [loop.screen.NO_SCREEN, None])
    captures = _captures(monkeypatch, [RuntimeError(loop.screen.NO_SCREEN), b"png"])
    _shoot(agent, 2)
    assert len(captures) == 1 and len(probes) == 1
    assert posted == [{"done": True, "returncode": 126, "error": loop.screen.NO_SCREEN}] * 2
    clock[0] += loop._SCREEN_RETRY_SECONDS
    _shoot(agent, 1)
    assert len(captures) == 2
    assert posted[-1]["returncode"] == 0


def test_normal_serve_without_allow_screen_never_opens_the_display(monkeypatch):
    agent, posted = _normal_agent(monkeypatch, allow_screen=False)
    monkeypatch.setattr(
        loop.screen, "unavailable", lambda: pytest.fail("display probed for a refused screenshot")
    )
    _shoot(agent, 3)
    assert posted == [{"done": True, "returncode": 126, "error": loop.screen.NOT_ALLOWED}] * 3


@pytest.mark.parametrize(
    ("answered", "error"), [(True, "screenshots_disabled"), (False, "screenshot_pending")]
)
def test_a_witness_session_without_screenshots_never_opens_the_display(
    monkeypatch, answered, error
):
    agent = _witness_screenshot_agent(PromptOwner([]), monkeypatch)
    agent.allow_screen = False
    agent.screen_session_answered = answered
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    monkeypatch.setattr(
        loop.screen, "unavailable", lambda: pytest.fail("display probed for a refused screenshot")
    )
    _shoot(agent, 2)
    assert posted == [{"done": True, "returncode": 126, "error": error}] * 2


def test_allowed_screenshots_do_not_open_an_extra_display_connection_per_job(monkeypatch):
    agent, posted = _normal_agent(monkeypatch)
    probes = _probe(monkeypatch, [None])
    _captures(monkeypatch, [b"png"] * 3)
    _shoot(agent, 3)
    assert probes == []
    assert [body["returncode"] for body in posted] == [0, 0, 0]


def test_a_witness_session_probes_the_display_once(monkeypatch):
    agent = _witness_screenshot_agent(PromptOwner(["Y", "Y", "Y", "Y"]), monkeypatch)
    agent.allow_screen = False
    agent.screen_session_answered = False
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    monkeypatch.setattr(loop.config, "load", lambda: {})
    probes = _probe(monkeypatch, [None])
    _captures(monkeypatch, [b"png"] * 3)
    agent._request_session_screenshot_consent()
    _shoot(agent, 3)
    assert len(probes) == 1
    assert [body["returncode"] for body in posted] == [0, 0, 0]


def test_normal_serve_without_the_screen_extra_still_refuses_with_the_fixed_code(monkeypatch):
    agent, posted = _normal_agent(monkeypatch)
    monkeypatch.setattr(loop.screen, "unavailable", lambda: pytest.fail("display probed without the screen extra"))
    captures = _captures(monkeypatch, [RuntimeError(loop.screen.NOT_INSTALLED)] * 2)
    _shoot(agent, 2)
    assert len(captures) == 1
    assert posted == [{"done": True, "returncode": 126, "error": loop.screen.NOT_INSTALLED}] * 2
