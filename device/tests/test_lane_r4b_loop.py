import httpx
import pytest

from hermeshands_device import loop
from test_lane_r3x_loop import agent  # noqa: F401


@pytest.mark.parametrize("job", [{"job_id": "cmd", "type": "exec", "script": "echo hi"}, {"job_id": "shot", "type": "screenshot"}])
def test_an_abnormal_session_end_sends_the_stable_device_error_code(agent, monkeypatch, job):  # noqa: F811
    agent.allow_screen = True
    monkeypatch.setattr(loop.screen, "unavailable", lambda: None)
    posted = []
    monkeypatch.setattr(agent, "_post", lambda endpoint, body: posted.append(dict(body)) or httpx.Response(204))
    monkeypatch.setattr(agent, "_verify_response", lambda *args: {})
    agent._begin_stopping(reason="error")
    agent._run_job(job)
    assert posted[-1]["error"] == "device_error"
    assert posted[-1]["returncode"] == 1


def _no_screen_agent(monkeypatch, answers):
    from test_lane_f2_loop import _witness_screenshot_agent
    from test_loop import PromptOwner

    owner = PromptOwner(answers)
    agent = _witness_screenshot_agent(owner, monkeypatch)
    agent.allow_screen = False
    agent.screen_session_answered = False
    posted = []
    monkeypatch.setattr(agent, "_result", lambda job_id, seq, **kwargs: posted.append(kwargs))
    monkeypatch.setattr(loop.config, "load", lambda: {})
    return agent, owner, posted


def test_a_computer_with_no_screen_is_never_asked_about_screenshots(monkeypatch):
    agent, owner, posted = _no_screen_agent(monkeypatch, [])
    monkeypatch.setattr(loop.screen, "unavailable", lambda: loop.screen.NO_SCREEN)
    monkeypatch.setattr(loop.screen, "capture", lambda **kwargs: pytest.fail("capture on a computer with no screen"))
    agent._request_session_screenshot_consent()
    agent._run_job({"job_id": "shot", "type": "screenshot"})
    assert owner.requests == []
    assert posted == [{"done": True, "returncode": 126, "error": "screenshot_unavailable"}]
    text = "".join(agent.console.outputs)
    assert "This computer has no screen that screenshots can capture, so none will be taken this session.\n" in text
    assert "Screenshot request: Refused: this computer has no screen that screenshots can capture" in text


def test_a_failed_capture_sends_a_stable_code_and_is_not_asked_again(monkeypatch):
    agent, owner, posted = _no_screen_agent(monkeypatch, ["Y", "Y"])
    monkeypatch.setattr(loop.screen, "unavailable", lambda: None)

    def capture(**kwargs):
        raise RuntimeError(loop.screen.NO_SCREEN)

    monkeypatch.setattr(loop.screen, "capture", capture)
    agent._request_session_screenshot_consent()
    agent._run_job({"job_id": "shot1", "type": "screenshot"})
    agent._run_job({"job_id": "shot2", "type": "screenshot"})
    assert [request[0] for request in owner.requests] == ["witness-instance-screenshot-session", "witness-instance-screenshot-shot1"]
    assert posted == [{"done": True, "returncode": 126, "error": "screenshot_unavailable"}] * 2
    text = "".join(agent.console.outputs)
    assert "Screenshot request: Failed: this computer has no screen that screenshots can capture" in text
    assert "DISPLAY" not in text
