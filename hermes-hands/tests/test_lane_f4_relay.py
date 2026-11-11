import contextvars
import threading

import pytest

from hands import client, messages, relay, witness
from hands_fakes import Device, hands_db, wired  # noqa: F401
from test_relay import (  # noqa: F401
    body, device_call, hub, local, started, until_waiting, witness_fields,
)


def _decision(device, witness=True, instance="w1"):
    return {"device_id": device.device_id, "state": [witness, "active" if witness else "normal", instance if witness else None]}


def _activate(hub, device, instance="w1", **extra):
    return device_call(hub, device, "device_heartbeat", "/device/heartbeat", {
        "policy_hash": "p0", "os": "Windows", "home": "/home/test",
        "agent_version": "0.2.0", "instance": instance,
        **witness_fields(), **extra,
    })[0]


def test_old_normal_poll_cannot_take_new_witness_work(hub):
    device = Device()
    stale = started(lambda: device_call(
        hub, device, "device_poll", "/device/poll", {"wait": 2},
    ))
    until_waiting(hub, device.device_id)
    assert _activate(hub, device).status == 200
    queued = local(hub, "local_exec", {
        "device": "laptop", "script": "echo approved", "timeout": 5,
        "decision": _decision(device),
    })
    reply, _, _ = stale()
    assert reply.status == 204
    job_id = body(queued)["job_id"]
    assert not hub._jobs[job_id].picked
    fresh, _, _ = device_call(hub, device, "device_poll", "/device/poll", {
        "wait": 0, "instance": "w1", **witness_fields(),
    })
    assert body(fresh)["job_id"] == job_id


def test_poll_session_is_checked_when_it_opens(hub, monkeypatch):
    device = Device()
    original = hub._open_poll
    opening = threading.Event()
    resume = threading.Event()

    def switch_before_open(*args, **kwargs):
        opening.set()
        assert resume.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(hub, "_open_poll", switch_before_open)
    stale = started(lambda: device_call(
        hub, device, "device_poll", "/device/poll", {"wait": 2},
    ))
    assert opening.wait(5)
    assert _activate(hub, device).status == 200
    queued = local(hub, "local_exec", {
        "device": "laptop", "script": "echo approved", "timeout": 5,
        "decision": _decision(device),
    })
    resume.set()
    reply, _, _ = stale()
    assert reply.status == 204
    assert not hub._jobs[body(queued)["job_id"]].picked


@pytest.mark.parametrize("route,handler", [
    ("/device/heartbeat", "device_heartbeat"), ("/device/poll", "device_poll"),
])
def test_queued_jobs_preserve_session_timeout_reason(hub, route, handler):
    device = Device()
    _activate(hub, device)
    job_id = body(local(hub, "local_exec", {
        "device": "laptop", "script": "echo waiting", "timeout": 5,
        "decision": _decision(device),
    }))["job_id"]
    fields = {
        "policy_hash": "p0", "os": "Windows", "home": "/home/test",
        "agent_version": "0.2.0", "instance": "w1", "wait": 0,
        **witness_fields(witness=False, session_state="stopping"),
        "stop_reason": "session_timeout",
    }
    reply, _, _ = device_call(hub, device, handler, route, fields)
    assert reply.status in {200, 204}
    output = body(local(hub, "local_output", {"job_id": job_id, "wait": 0}))
    assert output["error"] == "session_timeout"
    assert output["returncode"] == 124
    assert "30 minute session" in messages.device_result_error(output["error"], "laptop")


@pytest.mark.parametrize("kind", ["exec", "checkup", "screenshot"])
@pytest.mark.parametrize("binding", ["missing", "normal", "previous_witness", "wrong_device"])
def test_witness_work_requires_the_matching_hook_decision(hub, kind, binding):
    device = Device()
    _activate(hub, device)
    request = {"device": "laptop", "type": kind}
    if kind == "exec":
        request.update(script="echo approved", timeout=5)
    if binding != "missing":
        request["decision"] = _decision(device)
        if binding == "normal":
            request["decision"] = _decision(device, witness=False)
        elif binding == "previous_witness":
            request["decision"]["state"][2] = "old"
        else:
            request["decision"]["device_id"] = "other-device"
    reply = local(hub, "local_exec", request)
    assert reply.status == 409
    assert body(reply)["error"] == "session_changed"
    assert not hub._jobs and not hub._queues


@pytest.mark.parametrize("kind", ["exec", "checkup", "screenshot"])
def test_matching_decision_queues_only_in_the_same_witness(hub, kind):
    device = Device()
    _activate(hub, device)
    request = {"device": "laptop", "type": kind, "decision": _decision(device)}
    if kind == "exec":
        request.update(script="echo approved", timeout=5)
    queued = local(hub, "local_exec", request)
    assert queued.status == 200
    reply, _, _ = device_call(hub, device, "device_poll", "/device/poll", {
        "wait": 0, "instance": "w1", **witness_fields(),
    })
    assert body(reply)["job_id"] == body(queued)["job_id"]
    assert "decision" not in body(reply)


def test_one_execute_cannot_cross_into_a_new_witness_session(wired, monkeypatch, tmp_path):
    pytest.importorskip("tools.environments.base")
    from hands import environment

    monkeypatch.setattr(client, "_TOOL_SESSION", contextvars.ContextVar("f4_relay_session", default=None))
    hub, _ = wired
    device = Device(home=str(tmp_path), device_os="Linux")
    monkeypatch.setattr(environment, "resolve_current_target", lambda ctx: "laptop")

    class Ctx:
        def current_cron_execution(self):
            return None

    assert witness.pre_tool_call(Ctx(), "terminal", {"command": "rm notes.txt"}) is None
    requests = []
    original = hub._enqueue

    def enqueue(*args, **kwargs):
        reply = original(*args, **kwargs)
        requests.append(reply.status)
        if len(requests) == 1:
            assert _activate(hub, device).status == 200
        return reply

    def output(job_id, after):
        job = hub._jobs[job_id]
        if job.done:
            return hub._take_locked(job, after)
        return {"done": True, "returncode": 0, "chunks": [], "next": 0, "error": None}

    monkeypatch.setattr(hub, "_enqueue", enqueue)
    monkeypatch.setattr(client, "job_output", output)
    env = environment.DeviceEnvironment(
        "laptop", cwd=str(tmp_path), timeout=5, home=str(tmp_path),
        windows=False, inline_limit=8192,
    )
    result = env.execute("rm notes.txt", bounded_capture=True)
    assert requests[0] == 200
    assert len(requests) >= 3
    assert requests[1:] == [409] * (len(requests) - 1)
    assert result["returncode"] == relay.UNREACHABLE
    assert all(job.done and not job.picked for job in hub._jobs.values())
