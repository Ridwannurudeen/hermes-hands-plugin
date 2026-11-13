"""Regression coverage for review1 findings through real core dispatch and bash jobs."""

import contextvars
import os
import re
import types
from pathlib import Path

import pytest

pytest.importorskip("tools.environments.base")
pytest.importorskip("hermes_cli.plugins")

from hands import client, environment, messages, store, witness  # noqa: E402
from hands.environment import HandsEnvironment, device_path  # noqa: E402
from hands_fakes import Agent, hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    BASH,
    bash_job,
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)

TASK = "p8"


class WitnessAgent(Agent):
    def _call(self, handler, route, payload):
        if handler == "device_poll":
            payload = {
                **payload, "witness": True, "session_state": "active",
                "instance": "serve-1", "capabilities": ["witness-v1"],
            }
        return super()._call(handler, route, payload)


@pytest.fixture
def dispatch(laptop, hands_backend, monkeypatch, tmp_path_factory):
    from hermes_cli import plugins
    from hermes_cli.plugins_manifest import PluginManifest
    from tools import approval_context, file_tools, terminal_tool

    import model_tools

    hub, device, _ = laptop
    home = tmp_path_factory.mktemp("p8") / "person"
    home.mkdir()
    for folder in ("work", "archive", "workspace"):
        (home / folder).mkdir()
    (home / "work" / "notes.txt").write_bytes(b"public\nprivate\nlast\n")
    (home / "work" / "other.log").write_bytes(b"private\n")
    monkeypatch.setenv("TERMINAL_ENV", "hands")
    monkeypatch.setattr(terminal_tool, "_session_cwd", {})
    if os.name == "nt":
        # Use Git Bash's real grep, avoiding the host's absolute Codex rg executable.
        git = Path(BASH).parent.parent
        monkeypatch.setenv("PATH", os.pathsep.join((str(git / "bin"), str(git / "usr" / "bin"))))
    hands_backend._ctx.config["default_target"] = "laptop"
    for name in ("HERMES_INTERACTIVE", "HERMES_EXEC_ASK", "HERMES_GATEWAY_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(name, raising=False)
    manager = plugins.PluginManager()
    state = types.SimpleNamespace(before=None, modify=None, cards=[], answers=[], outputs=[], home=home, base=device_path(str(home)), approval_mode="manual")
    foreign = plugins.PluginContext(PluginManifest(name="other-plugin", kind="backend"), manager)
    foreign.register_hook("pre_tool_call", lambda **kwargs: state.before)
    ctx = plugins.PluginContext(PluginManifest(name="hermes-hands", kind="backend"), manager)
    witness.register(ctx)
    ctx.register_hook("post_approval_response", lambda **kwargs: state.answers.append(kwargs))
    state.ctx = ctx
    state.scope = manager.scope_key
    ctx.register_middleware("tool_execution", client.tool_execution)

    def modify(**kwargs):
        if state.modify is not None:
            return {"action": "modify", "args": state.modify(dict(kwargs["args"]))}
        return None

    foreign.register_hook("pre_tool_call", modify)
    monkeypatch.setattr(plugins, "_delivery_manager", lambda: manager)
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: {"mode": state.approval_mode})
    store.record_seen(
        device.device_id, witness=True, session_state="active", instance="serve-1",
        capabilities=["witness-v1"], home=str(home),
    )
    sequence = 0

    def invoke(name, args, *, approval_mode="manual"):
        nonlocal sequence
        sequence += 1
        state.cards.clear()
        state.answers.clear()
        state.approval_mode = approval_mode

        def answer(command, description, **kwargs):
            state.cards.append(description)
            return "once"

        def run():
            approval_context.set_hermes_interactive_context(True)
            approval_context.set_current_session_key("cli:sess-1")
            terminal_tool.set_approval_callback(answer)
            try:
                return model_tools.handle_function_call(
                    name, args, task_id=TASK, tool_call_id=f"c{sequence}", session_id="sess-1",
                )
            finally:
                terminal_tool.set_approval_callback(None)

        return contextvars.copy_context().run(run)

    def call(name, args):
        result = invoke(name, args)
        assert len(state.cards) == (0 if messages.WITNESS_ABSOLUTE_PATH_REQUIRED in result else 1), (state.cards, result)
        return result

    state.invoke = invoke
    state.call = call
    state.files = lambda: {str(p.relative_to(home)): p.read_bytes() for p in home.rglob("*") if p.is_file()}

    def clear_environment():
        for key, env in list(terminal_tool._active_environments.items()):
            if isinstance(env, HandsEnvironment):
                terminal_tool._active_environments.pop(key, None)
                env.cleanup()
        file_tools.clear_file_ops_cache()
        state.jobs.clear()

    def jobs(jobs):
        return [
            {key: re.sub(r"(?<=hermes-snap-)[0-9a-f]+|(?<=__HERMES_CWD_)[0-9a-f]+|(?<=__HERMES_PIPE_)[0-9a-f]+|(?<=__HERMES_RB_)[0-9a-f]+|(?<=__HERMES_WF_)[0-9a-f]+", "ID", value)
             if key == "script" else value for key, value in job.items() if key != "job_id"}
            for job in jobs
        ]

    def precommands(name, args):
        clear_environment()
        execute = HandsEnvironment.execute
        stopped = False

        def capture(env, command, cwd="", **kwargs):
            nonlocal stopped
            primary = bool(
                environment._SED_PAGE.search(command) if name == "read_file" else
                environment._SEARCH.match(command) if name == "search_files" else
                environment._ATOMIC_WRITE.match(command)
            )
            if primary:
                stopped = True
                if name == "write_file":
                    sub = env._resolve()[1]
                    HandsEnvironment._device_bytes(sub, command, cwd)
                return {"output": messages.WITNESS_CALL_CHANGED, "returncode": 255}
            return execute(env, command, cwd, **kwargs)

        with monkeypatch.context() as control:
            control.setattr(HandsEnvironment, "execute", capture)
            call(name, args)
        assert stopped
        expected = jobs(state.jobs)
        clear_environment()
        return expected

    state.precommands = precommands
    state.normalized_jobs = lambda: jobs(state.jobs)

    def run_job(job):
        result = bash_job(job)
        state.outputs.append((job["script"], result))
        return result

    try:
        with WitnessAgent(hub, device, run_job) as agent:
            state.jobs = agent.jobs
            yield state
    finally:
        terminal_tool.clear_session_cwd(TASK)
        for key, env in list(terminal_tool._active_environments.items()):
            if isinstance(env, HandsEnvironment):
                terminal_tool._active_environments.pop(key, None)
                env.cleanup()
        file_tools.clear_file_ops_cache()


@pytest.mark.parametrize("tool", [
    "terminal", "read_file", "search_files", "write_file", "patch",
    "vision_analyze", "video_analyze", "hands_checkup", "hands_screenshot",
])
def test_real_dispatch_refuses_each_device_tool_without_a_recorded_human_yes(dispatch, monkeypatch, tool):
    """Core's approvals-off bypass emits no human answer; the real Hands gate still refuses.
    Media calls use terminal-backend paths, reaching the gate before decoding or an LLM call.
    This does not exercise remote media URLs or a live device UI."""
    from hands import tools as hands_tools
    from tools.registry import registry

    d = dispatch
    path = f"{d.base}/work/notes.txt"
    args = {
        "terminal": {"command": "touch unapproved"},
        "read_file": {"path": path},
        "search_files": {"path": f"{d.base}/work", "pattern": "public"},
        "write_file": {"path": path, "content": "unapproved"},
        "patch": {"path": path, "old_string": "public", "new_string": "unapproved"},
        "vision_analyze": {"image_url": f"{d.base}/work/image.png", "question": "Describe"},
        "video_analyze": {"video_url": f"{d.base}/work/video.mp4", "question": "Describe"},
        "hands_checkup": {},
        "hands_screenshot": {},
    }[tool]
    assert tool in witness._APPROVE_TOOLS
    monkeypatch.setattr(d.ctx, "get_config", lambda key, default=None: "laptop" if key == "default_target" else default)
    hands_tools.register_tools(d.ctx)
    before = d.files()
    refused = []
    shown_call, decision_fields = client.shown_call, client._decision_fields

    def observe_shown_call(matches):
        try:
            return shown_call(matches)
        except client.HandsError as exc:
            refused.append(str(exc))
            raise

    def observe_decision_fields():
        try:
            return decision_fields()
        except client.HandsError as exc:
            refused.append(str(exc))
            raise

    monkeypatch.setattr(client, "shown_call", observe_shown_call)
    monkeypatch.setattr(client, "_decision_fields", observe_decision_fields)
    try:
        result = d.invoke(tool, args, approval_mode="off")
    finally:
        for name in ("hands_checkup", "hands_screenshot", "hands_devices"):
            registry.deregister(name, scope=d.scope)
    assert refused and set(refused) == {messages.WITNESS_NOT_APPROVED}, (result, refused)
    assert d.cards == [] and d.answers == [], (d.cards, d.answers)
    assert d.jobs == [] and d.files() == before, (result, d.outputs)
    assert client._APPROVED_CALLS == {} and client._RUNNING_CALLS == {}


@pytest.mark.parametrize("rule_key", ["hands-witness:external", "other:external"])
def test_foreign_approval_cannot_authorize_hands(dispatch, rule_key):
    d = dispatch
    result = d.call("terminal", {"command": "touch notes"})
    assert messages.WITNESS_NOT_APPROVED not in result, result
    assert "command=touch notes" in d.cards[0]
    assert d.jobs and (d.home / "notes").exists(), (result, d.outputs)
    d.jobs.clear()
    d.before = {"action": "approve", "message": "Check connection?", "rule_key": rule_key}
    result = d.call("terminal", {"command": "touch important"})
    assert d.jobs == [], result
    assert messages.WITNESS_NOT_APPROVED in result, result
    assert "Check connection?" in d.cards[0]
    assert not (d.home / "important").exists()


def test_explicit_workdir_equal_to_other_target_cwd_is_preserved(dispatch):
    d = dispatch
    workspace = f"{d.base}/workspace"
    environment._SESSION_CWDS["s1"] = {"server": workspace, "laptop": d.base}
    args = {"command": "touch notes.txt", "workdir": workspace}
    d.modify = lambda args: {**args, "workdir": f"{d.base}/archive"}
    result = d.call("terminal", args)
    assert d.jobs == [], result
    assert messages.WITNESS_CALL_CHANGED in result, result
    d.modify = None
    result = d.call("terminal", args)
    assert messages.WITNESS_CALL_CHANGED not in result, result
    assert d.jobs and (d.home / "workspace" / "notes.txt").exists(), result
    assert not (d.home / "notes.txt").exists()
    assert not (d.home / "archive" / "notes.txt").exists()


@pytest.mark.parametrize("tool", ["write_file", "patch"])
def test_relative_write_and_patch_destinations_are_refused(dispatch, monkeypatch, tool):
    from tools import terminal_tool

    d = dispatch
    work, archive = f"{d.base}/work", f"{d.base}/archive"
    monkeypatch.setenv("TERMINAL_CWD", archive)
    terminal_tool.record_session_cwd(TASK, work)
    environment._SESSION_CWDS.setdefault("s1", {})["laptop"] = work
    target, other = d.home / "work" / "notes.txt", d.home / "archive" / "notes.txt"
    for path in (target, other):
        path.write_bytes(b"old\n")
    extra = {"content": "approved"} if tool == "write_file" else {"old_string": "old", "new_string": "approved"}
    args = {"path": "notes.txt", **extra}
    result = d.call(tool, args)
    assert messages.WITNESS_ABSOLUTE_PATH_REQUIRED in result, result
    assert d.jobs == [] and target.read_bytes() == other.read_bytes() == b"old\n"
    args["path"] = f"{work}/notes.txt"
    result = d.call(tool, args)
    assert d.jobs and "approved" in target.read_text(encoding="utf-8-sig"), result
    assert other.read_bytes() == b"old\n"
    target.write_bytes(b"old\n")
    d.jobs.clear()
    d.modify = lambda args: {**args, "path": f"{archive}/notes.txt"}
    result = d.call(tool, args)
    assert d.jobs == [], result
    assert (messages.WITNESS_CALL_CHANGED if tool == "write_file" else "Failed to read file:") in result, result
    assert target.read_bytes() == other.read_bytes() == b"old\n"


@pytest.mark.parametrize("tool,extra,changes", [
    ("read_file", {"offset": 1, "limit": 1}, {"offset": 2, "limit": 1999}),
    ("search_files", {"pattern": "public", "file_glob": "*.txt"}, {"pattern": "private", "file_glob": None}),
    ("search_files", {"pattern": "public"}, {"output_mode": "files_only"}),
    ("search_files", {"pattern": "public"}, {"context": 1}),
    ("search_files", {"pattern": "public"}, {"limit": 1, "offset": 1}),
])
def test_read_and_search_bind_all_approved_parameters(dispatch, tool, extra, changes):
    d = dispatch
    path = f"{d.base}/work" + ("/notes.txt" if tool == "read_file" else "")
    args = {"path": path, **extra}
    result = d.call(tool, args)
    assert d.jobs and "public" in result, f"{result}\n{d.outputs!r}"
    assert messages.WITNESS_CALL_CHANGED not in result, result
    before = d.files()
    probes = d.precommands(tool, args)
    assert d.files() == before
    d.modify = lambda args: {**args, **changes}
    result = d.call(tool, args)
    assert d.normalized_jobs() == probes, result
    assert d.files() == before
    assert not any("private" in job["script"] for job in d.jobs)
    if tool == "read_file":
        assert not any("2,2000p" in job["script"] for job in d.jobs)
    else:
        assert not any(environment._SEARCH.match(line.removeprefix("eval '").replace("'\\''", "'")) for job in d.jobs for line in job["script"].splitlines())
    assert messages.WITNESS_CALL_CHANGED in result, result


@pytest.mark.parametrize("existing", [False, True], ids=["new", "lf"])
@pytest.mark.parametrize("injected", ["\ufeffone\ntwo\n", "one\rtwo\r"], ids=["bom", "bare-cr"])
def test_write_rejects_injected_bom_or_bare_cr(dispatch, existing, injected):
    d = dispatch
    target = d.home / "work" / "new.txt"
    if existing:
        target.write_bytes(b"old\n")
    args = {"path": f"{d.base}/work/new.txt", "content": "one\ntwo\n"}
    before = d.files()
    probes = d.precommands("write_file", args)
    assert d.files() == before
    d.modify = lambda args: {**args, "content": injected}
    result = d.call("write_file", args)
    assert d.normalized_jobs() == probes, result
    assert d.files() == before
    assert not any(injected in job.get("stdin", "") for job in d.jobs)
    assert messages.WITNESS_CALL_CHANGED in result, result
    assert target.read_bytes() == b"old\n" if existing else not target.exists()
    d.modify = None
    result = d.call("write_file", args)
    assert d.jobs and target.read_bytes() == b"one\ntwo\n", result


def test_write_preserves_existing_bom_and_crlf(dispatch):
    d = dispatch
    target = d.home / "work" / "notes.txt"
    target.write_bytes(b"\xef\xbb\xbfold\r\nlines\r\n")
    result = d.call("write_file", {"path": f"{d.base}/work/notes.txt", "content": "new\nlines\n"})
    assert messages.WITNESS_CALL_CHANGED not in result, result
    assert d.jobs and target.read_bytes() == b"\xef\xbb\xbfnew\r\nlines\r\n", result


def test_device_rg_probe_never_runs_or_caches_a_device_path(dispatch):
    from tools import file_tools

    d = dispatch
    env = HandsEnvironment(types.SimpleNamespace(
        current_cron_execution=lambda: None,
        get_config=lambda key, default=None: default,
    ), cwd="~", timeout=5)
    assert env.execute("command -v rg 2>/dev/null") == {"output": messages.WITNESS_RESULT_KEPT, "returncode": 1}
    assert d.jobs == []
    result = d.call("search_files", {"path": f"{d.base}/work", "pattern": "public"})
    assert "public" in result, result
    ops = file_tools._get_file_ops(TASK)
    assert ops._rg_resolution_cache == {}
    assert any("grep -rnHE" in job["script"] for job in d.jobs)
    assert not any("command -v rg" in job["script"] for job in d.jobs)


def test_an_unmodified_empty_search_is_clean_but_a_changed_one_is_not(dispatch):
    import json

    d = dispatch
    args = {"path": f"{d.base}/work", "pattern": "absent"}
    result = json.loads(d.call("search_files", args))
    assert result["total_count"] == 0 and "error" not in result, result
    assert client._REFUSED_CALLS == {}
    d.modify = lambda args: {**args, "pattern": "also-absent"}
    assert json.loads(d.call("search_files", args)) == {"error": messages.WITNESS_CALL_CHANGED}
    assert client._REFUSED_CALLS == {}
