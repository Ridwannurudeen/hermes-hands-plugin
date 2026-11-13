"""A refused auxiliary probe cannot replace a successful primary read or search result."""

import pytest

pytest.importorskip("tools.environments.base")
pytest.importorskip("hermes_cli.plugins")

from hands import client, environment, messages  # noqa: E402
from hands.environment import HandsEnvironment  # noqa: E402
from hands_fakes import hands_db, wired  # noqa: E402,F401
from test_environment import (  # noqa: E402,F401
    fresh_session_cwds,
    hands_backend,
    isolated_hermes_home,
    laptop,
)
from test_lane_p8_findings import dispatch  # noqa: E402,F401


@pytest.mark.parametrize("probe", [
    "head -c 1000 '/not-shown/probe.txt'",
    "rg -i --count-matches  'public' '/not-shown' 2>/dev/null | head -n 50",
    "command -v python3 2>/dev/null; echo extra",
    "command -v grep >/dev/null 2>&1 && echo 'yes'; echo extra",
])
@pytest.mark.parametrize("tool", ["read_file", "search_files"])
def test_refused_auxiliary_probe_preserves_successful_primary_result(dispatch, monkeypatch, tool, probe):
    d = dispatch
    path = f"{d.base}/work" + ("/notes.txt" if tool == "read_file" else "")
    args = {"path": path, **({"limit": 1} if tool == "read_file" else {"pattern": "public"})}
    expected = d.call(tool, args)
    assert "public" in expected, expected
    execute = HandsEnvironment.execute
    probes = []

    def inject_probe(env, command, cwd="", **kwargs):
        primary = environment._SED_PAGE.search(command) if tool == "read_file" else environment._SEARCH.match(command)
        if primary and not probes:
            result = execute(env, probe, cwd)
            probes.append(result)
        return execute(env, command, cwd, **kwargs)

    monkeypatch.setattr(HandsEnvironment, "execute", inject_probe)
    actual = d.call(tool, args)
    assert probes == [{"output": messages.WITNESS_CALL_CHANGED, "returncode": 255}]
    assert actual == expected
    assert client._REFUSED_CALLS == {}
