"""``HandsProvider``: the ``hands`` terminal backend (``agent/terminal_env_provider.py:20-122``).

``is_container=True`` gives the file tools sandbox path semantics (pure POSIX, no host ``resolve()``),
which a Windows device needs; ``skip_container_guards`` is overridden to False so Hermes's
dangerous-command approvals stay on. ``is_available`` is always True: the ``server`` target never needs
the relay, and a device target fails closed per call.
"""

from __future__ import annotations

from typing import Any, Optional

from agent.terminal_env_provider import TerminalEnvironmentProvider

from .environment import HandsEnvironment, ProbeEnvironment


class HandsProvider(TerminalEnvironmentProvider):
    name = "hands"
    display_name = "Hermes Hands"
    is_remote = True
    is_container = True
    supports_streams = False

    def __init__(self, ctx):
        self._ctx = ctx

    @property
    def skip_container_guards(self) -> bool:
        return False

    @property
    def default_cwd(self) -> Optional[str]:
        return "~"

    @property
    def strip_env_keys(self) -> frozenset:
        """The relay seed, which ``hermes hands setup`` writes to the profile's .env: it derives the
        relay's signing key and the local bearer that queues jobs on devices. Core strips these keys
        from every subprocess it spawns, so a ``server`` command cannot read it
        (agent/terminal_env_registry.py:71-85, tools/environments/local.py:333-370)."""
        return frozenset({"HANDS_RELAY_SEED"})

    @property
    def env_description(self) -> str:
        return "a device paired with Hermes Hands, or the gateway host for the server target"

    def is_available(self) -> bool:
        return True

    def create_environment(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        image: Optional[str] = None,
        container_config: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> HandsEnvironment | ProbeEnvironment:
        # The id core's prompt builder creates its backend probe with (agent/prompt_builder.py:851).
        if task_id == "prompt-backend-probe":
            return ProbeEnvironment(cwd=cwd, timeout=timeout)
        return HandsEnvironment(self._ctx, cwd=cwd, timeout=timeout, task_id=task_id)
