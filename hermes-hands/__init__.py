"""Hermes Hands: your own laptop as Hermes's hands. See plugin.yaml and README.md."""

from __future__ import annotations

from pathlib import Path


def register(ctx) -> None:
    """Load-time registration. The relay seed is read here, once, under the plugin manager's home
    scope; request handlers and the lazily started relay never call ``get_secret``."""
    from agent.secret_scope import get_secret
    from hermes_cli.dashboard_auth.token_auth import register_token_route

    from .hands import auth, cli, client, commands, relay, store, tools, witness
    from .hands.provider import HandsProvider

    witness.register(ctx)
    ctx.register_middleware("tool_execution", client.tool_execution)
    store.OFFLINE_AFTER = int(ctx.get_config("offline_after_seconds", 20))
    relay.configure_help(ctx)
    seed = get_secret("HANDS_RELAY_SEED")
    keys = relay.derive_keys(seed) if seed else None
    client.configure(
        str(ctx.get_config("dashboard_url", "http://127.0.0.1:9119")),
        keys.local_bearer if keys is not None else None,
    )
    ctx.register_terminal_environment_provider(HandsProvider(ctx))
    ctx.register_dashboard_auth_provider(auth.HandsTokenProvider(keys))
    for path in relay.TOKEN_ROUTES:
        register_token_route(path)
    commands.register_commands(ctx, has_seed=keys is not None)
    cli.register_cli(ctx, has_seed=keys is not None)
    tools.register_tools(ctx)
    if keys is not None:
        client.start_help_poller(ctx)
    ctx.register_skill(
        "hands",
        Path(__file__).parent / "skills" / "hands" / "SKILL.md",
        "Work on a paired Hermes Hands device: Git Bash paths on Windows, what hands errors (255, 126)"
        " mean, and device screenshots.",
    )
