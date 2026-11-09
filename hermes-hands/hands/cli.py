"""Hermes CLI commands for the Hands gateway plugin."""

from __future__ import annotations

import secrets

from . import client, commands, messages, store

DEFAULT_DASHBOARD_URL = commands.DEFAULT_DASHBOARD_URL


def register_cli(ctx, *, has_seed: bool) -> None:
    def setup_parser(parser):
        subparsers = parser.add_subparsers(dest="hands_action", required=True)
        subparsers.add_parser("status")
        subparsers.add_parser("devices")
        revoke = subparsers.add_parser("revoke")
        revoke.add_argument("name")
        revoke.add_argument("--yes", action="store_true")
        subparsers.add_parser("setup")
        subparsers.add_parser("doctor")
        pair = subparsers.add_parser("pair")
        pair.add_argument("name")
        pair.add_argument("--owner-label")

    def handler(args):
        action = args.hands_action
        if action == "status":
            if store.relay_alive():
                print("Relay: up")
            else:
                try:
                    client.state()
                except client.HandsError as exc:
                    print(f"Relay: down\n{exc}")
                else:  # the relay started, so it wrote its heartbeat
                    print("Relay: up" if store.relay_alive() else f"Relay: down\n{messages.STORE_SPLIT}")
            for device in store.list_devices():
                print(f"{device['name']}: {'online' if device['online'] else 'offline'}")
            return
        if action == "devices":
            for device in store.list_devices():
                print(f"{device['name']}: {'online' if device['online'] else 'offline'}")
            return
        if action == "pair":
            print(
                commands.pair_reply(
                    ctx, args.name, has_seed=has_seed, owner_label=args.owner_label
                )
            )
            return
        if action == "revoke":
            if not args.yes and input(f"Revoke {args.name}? [y/N] ").strip().lower() != "y":
                print("Revoke cancelled.")
                return
            print("Device revoked." if store.revoke(args.name) else f"No paired device named {args.name}.")
            return
        if action == "setup":
            from agent.secret_scope import get_secret
            from hermes_cli.gateway_setup_wizard import save_env_values

            if not get_secret("HANDS_RELAY_SEED"):
                save_env_values(HANDS_RELAY_SEED=secrets.token_hex(32))
                print("Relay seed saved. Restart the gateway and dashboard.")
            else:
                print("Relay seed is already set.")
            # Before the prompt, so every run shows them, an aborted prompt included.
            print("Select the Hands backend with: hermes config set terminal.backend hands")
            print("Set desktop placement with: hermes config set bot_desktop.placement gateway")
            print(
                "Optional owner opt-in for witness H help: H sends quoted device text as a user message "
                "to the saved owner chat and starts an agent turn. Asking the model to relay it and wait "
                "cannot guarantee that the model will avoid tool calls."
            )
            print(
                "To opt in, run: hermes config set "
                "plugins.entries.hermes-hands.allow_gateway_injection true"
            )
            print("Then restart the gateway and the dashboard.")
            owner_id = input("Owner Telegram user id: ").strip()
            if owner_id:
                ctx.set_config("owner_ids", [f"telegram:{owner_id}"])
                print(f"Owner saved: telegram:{owner_id}")
            else:
                print("Owner id was not saved.")
            return
        if action == "doctor":
            failures = 0

            def check(label: str, passed: bool, fix: str) -> None:
                nonlocal failures
                if not passed:
                    failures += 1
                print(f"{'PASS' if passed else 'FAIL'} {label}" + ("" if passed else f": {fix}"))

            backend = commands.terminal_backend()
            raw_dashboard_url = str(
                ctx.get_config("dashboard_url", default=DEFAULT_DASHBOARD_URL) or ""
            ).strip()
            dashboard_url = commands._normalise_public_url(raw_dashboard_url) or raw_dashboard_url
            public_url, _ = commands._resolve_public_url()
            basic_fix = commands.basic_auth_fix()
            check(
                "terminal.backend is hands",
                backend == "hands",
                f"It is {backend or 'not set'}. Run hermes config set terminal.backend hands, then restart the gateway.",
            )
            check(
                "dashboard_url is loopback",
                commands.loopback_url(dashboard_url),
                f"It is {dashboard_url or 'not set'}. The gateway sends its local bearer and every job script "
                f"there, so it must be a loopback address such as {DEFAULT_DASHBOARD_URL}.",
            )
            # /local/state proves the route is mounted, the seed matches and the relay answers; it
            # also starts the relay, which writes its first heartbeat row before it replies.
            try:
                client.state()
                relay_error = ""
            except client.HandsError as exc:
                relay_error = str(exc)
            check("Relay answers at dashboard_url", not relay_error, relay_error)
            if commands.loopback_url(public_url):
                public_fix = (
                    f"It is {public_url}. A loopback URL pairs only on the gateway host itself; "
                    "leave dashboard.public_url unset for same-host testing, or set it to the https URL "
                    "of the Hands host."
                )
            elif commands._parsed_http_url(public_url) is not None:
                public_fix = (
                    f"It is {public_url}. The device refuses a non-loopback http pairing URL, so set "
                    "dashboard.public_url to the https URL of the Hands host."
                )
            else:
                public_fix = (
                    f"It is {public_url}. Set dashboard.public_url to the https URL of the Hands host, "
                    "or unset it for same-host testing."
                )
            check(
                "dashboard.public_url is https or unset",
                not public_url or commands.https_url(public_url),
                public_fix,
            )
            check(
                "dashboard.basic_auth on the public host",
                not public_url or not basic_fix,
                basic_fix,
            )
            check(
                "Relay heartbeat row is visible after /local/state",
                store.relay_alive(),
                "Fix the relay check first."
                if relay_error
                else "The relay answered but wrote no heartbeat row in this HERMES_HOME, so the gateway "
                "and the dashboard use different plugin data directories.",
            )
            from hermes_cli.config import load_config_readonly

            entry = load_config_readonly()
            for key in ("plugins", "entries", "hermes-hands"):
                entry = entry.get(key) if isinstance(entry, dict) else None
            if isinstance(entry, dict) and entry.get("allow_gateway_injection") is True:
                print("PASS Witness H help gateway injection is explicitly enabled")
            else:
                print(
                    "WARN Witness H help is unavailable. Optional owner opt-in: H starts an agent "
                    "turn in the saved owner chat. To enable it, run hermes config set "
                    "plugins.entries.hermes-hands.allow_gateway_injection true, then restart the gateway. "
                    "Leave it disabled if you do not want device help text to trigger agent turns."
                )
            # Non-zero return exits via hermes_cli/main.py:3533-3537.
            return 1 if failures else 0

    ctx.register_cli_command("hands", "Manage Hermes Hands", setup_parser, handler)
