from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import config, executor, policy, receipt
from .console import (
    TerminalConsole,
    WITNESS_CAPABILITIES,
    WITNESS_CONSOLE_CLOSED,
    WITNESS_DECLINED,
    WITNESS_START_PROMPT,
    WITNESS_STOPPED_BEFORE_START,
    sanitize_text,
    witness_consent_copy,
)
from .keys import get_or_create, remove as remove_key
from .protocol import PROTOCOL_VERSION, R2D, b64u, canonical_json, fresh, sign, unb64u, verify_request
from . import service

API = "/api/plugins/hermes-hands"


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(sanitize_text(message))

    def _print_message(self, message, file=None):
        if message:
            message = sanitize_text(message, keep="\n\t")
        super()._print_message(message, file)


def _pair(url: str, name: str, code: str, *, force: bool = False) -> int:
    if "HERMES_HANDS_JOB" in os.environ:
        print("pair is unavailable from a Hermes Hands device job", file=sys.stderr)
        return 1
    base_url = url.rstrip("/")
    if base_url.endswith(API):
        base_url = base_url[: -len(API)].rstrip("/")
    parsed_url = urlparse(base_url)
    loopback = parsed_url.hostname == "localhost"
    if parsed_url.hostname:
        try:
            loopback = loopback or ipaddress.ip_address(parsed_url.hostname).is_loopback
        except ValueError:
            pass
    if parsed_url.scheme != "https" and not (parsed_url.scheme == "http" and loopback):
        print("Pairing requires an https URL unless the gateway host is loopback", file=sys.stderr)
        return 1
    if config.load().get("device_id") and not force:
        print("This device is already paired. Pass --force to replace the pairing.", file=sys.stderr)
        return 1
    pair_url = base_url + API + "/pair"
    private, public = get_or_create()
    body = {"name": name, "os": platform.platform(), "home": str(Path.home()), "public_key": b64u(public), "policy_hash": policy.digest(), "protocol": PROTOCOL_VERSION}
    body["sig"] = b64u(sign(private, canonical_json(body)))
    try:
        response = httpx.post(pair_url, content=canonical_json(body), headers={"Authorization": f"Bearer {code}", "Content-Type": "application/json"}, timeout=30)
    except httpx.HTTPError as exc:
        print(sanitize_text(f"Pairing request to {pair_url} failed: {exc}"), file=sys.stderr)
        return 1
    if response.status_code != 200:
        print(sanitize_text(f"Pairing failed: HTTP {response.status_code} {response.text}"), file=sys.stderr)
        if response.status_code == 401:
            print("The pairing code is unknown, expired or already used, or the dashboard was not restarted after setup.", file=sys.stderr)
        return 1
    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("invalid pairing response")
        relay_key = unb64u(data["relay_public_key"])
        owner_label = data.get("owner_label", "")
        if (
            not isinstance(owner_label, str)
            or len(owner_label) > 80
            or (owner_label and owner_label.strip() != owner_label)
            or any(not char.isprintable() for char in owner_label)
        ):
            raise ValueError("invalid owner label")
        response_ts, response_nonce = int(response.headers["X-Hands-Ts"]), response.headers["X-Hands-Nonce"]
        response_path = urlparse(pair_url).path
        valid_signature = verify_request(relay_key, response.headers["X-Hands-Signature"], R2D, response_ts, response_nonce, "POST", response_path, response.content)
    except (KeyError, ValueError, TypeError):
        valid_signature = False
        data = {}
        relay_key = b""
        response_ts = 0
    if not re.fullmatch(r"[a-z0-9-]{1,40}", data.get("device_id", "")) or len(relay_key) != 32 or not fresh(response_ts, int(time.time())) or not valid_signature:
        print("Pairing failed: invalid relay signature", file=sys.stderr)
        return 1
    pairing = {
        "gateway_url": base_url + API,
        "device_id": data["device_id"],
        "relay_public_key": data["relay_public_key"],
    }
    if owner_label:
        pairing["owner_label"] = owner_label
    config.save(pairing)
    print(sanitize_text(f"Paired as {data['device_id']}"))
    return 0


def _run_agent(agent) -> int:
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        if "already running" not in str(exc):
            raise
        message = "Hermes Hands is already running on this computer. Close the other window and try again."
    except PermissionError as exc:
        if str(exc) != "unknown_device":
            raise
        message = "This computer is no longer paired with your helper. Ask your helper for a new pairing code."
    else:
        return 0
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    return 1


def _verify_receipt(path: Path, key_text: str | None) -> int:
    if key_text is None:
        if not config.device_id():
            print("This computer has no device key. Run this again with --key=<device public key>.", file=sys.stderr)
            return 1
        public_key = get_or_create()[1]
        key_name = "this device's key"
    else:
        try:
            public_key = unb64u(key_text)
        except ValueError:
            public_key = b""
        if len(public_key) != 32:
            print("Receipt verification failed: the key you gave is not a device public key.", file=sys.stderr)
            return 1
        key_name = "the key you gave"
    try:
        receipt.verify_receipt(path.expanduser(), public_key)
    except receipt.ReceiptKeyMismatch:
        print(sanitize_text(f"This receipt was not signed by {key_name}."), file=sys.stderr)
        return 1
    except receipt.ReceiptError as exc:
        print(sanitize_text(f"Receipt verification failed: {exc}"), file=sys.stderr)
        return 1
    print(sanitize_text(f"This receipt was signed by {key_name} and has not been changed."))
    print(sanitize_text(f"Key: {b64u(public_key)}"))
    return 0


def _doctor() -> int:
    failures = []
    bash = executor.resolve_bash()
    print(sanitize_text(f"bash: {bash or 'missing'}"))
    if not bash:
        failures.append("Git Bash")
    if bash:
        python_found = False
        for command in ("python3", "python"):
            try:
                probe = subprocess.run([bash, "-c", f'command -v {command}'], capture_output=True, text=True, encoding="utf-8", timeout=5)
            except subprocess.TimeoutExpired:
                print(sanitize_text(f"python in bash: command -v {command} timed out"))
                continue
            executable = probe.stdout.strip()
            if not executable:
                continue
            try:
                version = subprocess.run([bash, "-c", f'{command} -c "import sys; print(sys.version)"'], capture_output=True, text=True, encoding="utf-8", timeout=20)
            except subprocess.TimeoutExpired:
                print(sanitize_text(f"python in bash: {command} version probe timed out while starting"))
                continue
            if version.returncode == 0 and version.stdout.strip():
                print(sanitize_text(f"python in bash: {executable} ({version.stdout.strip().splitlines()[0]})"))
                if command == "python3":
                    python_found = True
                continue
            if "windowsapps" in executable.lower():
                print(sanitize_text(f"python in bash: {executable} is the WindowsApps alias and did not run"))
            else:
                print(sanitize_text(f"python in bash: {executable} did not run ({version.stdout.strip() or version.stderr.strip()})"))
        if not python_found:
            failures.append("working python3 in Git Bash")
    git_bash = shutil.which("git")
    print(sanitize_text(f"git: {git_bash or 'missing'}"))
    if sys.platform == "win32" and not git_bash:
        failures.append("git for Windows")
    try:
        import keyring
        print(sanitize_text(f"keyring: available ({keyring.get_keyring().__class__.__name__})"))
    except ImportError:
        print("keyring: unavailable; using protected file")
    url = config.gateway_url()
    if url:
        try:
            response = httpx.get(url, timeout=5)
            print(sanitize_text(f"gateway: reachable (HTTP {response.status_code})"))
        except httpx.HTTPError as exc:
            print(sanitize_text(f"gateway: unreachable ({exc})"))
            failures.append("gateway")
    else:
        print("gateway: not paired")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(prog="hermes-hands")
    subs = parser.add_subparsers(dest="command", required=True)
    pair = subs.add_parser("pair")
    pair.add_argument("gateway_url")
    pair.add_argument("--name", required=True)
    pair.add_argument("--code", required=True)
    pair.add_argument("--force", action="store_true")
    serve = subs.add_parser("serve")
    serve.add_argument("--allow-screen", action="store_true")
    serve.add_argument("--witness", action="store_true")
    serve.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    subs.add_parser("status")
    subs.add_parser("doctor")
    install_service = subs.add_parser("install-service")
    install_service.add_argument("--dry-run", action="store_true")
    install_service.add_argument("--remove", action="store_true")
    install_service.add_argument("--allow-screen", action="store_true")
    pol = subs.add_parser("policy")
    pol.add_argument("action", choices=("show", "reset"))
    subs.add_parser("unpair")
    receipt_command = subs.add_parser("receipt")
    receipt_subs = receipt_command.add_subparsers(dest="receipt_action", required=True)
    verify_receipt = receipt_subs.add_parser("verify")
    verify_receipt.add_argument("file", type=Path)
    verify_receipt.add_argument("--key", help="Device public key. Use --key=<key> if the key starts with a dash.")
    args = parser.parse_args(argv)
    if args.command == "pair":
        return _pair(args.gateway_url, args.name, args.code, force=args.force)
    if args.command == "serve":
        if args.witness:
            if args.service:
                if sys.stderr is not None:
                    print("Witness mode cannot run in service mode", file=sys.stderr)
                return 1
            if Path(sys.executable).stem.casefold() == "pythonw":
                if sys.stderr is not None:
                    print("Witness mode cannot run under pythonw", file=sys.stderr)
                return 1
            if sys.stdin is None or sys.stdout is None or not sys.stdin.isatty() or not sys.stdout.isatty():
                if sys.stderr is not None:
                    terminal = "Command Prompt or PowerShell" if sys.platform == "win32" else "terminal"
                    print(f"Open a normal {terminal} window and run this again.", file=sys.stderr)
                return 1
            if not config.device_id() or not config.gateway_url():
                parser.error("pair this device first")
            console = TerminalConsole()
            pairing = config.load()
            owner_label = pairing.get("owner_label", "")
            gateway_host = urlparse(config.gateway_url()).netloc or "unknown gateway"
            console.write(witness_consent_copy(owner_label, gateway_host))
            agent = None
            try:
                from .loop import DeviceLoop
                from .janitor import start as start_janitor

                agent = DeviceLoop(allow_screen=False, console=console)
                consent = agent.console_owner.startup_consent(WITNESS_START_PROMPT)
                if consent is None:
                    console.write(WITNESS_CONSOLE_CLOSED)
                    return 1
                if consent.strip() in ("S", "s"):
                    console.write(WITNESS_STOPPED_BEFORE_START)
                    return 0
                if consent.strip().casefold() != "y":
                    console.write(WITNESS_DECLINED)
                    return 0
                with agent._stop_lock:
                    if agent.stop_event.is_set():
                        console.write(WITNESS_STOPPED_BEFORE_START)
                        return 0
                    agent.witness = True
                    agent.session_state = "active"
                    agent.capabilities = list(WITNESS_CAPABILITIES)
                start_janitor(witness=True)
                return _run_agent(agent)
            except KeyboardInterrupt:
                return 130
            finally:
                if agent is not None:
                    agent.console_owner.close()
        from .loop import DeviceLoop
        from .janitor import start as start_janitor

        if not config.device_id() or not config.gateway_url():
            parser.error("pair this device first")
        try:
            start_janitor()
            agent = DeviceLoop(allow_screen=args.allow_screen)
        except KeyboardInterrupt:
            return 130
        return _run_agent(agent)
    if args.command == "receipt":
        return _verify_receipt(args.file, args.key)
    if args.command == "status":
        print(sanitize_text(json.dumps({"paired": bool(config.device_id()), "device_id": config.device_id(), "gateway_url": config.gateway_url()}, indent=2), keep="\n"))
        return 0
    if args.command == "doctor":
        return _doctor()
    if args.command == "install-service":
        return service.install(dry_run=args.dry_run, remove=args.remove, allow_screen=args.allow_screen)
    if args.command == "policy":
        if args.action == "show":
            for item in policy.patterns():
                print(sanitize_text(item))
        else:
            if "HERMES_HANDS_JOB" in os.environ:
                print("policy reset is unavailable from a Hermes Hands device job", file=sys.stderr)
                return 1
            print(sanitize_text(policy.reset()))
        return 0
    if args.command == "unpair":
        if "HERMES_HANDS_JOB" in os.environ:
            print("unpair is unavailable from a Hermes Hands device job", file=sys.stderr)
            return 1
        config.save({})
        remove_key()
        print("Device unpaired")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
