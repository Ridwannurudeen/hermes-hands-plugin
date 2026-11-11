# Add Hermes Hands to the plugin catalog

Draft pull request body for NousResearch/hermes-agent. The entry file is `docs/CATALOG-ENTRY.draft.yaml` in this repository, copied to `plugin-catalog/hermes-hands.yaml`. In the copy only `sha` changes, and the freeze notes are deleted.

## Release steps

This file is part of the tagged commit, so it never holds the commit hash or the check results. Do these steps in order, and paste the results into the pull request, not into this file.

1. Finish every commit for 0.2.0. The docs name the `v0.2.0` tag, so no file needs a commit hash. If the repository is published under a name other than `Ridwannurudeen/hermes-hands-plugin`, change that name everywhere first.
2. Create the annotated tag: `git tag -a v0.2.0 -m "Hermes Hands 0.2.0"`.
3. Run `python scripts/check-freeze.py`. It fails if a placeholder is left in the docs, other than the `sha` in the entry draft, or if the tag does not point at the checked out commit. It reads the files from the tag and fails if the checkout differs from the tag. If it fails, fix and commit, delete the local tag with `git tag -d v0.2.0`, create the tag again and rerun the check until it passes.
4. Push the commit and the tag. The plugin tests workflow runs the same check on the tag push. If the tag was already pushed when a problem turns up, do not move it: release v0.2.1 instead.
5. Read the commit the tag points to: `git rev-parse "v0.2.0^{commit}"`.
6. Copy the entry draft to `plugin-catalog/hermes-hands.yaml` in hermes-agent. In the copy, delete every line that starts with #, put that 40 character commit in `sha` and delete the comment after it. Nothing else changes.
7. Replace this section with a list of results: the commit in `sha`; `hermes plugins validate hermes-hands --install-deps` and `hermes plugins doctor` at that commit, with warnings; `scripts/validate_plugin_catalog.py plugin-catalog/hermes-hands.yaml`; `scripts/scan_plugin_payloads.py` on that tree; the full test run against Hermes 0.23.0 at that commit (passed, skipped, warnings); links to the public device and plugin workflow runs for that commit; and whether `hermes-hands` 0.2.0 is on PyPI under a name the maintainer owns. Until it is, every doc leads with the git install at the tag, and the sentences that say the package is not on PyPI yet stay.

## What it does

Hermes Hands lets a helper work on a paired Windows or Linux computer from chat while Hermes stays on a Linux or WSL gateway. It registers a terminal backend, so `terminal`, `read_file`, `write_file`, `patch`, `search_files` and `execute_code` run on the device selected for the chat. It adds `hands_screenshot`, `hands_devices` and `hands_checkup`.

The device runs a separate agent, the `hermes-hands` Python package from the `device` folder of the same repository. It is not on PyPI yet. It connects out over HTTPS and has no inbound listening port. Requests in both directions are signed with Ed25519 keys pinned at pairing. Device targets fail closed when offline, revoked or unreachable; a device command never falls back to the gateway.

## Witness mode

The person at the computer starts `hermes-hands serve --witness` in an interactive terminal. The console names the helper by the label given at pairing, says the helper can run commands and change files only after approving each one, and asks `Start? Type Y or N, then press Enter:`. Every command appears on the person's screen before it runs. Each screenshot needs session permission and a fresh local answer within 30 seconds. Typing `S` and Enter stops the session. Typing `H` and Enter sends the helper up to three short messages. Sessions end after 30 minutes and leave a text receipt and a signed JSON receipt.

While a witness session is active, the plugin's `pre_tool_call` hook asks the helper to approve every tool call that reaches the device, read only commands included, and blocks every tool outside a short safe list and the approval list. It blocks shell composition, script launchers, shell state builtins, patch directives, non-replace patches, common startup persistence that would outlast the session (startup and autostart folders, shell profiles, cron, registry Run keys, scheduled task creation, systemd enable), and arguments with hidden characters or secrets. Other logon methods, such as `sc create` or the `UserInitMprLogonScript` registry value, are not on that list and reach the helper's approval. The whole approval text must fit in 300 characters so no chat surface cuts it; a longer call is refused, not shortened. The hook blocks all device tools while approvals are off, yolo mode is on, an unattended context would approve on its own, or any other `pre_tool_call` hook or `tool_execution` middleware is registered, because nobody would see the call that runs. Such a hook can come from another plugin (security-guidance and disk-cleanup, which ship with Hermes, are two; the fix is `hermes plugins disable <name>`), from an allowed `pre_tool_call` shell hook under `hooks:` in `config.yaml`, or from a `hooks.outbound` webhook whose `events` include `pre_tool_call` (the fix is to remove that entry or event; `hermes hooks list` shows both). Each fix needs a restart. The plugin's own `tool_execution` middleware only carries the hook's decision into the device call.

## Rule 12: approvals

The hook never approves anything itself. It returns either block or approve with the full approval text, and every approve reaches a person through Hermes's approval flow. Session and Always choices on a witness approval do not carry over, because every approval uses a fresh rule key; each Always tap leaves an unused `command_allowlist` entry, which the README tells the owner they can delete. Outside a witness session the plugin adds no approval of its own and Hermes's normal approval rules apply.

## Rule 13: disclosures

- Runs shell commands and file operations on the paired device as its logged in user. That user's files, credentials included, are reachable. Witness mode is not a sandbox, and a compromised helper account or gateway can still command paired devices.
- Long running processes: the relay inside the dashboard process, a help poller in the gateway, and the device agent. On Linux, a process that moves to a new session or process group can outlive a stop or revoke. If the small watcher process the agent starts for each job group has died or stalled for more than a second, a process started late by a background command can also outlive Stop.
- Stored credentials: the device keeps its signing key in the OS keyring with the `keyring` extra, otherwise in an owner only file. The gateway stores device public keys and pairing metadata, and reads its relay seed through a declared `config_schema` secret with `get_secret`.
- Command text in the device console and receipts can include sensitive arguments or file content. Device output logs stay on the device for up to 7 days.
- Screenshots are cached on the gateway for up to 24 hours, sent to the configured vision model when described, and sent to the chat platform when delivered.
- `hands_checkup` resolves `example.com` and opens connections to 1.1.1.1, 8.8.8.8 and 9.9.9.9 on port 443.
- Optional `H` help, off unless the owner sets `allow_gateway_injection`, puts quoted device text into a user-role model turn in the saved owner chat. It is a prompt-injection surface.
- No telemetry.
- Hermes's dashboard token seam offers every token route to every token provider, so Hands credentials also pass other plugins' token routes. The README documents the revoked key window and why this needs a core change.

## Rule 9: Hermes internals

`hermes plugins validate` warns about imports of Hermes internals and one private attribute access, and the plugin also reads the plugin manager's hook and middleware lists, the approval state and the message injector. No core function or attribute is replaced or rebound. Every coupling, with the public seam that would replace it, is listed in [the hook request](https://github.com/Ridwannurudeen/hermes-hands-plugin/blob/v0.2.0/docs/HOOK-REQUEST-ISSUE.md). That request is a draft and has not been opened upstream.

## Compatibility

Tested with Hermes 0.23.0 only; `requires_hermes` is `>=0.23.0` in both the manifest and the entry. The gateway supports Linux and WSL. Devices are native Windows with Git Bash and Linux; macOS devices are not supported. The device installs with `pipx install "git+https://github.com/Ridwannurudeen/hermes-hands-plugin@v0.2.0#subdirectory=device"` (the v0.2.0 release tag), or with `pipx install "hermes-hands==0.2.0"` once 0.2.0 is on PyPI; screenshots work after that install on a desktop session, with the person's yes for each shot. Witness mode needs an interactive terminal and cannot run as a service.

## What was tested live

Live checks ran on earlier builds of 0.2.0. A Hermes 0.23.0 gateway in WSL and a native Windows 11 laptop covered pairing, terminal work, byte exact file transfer, timeouts, offline failure, witness consent, screenshot grant and decline, checkup, signed receipts and stop. Linux under WSL2 covered commands, files, timeout, witness consent and stop, receipts and revoke. A public HTTPS test covered pairing, a command, checkup, and offline and revoked refusal in normal mode. An owner run on Telegram covered screenshot delivery, decline, timeout, `H` help delivery and stop.

Not yet tested live on this build: a witness session with the current console wording and approval of every call, a screenshot after a fresh device install, Linux screenshots, a separate native Linux host, and Windows scheduled task logon startup.
