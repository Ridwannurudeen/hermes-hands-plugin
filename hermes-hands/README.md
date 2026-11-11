# Hermes Hands

Help someone's computer from your phone. In witness mode they see each command before it runs and hold the off switch.

Hermes runs on a Linux or WSL gateway. A small agent on a paired Windows or Linux computer receives signed terminal, file, checkup, and screenshot requests over outbound HTTPS. The device has no inbound listening port. Offline, revoked, and unreachable device targets fail closed.

## Witness mode

The person at the computer starts `hermes-hands serve --witness` in an interactive terminal, reads who wants to help and what they can do, and types `Y` and presses Enter to consent. They see timestamped command text and outcomes, can type `H` and press Enter to send the helper a message, and can type `S` and press Enter to stop. Sessions end after 30 minutes and write a text receipt plus a signed JSON receipt.

Optional `H` help requires the gateway owner to run `hermes config set plugins.entries.hermes-hands.allow_gateway_injection true` in the intended Hermes profile and restart the gateway, plus a saved owner chat origin from `/hands use <name>`. Setup prints this opt-in command but never enables it. The permission belongs at the plugin entry root, not under `settings`. Leave it disabled if device help text should not start agent turns. `hermes hands doctor` reports `WARN` when this permission is absent, false, or a string, without changing its exit status; other Hands features do not require it.

Help text is filtered, capped at 200 characters, and quoted as untrusted data in a user-role model turn in the saved helper conversation. It is not a fixed direct notification. Asking the model to relay it does not enforce a no-tool boundary; device help remains a prompt-injection surface. Acceptance by the gateway is not proof of delivery to Telegram.

During an active witness session the gateway hook blocks every tool that is not on a short safe list or the approval list. Every `terminal`, `read_file`, `search_files`, `write_file`, `patch`, `vision_analyze`, `video_analyze`, `hands_checkup` and `hands_screenshot` call needs the helper's approval, read only commands included, and each step needs its own approval. The hook blocks shell metacharacters, script launchers and shell state builtins, patch directives, non-replace patches, common startup persistence that would outlast the 30 minute session (startup and autostart folders, LaunchAgents, shell profiles, cron, registry Run keys and imports, scheduled task creation, `systemctl enable`, and any terminal command that names a startup path), and arguments with hidden characters or secrets. Other logon methods, such as `sc create` or the `UserInitMprLogonScript` registry value, are not blocked and reach the helper's approval. It blocks all device tools while approvals are off, yolo is on, or any other `pre_tool_call` hook or `tool_execution` middleware is registered. For the session, turn off such a plugin with `hermes plugins disable <name>` (security-guidance and disk-cleanup, which ship with Hermes, register one), or remove a `pre_tool_call` shell hook from `hooks:` or `pre_tool_call` from a `hooks.outbound` webhook's `events` in `config.yaml`, then restart Hermes. `hermes hooks list` shows those hooks. The whole approval text must fit in 300 characters; a longer call is refused, not shortened, and the refusal names the longest argument. Prefer short `~/` paths. Session and Always on a witness approval do not carry over, and Always leaves an unused `command_allowlist` entry the owner can delete.

Screenshots work after a normal install, but only with the person's yes for each shot and only on a desktop session; a headless Linux machine has no screen to capture. They need session permission and fresh local consent for every capture. A screenshot request expires after 30 seconds without an answer.

`hands_checkup` returns fixed structured health facts. Windows print queues and known reboot markers are supported. Pending Windows Update availability is unsupported. Five Windows troubleshooting playbooks start with diagnostics and ask for approval before a repair.

## Install and configure

Install Hermes 0.23.0 on the gateway; Hermes Hands was tested with that version only. Before catalog admission, install it at the v0.2.0 release with `hermes plugins install Ridwannurudeen/hermes-hands-plugin/hermes-hands --ref <commit> --enable`, where `<commit>` is the 40 character commit that `git ls-remote https://github.com/Ridwannurudeen/hermes-hands-plugin "refs/tags/v0.2.0^{}"` prints. Hermes takes only a full commit for `--ref`, not a tag name, so the gateway plugin and the device agent come from the same tag. Then run `hermes hands setup`, apply its backend and placement settings, and start the dashboard on loopback. A device on another machine requires the HTTPS relay route described in the [full setup guide](../README.md#gateway).

The device needs Python 3.11 or later and Bash. Windows uses Git for Windows. Install the device agent from this repository with `pipx install "git+https://github.com/Ridwannurudeen/hermes-hands-plugin@v0.2.0#subdirectory=device"` (the v0.2.0 release tag), which needs Git. To keep its key in the OS keyring, also run `pipx inject hermes-hands "keyring>=24,<26"`. The package is not on PyPI yet; once 0.2.0 is, `pipx install "hermes-hands==0.2.0"` installs the same version. Pair using the command printed by `/hands pair <name> --owner-label "<helper name>"`, start `hermes-hands serve --witness`, and select it from a direct owner chat with `/hands use <name>`. Run only one device agent per device home.

For the Desktop pane, open **Capabilities > Plugins**, search for **Hands**, and enable the **Desktop** part of **Hermes Hands**. It starts disabled in a fresh browser origin. Open a conversation to select its target or pair a device; the status chip follows that conversation's target.

See the [full guide](../README.md) for prerequisites, nginx configuration, policy acceptance after upgrades, doctor checks, receipt verification, data retention, threat model limits and uninstall steps.

## Limits and data handling

The device runs with its logged in user's permissions. This is not a sandbox and does not protect against a compromised helper account or gateway. Plain `hermes-hands serve` has no local consent, transcript or stop prompt; use `--witness` when someone else is at the computer. Linux detached processes can survive a stop. Native Windows and Linux under WSL2 were tested live; macOS devices and native Windows gateways are unsupported. The service installer supports Windows Task Scheduler; witness mode requires a real interactive terminal.

Command text is printed and saved in receipts and can contain sensitive arguments or file content. Receipts do not include command output or prove exactly which files changed, and a hard kill of the agent leaves no receipt. Device output logs are stored locally. Screenshots are cached on the gateway, sent to the configured vision model when described, and sent to the chat platform when delivered. The device key stays in its OS keyring when the optional keyring package is installed, otherwise in a protected local file. The gateway stores public device keys and pairing metadata, and obtains its relay seed through Hermes's declared secret configuration.

Hermes Hands registers a terminal backend, dashboard authentication provider, tools, chat and CLI commands, a skill, a `pre_tool_call` hook, and a `tool_execution` middleware that carries the hook decision into the call. Some Hermes 0.23.0 internals are still imported or read; file tools are recognized through call frames and their cache is cleared on target changes. The [upstream hook request](../docs/HOOK-REQUEST-ISSUE.md) describes the missing public seams. Hermes's dashboard token-provider scope limitation and the full trust model are disclosed in the [security model](../README.md#security-model).

No telemetry is collected. Checkup network probes resolve `example.com` and connect to 1.1.1.1, 8.8.8.8 and 9.9.9.9 on port 443. For the live checks and what remains untested, see [live verification](../README.md#live-verification).

## Verification

From the repository root, using an environment with Hermes's test dependencies:

```sh
PYTHONPATH=/path/to/hermes-agent python -m pytest hermes-hands/tests device/tests -q -p no:cacheprovider
```

`hermes plugins validate` warns about each import of a Hermes internal and one private attribute access, which the hook request lists, and reports that dashboard authentication runs in the dashboard process. The live checks in the full guide ran on earlier builds of 0.2.0 and say which parts of this build still need a live run.
