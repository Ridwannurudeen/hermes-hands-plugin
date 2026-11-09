# Hermes Hands

Help someone's computer from your phone. They see each command and hold the off switch.

Hermes runs on a Linux or WSL gateway. A small agent on a paired Windows or Linux computer receives signed terminal, file, checkup, and screenshot requests over outbound HTTPS. The device has no inbound listening port. Offline, revoked, and unreachable device targets fail closed.

## Witness mode

The person at the computer starts `hermes-hands serve --witness` in an interactive terminal and types `y` or `Y` to consent. They see timestamped command text and outcomes, can press `H` to ask for help, and can stop with `S`. Sessions end after 30 minutes and write a text receipt plus a signed JSON receipt.

Help text is filtered, capped at 200 characters, and quoted as untrusted data in a user-role model turn in the saved helper conversation. It is not a fixed direct notification. Asking the model to relay it does not enforce a no-tool boundary; device help remains a prompt-injection surface. Acceptance by the gateway is not proof of delivery to Telegram.

The gateway asks the helper to approve file reads, searches, writes, patches, and terminal commands outside an exact read-only list. Approval reasons show the command or path; search approvals include the pattern and target. Details are sanitized and capped at 300 characters. Common script launchers, shell metacharacters, and `execute_code` are blocked in active witness sessions. Screenshots need session permission and fresh local consent for every capture. A screenshot request expires after 30 seconds without an answer.

`hands_checkup` returns fixed structured health facts. Windows print queues and known reboot markers are supported. Pending Windows Update availability is unsupported. Five Windows troubleshooting playbooks start with diagnostics and ask for approval before a repair.

## Install and configure

Install Hermes 0.23.0 or later on the gateway. Before catalog admission, install a reachable repository with `hermes plugins install Ridwannurudeen/hermes-hands/hermes-hands --enable`. Then run `hermes hands setup`, apply its backend and placement settings, and start the dashboard on loopback. A device on another machine requires the HTTPS relay route described in the [full setup guide](../README.md#gateway).

The device needs Python 3.11 or later and Bash. Windows uses Git for Windows. Before a PyPI release, run `pipx install ./device` from a reachable repository checkout. Pair using the command printed by `/hands pair <name>`, start `hermes-hands serve --witness`, and select it from a direct owner chat with `/hands use <name>`. Run only one device agent per device home.

See the [full guide](../README.md) for prerequisites, nginx configuration, policy acceptance after upgrades, doctor checks, data retention, and uninstall steps.

## Limits and data handling

The device runs with its logged in user's permissions. This is not a sandbox and does not protect against a compromised helper account or gateway. Linux detached processes can survive a stop. Native Windows and Linux under WSL2 were tested live; macOS devices and native Windows gateways are unsupported. The service installer supports Windows Task Scheduler; witness mode requires a real interactive terminal.

Command text is printed and saved in receipts and can contain sensitive arguments or file content. Receipts do not include command output or prove exactly which files changed. Device output logs are stored locally. Screenshots are cached on the gateway, sent to the configured vision model when described, and sent to the chat platform when delivered. The device key stays in its OS keyring when the optional keyring package is installed, otherwise in a protected local file. The gateway stores public device keys and pairing metadata, and obtains its relay seed through Hermes's declared secret configuration.

Hermes Hands registers a terminal backend, dashboard authentication provider, tools, chat and CLI commands, a skill, and a `pre_tool_call` hook. Some Hermes 0.23.0 internals are still imported; file tools are recognized through call frames and their cache is cleared on target changes. The [upstream hook request](../docs/HOOK-REQUEST-ISSUE.md) describes the missing public seams. Hermes's dashboard token-provider scope limitation and the full trust model are disclosed in the [security model](../README.md#security-model).

No telemetry is collected. Checkup network probes contact fixed DNS and reachability targets. For detailed verification and the remaining live checks, see [live verification](../README.md#live-verification).

## Verification

The full real-Hermes 0.23.0 suite on 9 November 2026 completed with **651 passed, 4 skipped, 1 Starlette/httpx deprecation warning in 316.48s**. The final shared-environment run had 538 passed and 18 skipped in 77.81s. Its earlier result at `fcd5b16` was 527 passed and 18 skipped; this environment excludes checks needing Hermes source. From the repository root, using an environment with Hermes's test dependencies:

```sh
PYTHONPATH=/path/to/hermes-agent python -m pytest hermes-hands/tests device/tests -q -p no:cacheprovider
```

Plugin validation reported a safe security scan, matching capabilities, and a clean Desktop SDK surface, with warnings for 15 private-core import sites and in-process dashboard authentication. Plugin doctor passed with three tools and one hook.

A fresh in-process Linux checkup under WSL returned 27 schema-v1 facts, no inferences, and unsupported for an incomplete TEMP scan. This rechecked the fact collector, not the full relay or witness transport. Human Telegram help delivery, screenshot delivery, and the final prompt/transcript changes still need live verification.
