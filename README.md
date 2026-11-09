# Hermes Hands

Help someone's computer from your phone. They see each command and hold the off switch.

Hermes Hands pairs a Windows or Linux computer with a one-time code. Hermes runs on a Linux or WSL gateway; terminal and file tools run on the paired computer. In optional witness mode, the person at that computer gives local consent, sees a timestamped command transcript, approves each screenshot, and can stop the session with S. The device connects out over HTTPS and does not listen for inbound connections. If a device is offline, revoked, or the relay is unreachable, the device command fails and is not sent to another target.

**Beyond one laptop:** use the same pairing model for another workstation, a GPU box, or a Pi.

## Quick start

1. On the gateway host (Linux, or Windows inside WSL), install the plugin with `hermes plugins install Ridwannurudeen/hermes-hands-plugin/hermes-hands --enable`, then run `hermes hands setup` and follow its prompts. Once Hermes Hands is in the plugin catalog, `hermes plugins install hermes-hands` installs the reviewed version instead.

   For an unreleased checkout, install the plugin from a repository copy you can access. The device package is distributed separately. Before `hermes-hands==0.2.0` is published on PyPI, install it from a reachable checkout as shown in [Device](#device).
2. Run the two lines setup prints, `hermes config set terminal.backend hands` and `hermes config set bot_desktop.placement gateway`. Restart the gateway, and start the dashboard on loopback with `hermes dashboard --host 127.0.0.1 --port 9119 --no-open`. Any device that is not the gateway host needs the public HTTPS route in [Setup](#gateway); a loopback URL cannot pair a laptop on another machine.
3. Pair a named device with `/hands pair laptop` in a direct Telegram chat with the bot or `hermes hands pair laptop` on the gateway. On the device, run the printed `hermes-hands pair` command, then `hermes-hands serve`.
4. In a direct chat with the bot, run `/hands use laptop`.

## Versions

Hermes Hands 0.2.0 for the gateway plugin and device package, same version. Requires Hermes 0.23.0 or later.

## What it provides

| Capability | Hermes Hands |
|---|---|
| Device systems | Native Windows with Git Bash and Linux under WSL2, tested live; macOS devices are unsupported |
| Device install | Separate Python package; Hermes is needed only on the gateway |
| Connection | Outbound HTTPS long poll; no inbound device port |
| Signing | Ed25519 in both directions, with keys pinned at pairing |
| Shell and file tools | Routed to the device selected for the chat |
| Screenshot from chat | Built in tool; witness sessions require local consent for every capture |
| Local control | Optional witness consent, command transcript, stop key, and signed receipts |
| Relay unavailable | Device targets fail closed; `server` does not need the relay |

## Setup

### Gateway

The gateway runs on Linux, or on Windows inside WSL. A native Windows gateway is not supported.

1. Install Hermes 0.23.0 or later, then install and enable Hermes Hands with `hermes plugins install Ridwannurudeen/hermes-hands-plugin/hermes-hands --enable`. After Hermes Hands is admitted to the plugin catalog, install it from the catalog or with `hermes plugins install hermes-hands`, which installs the reviewed commit.
2. Run `hermes hands setup` on the gateway host. It creates the relay seed if missing and asks for the owner Telegram user ID. Configure Telegram and its owner access in Hermes.
3. Select the Hands terminal backend: `hermes config set terminal.backend hands`. Without it Hermes keeps its default `local` backend, every command runs on the gateway host, and `/hands use <device>` refuses to switch.
4. Set the placement line printed by setup: `hermes config set bot_desktop.placement gateway`. Without it, Hermes refuses to start browser and computer use tools under any plugin terminal backend, for every conversation in the profile.
5. Set the dashboard URL and authentication in Hermes configuration. Set `dashboard.public_url` to the public HTTPS URL of the Hands host that nginx serves in step 7, for example `https://hands.example.com`, and configure `dashboard.basic_auth`. The dashboard accepts only loopback host names and the host of `dashboard.public_url`, and that host serves only the device routes, so you then use the dashboard UI over loopback or an SSH tunnel. Only `dashboard.basic_auth` works in this setup: redirect sign-in providers such as OAuth or OIDC send the browser back to `dashboard.public_url` plus `/auth/callback`, which the Hands host does not serve.
6. Restart the gateway, and start the dashboard on loopback, for example: `hermes dashboard --host 127.0.0.1 --port 9119 --no-open`. Restart both again whenever setup creates the seed.
7. For devices that reach the gateway over the internet, expose only the device pair and poll routes through nginx on the Hands host. Replace the example host and TLS certificate paths with your own existing certificate configuration.

```nginx
server {
    listen 443 ssl;
    server_name hands.example.com;
    ssl_certificate /path/to/existing/fullchain.pem;
    ssl_certificate_key /path/to/existing/privkey.pem;
    client_max_body_size 4m;

    location ~ ^/api/plugins/hermes-hands/(device/|pair$) {
        proxy_pass http://127.0.0.1:9119;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        return 404;
    }
}
```

`client_max_body_size 4m;` lets a screenshot of up to 2 MiB through; without it nginx refuses any request body over 1 MiB. `server_name` must be the host of `dashboard.public_url`, because the dashboard refuses any other host name. Do not add the `return 404` location to a host that serves anything else. Keep the dashboard bound to loopback. Do not expose `/local/*` or `/ui/*` through the public route.

Then run `hermes hands doctor`. It exits non-zero if any check fails: `terminal.backend` must be `hands`, `dashboard_url` must be a loopback address, the relay must answer there, `dashboard.public_url` (or `HERMES_DASHBOARD_PUBLIC_URL`) must be an `https` URL or unset, and the relay's heartbeat row must be visible after `/local/state`. When a public URL is set, `dashboard.basic_auth` needs a username and either a password or password hash; the corresponding `HERMES_DASHBOARD_BASIC_AUTH_*` variables override those config values. The heartbeat check shows that the gateway and the dashboard share a plugin data directory; `doctor` does not compare the two paths. It also checks the explicit gateway injection permission needed for optional witness `H` help; leaving that feature disabled produces a `WARN` that H help is unavailable and does not change the doctor exit status or disable other Hands features.

### Desktop pane

In the Hermes Desktop interface, open **Capabilities → Plugins**, search for **Hands**, and enable the **Desktop** part of **Hermes Hands**. The frontend part starts disabled in a fresh browser origin. The Hands pane shows relay and device state; its target selector and status chip follow the focused conversation. Open a conversation before choosing its target or pairing a device.

### Device

On Windows, in PowerShell:

1. Install Python and Git for Windows. Git for Windows provides Git Bash and its `cygpath` tool, which file deletes on a Windows device rely on:

   ```powershell
   winget install Python.Python.3.12
   winget install Git.Git
   ```

2. Open a new terminal so the updated PATH loads, then install pipx:

   ```powershell
   py -m pip install --user pipx
   py -m pipx ensurepath
   ```

3. Open a new terminal again, then install the device agent:

   ```powershell
   pipx install hermes-hands==0.2.0
   ```

   Before 0.2.0 is on PyPI, open a reachable repository checkout and run `pipx install ./device` from its root. This uses the local device package and does not require a release tag.

   To keep the device's private key in the OS keyring instead of a file, install it with `pipx install "hermes-hands[keyring]==0.2.0"`.

4. Make `python3` work inside Git Bash. In Git Bash, `python3 -c "import sys; print(sys.version)"` must print a Python version. The python.org build from step 1 has no `python3.exe`, so Git Bash finds the Microsoft Store alias instead, which only prints "Python was not found". Installing the Python Install Manager gives Git Bash a working `python3`; on the laptop used for the live checks it runs the Python 3.12 from step 1. `hermes-hands doctor` runs the same check in Git Bash and names the Store alias if that is what it finds.

Upgrading the device agent changes its default deny list, and with it the policy hash, so the relay refuses a device paired on an older version until the owner sends `/hands accept-policy <device>` once. It is a chat command (Telegram, the Desktop or the Hermes CLI chat); there is no `hermes hands accept-policy` command.

Pair using the command printed by `/hands pair laptop`, substituting the displayed URL, name, and code. Mint the code after the device is installed: it works once and expires after 10 minutes.

```powershell
hermes-hands pair https://hands.example.com --name laptop --code=ONE_TIME_CODE
hermes-hands serve
```

Run one `hermes-hands serve` per device; `serve` holds an exclusive lock on `~/.hermes-hands/serve.lock` and refuses to start if another `serve` process is already running for that device home. Screen capture is off by default; to opt in, run the agent as `hermes-hands serve --allow-screen`. To start the agent at logon instead, run `hermes-hands install-service`, which registers a Windows scheduled task that runs `pythonw -I -m hermeshands_device.cli serve`; add `--allow-screen` (`hermes-hands install-service --allow-screen`) to let that agent take screenshots. To change the flag later, stop the running task, remove it with `hermes-hands install-service --remove`, and install it again. `hermes-hands install-service --dry-run` prints the planned action.

Linux devices need Python 3.11 or later, pipx, and a Bash environment. Install `hermes-hands==0.2.0` (or `"hermes-hands[keyring]==0.2.0"`, or from a checkout before the release), pair using the command printed by `/hands pair <name>`, then run `hermes-hands serve`. The service installer is implemented for Windows Task Scheduler. Linux `serve --witness` uses an interactive TTY console. Commands, file I/O, timeout, witness consent, signed receipts, and revoke were tested live on Linux under WSL2. Linux screenshot capture was not tested live.

## Witness mode: help someone else's computer

Witness mode lets a paired device owner ask for help while keeping control at the keyboard. Pair the device first. Then start this command in an interactive terminal on that device:

```sh
hermes-hands serve --witness
```

The command requires stdin and stdout TTYs. It does not run under `pythonw` or as a service. The console shows the paired owner label when configured, otherwise the device ID, the gateway host, the 30 minute session limit, the available features, and the stop key. The person at the device must type `y` or `Y` at `Start witness mode? [Y/N]` to begin. `S` stops before the session starts. Other input leaves witness mode inactive.

To enable optional `H` help, the gateway owner must explicitly opt in on the gateway host, using the intended Hermes profile:

```sh
hermes config set plugins.entries.hermes-hands.allow_gateway_injection true
```

Restart the gateway after changing it. Setup prints this optional command but never enables the permission itself. Hermes requires the boolean `true` at the plugin entry root; putting it under `settings` does not grant permission. Leave it disabled if device help text should not start agent turns. This permission allows quoted device text to enter the saved owner chat as a user message and start an agent turn; it cannot guarantee that the model will avoid tool calls.

The session lasts at most 30 minutes. Press `S` or `s` to stop. Press `H` to write a help request, or Escape to cancel that request. Up to three help requests are accepted per session. The helper needs a saved owner chat origin from `/hands use` for the relay to accept a request, and the explicit gateway injection permission above for the gateway to deliver it. An accepted request is marked pending until the gateway delivers it. The device console says when the request was not sent or when delivery is still pending.

Help text is filtered to printable characters, capped at 200 characters, quoted as untrusted device data, and injected into the saved helper conversation as a user-role model turn. It is not a direct notification with fixed text. The model is asked to relay the message and wait, but that wording cannot enforce a no-tool boundary. Treat device help text as a prompt-injection surface; witness approvals still apply to subsequent tool calls. Gateway acceptance of an injected turn does not prove the reply reached Telegram.

The helper can request the built in `hands_checkup` tool. It returns structured device facts with `observed`, `unsupported`, or `error` availability. Its `inferences` list is currently empty. On Windows, the checkup can report aggregate print queue jobs and known pending reboot registry markers. It does not enumerate the Windows Update catalog, so `pending_updates` is unsupported. On Linux, Windows print queue and update facts are unsupported, while `pending_reboot` checks the known reboot marker files.

Screenshots require two separate permissions. The person first answers `y` or `Y` to allow screenshot requests for the session. Each screenshot then asks `Allow this screenshot?` and requires another `y` or `Y` within 30 seconds. A declined or unanswered request does not capture an image. After a timeout the console prints a decline line and can show a new request; input started before a fresh prompt cannot approve it. This session consent is separate from the normal `serve --allow-screen` setting.

The bundled `hands` skill contains five Windows troubleshooting playbooks. They start with diagnostics, state the limits of the live standard user checks, request owner approval for one repair, then recheck the result. Linux notes are read only comparisons and were not run live. The Windows checklist was tested as a standard user on Windows 11 Home. All listed diagnostics ran without elevation. No real repair was applied. The printer resume probe returned access denied even with `-WhatIf`, so permission to resume a real job is not established.

During an active witness session, the plugin's `pre_tool_call` hook blocks `execute_code`. For terminal commands, it also blocks shell metacharacters and a list of common script launchers. A small exact read only command list can run without owner approval. Other terminal commands and all `read_file`, `search_files`, `write_file`, or `patch` calls require owner approval. The approval reason includes the command or file path. Search approvals also identify the pattern and search target. Approval details are sanitized and limited to 300 characters. This parser is a guard rail; it does not classify every possible executable or script runtime.

The console timestamps its prompts and status lines. It prints command text as terminal and file jobs start, followed by their outcome. File tools can appear as the shell command Hermes generates for that operation. Local receipts retain the same command text, labels, timestamps, outcomes, checkup facts, and session end reason. They do not contain command output or an exact list of file changes. Command text can include sensitive arguments or file content, so treat receipts as private. The device writes a text receipt and a signed JSON receipt under `~/.hermes-hands/receipts/` and prints both paths. Verify the JSON file with:

```sh
hermes-hands receipt verify ~/.hermes-hands/receipts/session-name.json
```

`S` starts shutdown, cancels registered jobs, rejects work once the device enters its stopping state, and attempts a final relay heartbeat. A process detached into a separate session can outlive the witness session on Linux. The device agent runs with the logged in user's permissions. A compromised helper account or gateway can still issue requests to paired devices. Local consent and the stop key do not protect files from a compromised account.

## How this is different from a tech support scam

The person at the computer starts the witness session and can stop it locally. The helper cannot start or restart witness mode remotely. The session is time limited, and screenshot sharing needs session consent plus consent for every capture.

The gateway has an owner approval hook for device commands and file operations. It blocks `execute_code`, common script launchers, and shell metacharacters during an active witness session. It requires approval for commands outside its exact read only list and for file reads, searches, writes, and patches. The device process can access files allowed to the logged in account, including credentials, so witness mode is not a security sandbox.

The device connects out over HTTPS and does not open a listening port. Both sides sign requests with Ed25519 keys pinned at pairing. A local text receipt and signed JSON receipt record command text, session events, and outcomes. They do not contain command output or prove exactly what changed. A compromised helper account or gateway can still control paired devices, so the consent screen and stop key reduce risk but do not remove that risk.

Screenshot declines, local stops, session expiry, and unsupported job types return fixed plain language messages to the helper. The messages tell the model not to invent a cause or retry.

Optional on Windows: `winget install BurntSushi.ripgrep.MSVC` enables ripgrep features in search. `hermes-hands doctor` reports whether Git Bash and Python are available inside it. The device needs Python on Git Bash's PATH for `execute_code` and some file operations.

In Git Bash, a native Windows program turns a `/switch` argument into a path, so `cmd /c ...` runs nothing and still exits 0. Run such a program with `MSYS_NO_PATHCONV=1` in front and its switches written normally, with one slash: `MSYS_NO_PATHCONV=1 cmd /c dir`, `MSYS_NO_PATHCONV=1 tasklist /FO CSV`. Never double the slash (`//c`, `//F`): that spelling hides the command from Hermes's approval check, which matches only the single slash form. Under `MSYS_NO_PATHCONV=1`, write that program's path arguments in Windows form. The bundled `hands` skill tells the model the same.

## What runs on the device

With Hermes 0.23.0, Hands routes these tools through the selected device terminal backend: `terminal`, `execute_code`, `read_file`, `write_file`, `patch`, and `search_files`. `execute_code` needs Python available inside Git Bash. Hands also registers `hands_screenshot`, `hands_devices`, and `hands_checkup` as its own tools.

The target is selected for each terminal call. The first terminal result after a target change identifies the target and device home. Terminal commands on a device start in the device's home folder. A relative path in a file tool resolves against the device's current terminal folder, as on a local backend, except that a `terminal.cwd` configured on the gateway still wins; the bundled skill tells the model to prefer absolute device paths. `search_files` patterns reach the device exactly as the model wrote them. `/hands use server` switches terminal calls back to the gateway host. A chat that never chose a target uses `default_target`, which defaults to `server`; cron execution always uses `server`. The target belongs to the chat, so `/new` and `/reset` keep it: send `/hands use server` first when a fresh conversation should run on the gateway. A device command never falls back to the gateway.

## Known limits

- Hermes takes no file checkpoints under `terminal.backend: hands`, on any target including `server`, and `/rollback` is refused.
- If a background job's pid is in use on two targets at once, `process kill` refuses that pid instead of guessing, until one of the jobs exits.
- If the gateway loses the relay's reply to `/local/exec`, Hands has no job ID to poll or cancel, fails with exit 255, and reports that the command may have been queued and may run on the device; if the relay queued it, the relay cancels unfetched jobs after about 60 seconds.
- When the device agent restarts, the gateway notices within about 10 seconds and then fails a command the old agent had taken, saying it may have partly run.
- A file tool path written as `~/...` lands in the device home, but the tool result's `resolved_path` shows the gateway's home, because core expands `~` on the gateway.
- Switching targets calls `clear_file_ops_cache` for the task, which also clears Hermes's read tracker and file-state registry for that task. Stale-write and concurrent-edit checks from reads before the switch are lost, and overwriting an existing server file after switching back requires reading it again first.
- On Windows, revoking a device stops every job the agent started, foreground and background. On Linux the agent stops the process groups it started; a job that detached itself into a new session (for example with `setsid`) keeps running, so stop it on the device yourself.
- File tools (`read_file`, `write_file`, `patch`, and `search_files`) check their generated command against only the first four deny list entries, which are the self-protection rules (`.hermes-hands`, `hermes-hands` management commands, killing the agent PID, and stopping or removing the `HermesHands` task), not general shell words such as `sudo` or `shutdown`. A file path or `search_files` pattern whose text matches one of those self-protection rules is still refused with exit 126.
- A command handed to a connection the device can no longer read, for example during a Wi-Fi switch while the same agent process keeps running, is not delivered again; it fails when the gateway's terminal timeout ends.
- macOS is not a supported device platform.
- Linux device command, file, timeout, witness, receipt, and revoke paths were tested live under WSL2. A separate native Linux host and Linux screenshots have not been tested live. Linux witness mode needs an interactive TTY. The service installer supports Windows Task Scheduler only.
- `hands_checkup` can report Windows print queue jobs and known Windows reboot registry markers. It does not enumerate Windows Update availability, so `pending_updates` is unsupported. Linux reports Windows-only print queue and update facts as unsupported; its `pending_reboot` fact checks known reboot marker files.

## Security model

The relay is trusted; whoever controls the gateway and dashboard can command every paired device, and the signatures protect the path between them, not against a compromised gateway. Pairing and target switching from chat are owner gated. `/hands pair` and `/hands use <device>` work only in a direct chat with the bot, because a pairing code is a secret and a device target in a shared chat would apply to everyone in it; `/hands use server` works anywhere. When `owner_ids` is set, which `hermes hands setup` does, it alone decides who the owner is; only when it is empty does the platform's `allow_admin_from` list for that chat count. The device keeps its private signing key locally; the gateway stores device public keys. Requests have a 300 second freshness window and the relay's nonce cache keeps used nonces for 600 seconds. Pairing codes expire after 600 seconds and are single use.

Hermes's token seam offers every plugin token route to every token provider, and core's drain route checks neither the provider nor the scope. So a fresh bearer token signed by a paired or revoked device's key, a pairing code that is still unused, and the gateway's local bearer (derived from the relay seed, held by the gateway and the dashboard) also pass the token check on other plugins' token routes, such as the drain route on a Hermes install that enables it. A revoked device's key keeps that access until 1 hour after the relay first tells the device to stop, or 7 days after revocation, whichever comes first; pairing a new device with the same name does not shorten that window. Hands cannot limit that from a plugin; it needs a change in Hermes core.

Hermes's existing approval gate runs first. A device policy deny list adds a second guard. The relay checks the device policy hash against the hash recorded at pairing; if it changes, the relay refuses work until the owner accepts the changed policy. The deny list matches the text of each command, so it is best effort: it stops the commands it lists as they are usually written, and a command written to avoid it can still get through. It is a guard rail, not a sandbox.

The agent runs as the logged in device user. A same-user shell can read or change any file that user can access, including credentials. The deny list cannot isolate the agent from that user's permissions.

The device connects out and does not open a listening port. Ed25519 signatures authenticate requests in both directions. They detect forged or replayed requests between the paired device and relay but do not protect against a compromised gateway.

## Stored data and retention

The gateway stores the relay seed through Hermes's declared secret configuration, and stores device public keys and pairing metadata in the plugin database. It does not store device private keys. The device stores its Ed25519 private key in the OS keyring only when the agent was installed with the `keyring` extra (`pipx install "hermes-hands[keyring]==0.2.0"`); otherwise, as with the plain install, it uses `~/.hermes-hands/device.json`. The keyring service is `hermes-hands` and the entry username is `device-private`. The fallback file is restricted to the device user: an owner only ACL on Windows, mode 0600 elsewhere.

Device output logs are written under `~/.hermes-hands/out/` and the device agent deletes them after 7 days. Hermes's temporary shell and cwd files on the device (`hermes-snap-*.sh` and `hermes-cwd-*.txt` in the system temp folder and in a local Hermes install's `cache/terminal` folder, if one exists) are removed after 24 hours. Both cleanups run when `serve` starts and then hourly while it runs. Delete output logs sooner with `rm -rf ~/.hermes-hands/out` or remove selected files there.

Screenshots are written on the gateway under `$HERMES_HOME/cache/hermes-hands/`. Each new screenshot first removes screenshots in that folder older than 24 hours, so the last ones stay until the next capture. Remove them sooner by deleting the files in that folder. A captured screenshot is sent to your configured vision model provider when the model describes it, and to the chat platform when it is delivered to the chat.

## Latency

About 0.4 s per small command (p50 409 ms, p90 411 ms over 30 runs, measured twice) from a Hermes v0.23.0 gateway in WSL to a Windows 11 laptop on the same machine, network latency excluded. Most of what remains is Hermes's own per command shell wrapper and its exit polling.

## Why a plugin, not a skill

1. A terminal backend core routes terminal and file tools through the selected environment.
2. An authenticated relay routes work to paired devices and handles pairing.
3. A process on the laptop receives signed work and enforces its own device policy.
4. Per conversation target selection and the Desktop pane let users choose and inspect the active device.

A skill can explain how to use a feature, but cannot register a terminal backend, provide authenticated relay routes, run a laptop process, or enforce local policy.

The current hook API coupling and proposed public interfaces are documented in [the hook request issue](docs/HOOK-REQUEST-ISSUE.md).

## Tests and validation

The suite covers the gateway plugin and device agent. For the full integration run, use a Python environment with Hermes's test dependencies installed and point `PYTHONPATH` at a Hermes 0.23.0 source checkout:

```sh
PYTHONPATH=/path/to/hermes-agent python -m pytest hermes-hands/tests device/tests -q -p no:cacheprovider
```

On 9 November 2026, the full real-Hermes run completed with **651 passed, 4 skipped, 1 warning in 316.48s**. The warning is a Starlette/httpx deprecation. Plugin validation reported a safe security scan, matching capabilities, and a clean Desktop SDK surface. It warned about 15 private-core import sites and in-process dashboard authentication. Plugin doctor passed with three tools and one hook.

The final shared-environment run completed with 538 passed, 18 skipped in 77.81s. Historical shared-environment result at `fcd5b16`: 527 passed, 18 skipped. That smaller environment skips checks that require a real Hermes checkout; its count is not the final integration result.

The workflows in `.github/workflows/` cover the plugin on Ubuntu and Windows and the device on Ubuntu, Windows and macOS.

The device CI tests on Python 3.11 and 3.12. Plugin CI validates the plugin and doctor, runs the plugin suite against Hermes 0.23.0, validates catalog shape, scans plugin payloads, and checks Python changes for Windows footguns.

## Live verification

Live checks on a real Hermes 0.23.0 gateway in WSL and a native Windows 11 laptop confirmed pairing, terminal work on the laptop, persistent working directory, a 200,001 byte `write_file` round trip verified by SHA-256, timeout handling, offline failure without execution, and recovery after the device restarted. A witness run confirmed local consent, the exact read only command allowlist, write blocking, screenshot decline and grant, checkup results, and signed JSON receipt verification. A follow up run verified that `S` stopped the active child, the gateway received `stopped_by_person`, and the device exited 2.59 seconds after `S`; both receipt paths existed.

An owner-operated Telegram run confirmed device selection, a checkup report, an approval prompt showing the actual command, and a real file write. Linux under WSL2 passed terminal, byte-exact file I/O, 1 MB output, timeout, checkup transport, interactive witness consent and stop, signed receipt verification, and process-tree revoke. That earlier Linux checkup reported one TEMP-folder fact error. A fresh in-process WSL check on 9 November returned 27 schema-v1 facts with no inferences and marked the incomplete TEMP scan unsupported rather than error. The in-process recheck did not repeat the full Linux relay or witness flow.

A public HTTPS smoke test on 9 November 2026, from 16:22:41 to 16:24:23 WAT, used source candidate `5b6524607810dd0f4b9c79eeb95153a3532171b9`. A disposable Windows device paired with `https://hands.gudman.xyz`, came online, ran a harmless command with the expected marker and exit code 0, and returned a schema-v1 checkup with 27 facts. Offline and revoked device requests failed closed; revocation stopped the reconnected agent. This used normal device mode. It did not test witness mode, Telegram, a phone, a hotspot, or screenshots.

A later owner-operated Telegram witness run confirmed screenshot delivery to the phone after local consent, no image after an explicit decline, and an unanswered request expiring after 30 seconds. Optional `H` help reached the phone after the gateway owner explicitly enabled `allow_gateway_injection`. File reads and searches each presented a separate approval. Stopping an active `sleep 30` prevented a subsequent `pwd`; the text receipt and signed JSON receipt were verified. This run did not measure stop latency. The checkup delivered 27 facts and no inferences, but the model added unsupported cause guidance; the subsequent guidance fix has not yet been retested by the owner.

A separate normal-mode public HTTPS test passed all seven transport checks while the Windows device used a phone hotspot with VPN TUN active. It did not test Telegram witness mode over the public relay.

The official browser-hosted Desktop interface was tested with source candidate `d3cd2a147af1d749f74d2caefe855f46b0afaeb5`. Enabling the Desktop part loaded the pane and status chip, displayed the live relay and an offline paired device, and switched a disposable conversation from `server` to that device and back. The Pair button was disabled for an empty name and enabled for a supplied name; minting a code through the UI was not tested. Native Electron was not tested.

Remaining live checks are controlled stale-input recovery after a prompt timeout within the same session, the owner retest of checkup response guidance, and Windows scheduled-task installation and logon startup. The service installer's native Windows XML dry run passed, but no scheduled task was installed. macOS is not a supported device platform.

## Uninstall

On the device:

1. Stop the agent: press Ctrl+C in the terminal that runs `hermes-hands serve`, or, if the scheduled task started it, run `schtasks /End /TN HermesHands` in PowerShell. Then run `hermes-hands install-service --remove` if the task is installed.
2. Run `hermes-hands unpair`.
3. Remove `~/.hermes-hands`, and delete the keyring entry with service `hermes-hands` and username `device-private` if you installed the `keyring` extra.
4. Uninstall the package with `pipx uninstall hermes-hands`.

On the gateway:

5. Revoke the paired device with `hermes hands revoke laptop` (replace `laptop` with its name).
6. Set `terminal.backend` back to the backend you used before Hands, for example `hermes config set terminal.backend local`, and undo the placement line with `hermes config unset bot_desktop.placement`.
7. Remove the plugin with `hermes plugins remove hermes-hands`. This also removes its settings, `owner_ids` included.
8. Delete the relay seed with `hermes config unset HANDS_RELAY_SEED`.
9. Delete the plugin data and the screenshot cache: `$HERMES_HOME/plugin-data/hermes-hands/` and `$HERMES_HOME/cache/hermes-hands/`.
10. Restart the gateway and the dashboard.

## Install from Hermes

Before Hermes Hands is in the plugin catalog: [Install Hermes Hands](hermes://plugin/install?repo=Ridwannurudeen/hermes-hands-plugin/hermes-hands&enable=1)

After it is admitted, use the catalog link, which installs the reviewed commit: [Install Hermes Hands from the catalog](hermes://plugin/install?catalog=hermes-hands)

Repository: [Ridwannurudeen/hermes-hands-plugin](https://github.com/Ridwannurudeen/hermes-hands-plugin)

## License

MIT. See [LICENSE](LICENSE).
