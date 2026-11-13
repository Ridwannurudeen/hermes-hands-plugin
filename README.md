# Hermes Hands

Help someone's computer from your phone. In witness mode they see each command before it runs and hold the off switch.

Hermes Hands pairs a Windows or Linux computer with a one-time code. Hermes runs on a Linux or WSL gateway; terminal and file tools run on the paired computer. In optional witness mode, the person at that computer starts the session, gives local consent, sees each command before it runs, answers a question before each screenshot, and can stop the session by typing S and pressing Enter. The device connects out over HTTPS and does not listen for inbound connections. If a device is offline, revoked, or the relay is unreachable, the device command fails and is not sent to another target.

**Beyond one laptop:** use the same pairing model for another workstation, a GPU box, or a Pi.

## Quick start

1. On the gateway host (Linux, or Windows inside WSL), install Hermes 0.23.1 or later. Once Hermes Hands is listed in the plugin catalog, install and enable the reviewed plugin with `hermes plugins install hermes-hands --enable`. Then run `hermes hands setup` and follow its prompts.
2. Run the two lines setup prints, `hermes config set terminal.backend hands` and `hermes config set bot_desktop.placement gateway`. Restart the gateway, and start the dashboard on loopback with `hermes dashboard --host 127.0.0.1 --port 9119 --no-open`. Any device that is not the gateway host needs the public HTTPS route in [Gateway](#gateway); a loopback URL cannot pair a laptop on another machine.
3. Install the device agent on the computer, as in [Device](#device).
4. Pair a named device with `/hands pair laptop --owner-label "Sam"` in a direct Telegram chat with the bot, or with `hermes hands pair laptop --owner-label "Sam"` on the gateway. The label is the helper's name. The person at the computer sees it in witness mode. On the device, run the printed `hermes-hands pair` command, then `hermes-hands serve`.
5. In a direct chat with the bot, run `/hands use laptop`.

## Versions

The gateway plugin is version 0.2.1; the unchanged device package stays at 0.2.0. CI runs the full automated suite on Hermes 0.23.1. The supported minimum is Hermes 0.23.1; the manifest declares `>=0.23.1`. The plugin still imports two names outside Hermes's public plugin list, `register_token_route` and `LocalEnvironment`, which a later release can change (see [the hook request](docs/HOOK-REQUEST-ISSUE.md)).

## What it provides

| Capability | Hermes Hands |
|---|---|
| Device systems | Native Windows with Git Bash and Linux under WSL2, tested live; macOS devices are unsupported |
| Device install | Separate Python package; Hermes is needed only on the gateway |
| Connection | Outbound HTTPS long poll; no inbound device port |
| Signing | Ed25519 in both directions, with keys pinned at pairing |
| Shell and file tools | Routed to the device selected for the chat |
| Screenshot from chat | Built in tool; witness sessions ask the person before every capture |
| Local control | Optional witness consent, command transcript, stop key, and signed receipts |
| Relay unavailable | Device targets fail closed; `server` does not need the relay |

## Setup

### Gateway

The gateway runs on Linux, or on Windows inside WSL. A native Windows gateway is not supported.

1. Install Hermes 0.23.1 or later. Once Hermes Hands is listed in the plugin catalog, install and enable the reviewed plugin with `hermes plugins install hermes-hands --enable`, then install the device agent from the reviewed commit below. Hermes takes only a full 40 character commit for `--ref`, not a tag name. `hermes plugins update` does not move a pinned install.
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

In the Hermes Desktop interface, open **Capabilities > Plugins**, search for **Hands**, and enable the **Desktop** part of **Hermes Hands**. The frontend part starts disabled in a fresh browser origin. The Hands pane shows relay and device state; its target selector and status chip follow the focused conversation. Open a conversation before choosing its target or pairing a device.

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
   pipx install "git+https://github.com/Ridwannurudeen/hermes-hands-plugin@7e078a50d3a09066aa3e95c3c1a86a9ec221996b#subdirectory=device"
   ```

   This installs the device agent from the reviewed commit, pinned by its full 40 character SHA so the device code matches what the maintainers reviewed. It needs Git on the PATH, which step 1 installs. The package is not on PyPI; use the reviewed Git URL above.

   To keep the device's private key in the OS keyring instead of a file, also run `pipx inject hermes-hands "keyring>=24,<26"` after the install.

4. Make `python3` work inside Git Bash. In Git Bash, `python3 -c "import sys; print(sys.version)"` must print a Python version. The python.org build from step 1 has no `python3.exe`, so Git Bash finds the Microsoft Store alias instead, which only prints "Python was not found". Installing the Python Install Manager gives Git Bash a working `python3`; on the laptop used for the live checks it runs the Python 3.12 from step 1. `hermes-hands doctor` runs the same check in Git Bash and names the Store alias if that is what it finds.

Upgrading the device agent can change its default deny list, and with it the policy hash, so the relay refuses a device paired on an older version until the owner sends `/hands accept-policy <device>` once. It is a chat command (Telegram, the Desktop or the Hermes CLI chat); there is no `hermes hands accept-policy` command.

A saved deny list is the exception. `hermes-hands policy reset` writes the current defaults to `~/.hermes-hands/policy.json`, and the device uses that file whenever it exists. An upgrade does not change it, so the device keeps its old deny list and its old hash, the relay does not ask for `/hands accept-policy`, and the new default rules do not apply. When `serve` starts it prints a warning about this, on the witness console in a witness session and on the terminal otherwise; a service started at logon has no console and shows no warning, so if you ever ran `hermes-hands policy reset` on that device, run it again after each upgrade. To take the new defaults, run `hermes-hands policy reset` on the device again, then send `/hands accept-policy <device>`.

Pair using the command printed by `/hands pair laptop --owner-label "Sam"`, substituting the displayed URL, name, and code. Mint the code after the device is installed: it works once and expires after 10 minutes.

```powershell
hermes-hands pair https://hands.example.com --name laptop --code=ONE_TIME_CODE
hermes-hands serve
```

Run one `hermes-hands serve` per device; `serve` holds an exclusive lock on `~/.hermes-hands/serve.lock` and refuses to start if another `serve` process is already running for that device home. Screen capture is off by default; to opt in, run the agent as `hermes-hands serve --allow-screen`. To start the agent at logon instead, run `hermes-hands install-service`, which registers a Windows scheduled task that runs `pythonw -I -m hermeshands_device.cli serve`; add `--allow-screen` (`hermes-hands install-service --allow-screen`) to let that agent take screenshots. To change the flag later, stop the running task, remove it with `hermes-hands install-service --remove`, and install it again. `hermes-hands install-service --dry-run` prints the planned action.

Linux devices need Python 3.11 or later, pipx, and a Bash environment. Install the device agent with the same `pipx install` command as on Windows (Git must be installed), add `keyring` with `pipx inject` if you want it, pair using the command printed by `/hands pair <name> --owner-label "<helper name>"`, then run `hermes-hands serve`. The service installer is implemented for Windows Task Scheduler. Linux `serve --witness` uses an interactive TTY console. Commands, file I/O, timeout, witness consent, signed receipts, and revoke were tested live on Linux under WSL2. Linux screenshot capture was not tested live.

## Witness mode: help someone else's computer

Witness mode lets the person at a paired computer ask for help while keeping control at the keyboard. Pair the device first. Then the person starts this command in an interactive terminal on that device:

```sh
hermes-hands serve --witness
```

The command requires stdin and stdout TTYs. It does not run under `pythonw` or as a service.

The console names the helper by the label given with `--owner-label` at pairing, or says "your helper" when the label is missing or looks like an account ID. It says the helper can run commands and open or change files only after the helper approves each one, that every command appears on the screen before it runs, that screenshots are asked about each time, that the session ends by itself after 30 minutes, and how to stop and how to send a message. A `Details:` line shows the gateway host. The person types `Y` and presses Enter at `Start? Type Y or N, then press Enter:` to begin. `S` and Enter stops before the session starts. Any other answer leaves witness mode off.

To enable optional `H` help, the gateway owner must explicitly opt in on the gateway host, using the intended Hermes profile:

```sh
hermes config set plugins.entries.hermes-hands.allow_gateway_injection true
```

Restart the gateway after changing it. Setup prints this optional command but never enables the permission itself. Hermes requires the boolean `true` at the plugin entry root; putting it under `settings` does not grant permission. Leave it disabled if device help text should not start agent turns. This permission allows quoted device text to enter the saved owner chat as a user message and start an agent turn; it cannot guarantee that the model will avoid tool calls.

The session lasts at most 30 minutes. Every line the person types ends with Enter. Type `S` (or `s`) and press Enter to stop. `S` also stops the session at a Y or N question. Type `H` and press Enter to write a help message; pressing Escape cancels it. Inside the help editor only a capital `S` on its own stops the session; any other text, a lowercase `s` included, is the message. Up to three help messages are sent per session. The helper needs a saved owner chat origin from `/hands use` for the relay to accept a message, and the explicit gateway injection permission above for the gateway to deliver it.

When the person presses Enter on a help message, the console says "Help request queued for sending." An empty message gets "Help message cannot be empty." and Escape gets "Help request cancelled." After the send, the console prints one result:

- The relay accepted it: "Sent. Your helper should see it in their chat soon."
- The reply from the relay was lost or could not be checked: "Your message may not have reached your helper."
- The relay could not be reached: "Your message was not sent. Check the internet and try H again."
- The relay refused it because the helper has no saved owner chat: "Your helper has not connected a chat yet, so the request was not sent."
- The relay refused it because the gateway injection permission is off: "Your helper has not turned on messages, so this was not sent."
- The relay refused it because the session reached its help limit: "Your helper cannot receive more messages this session."
- The relay refused it for another reason: "This message was not accepted, so it was not sent."
- The device already sent three messages this session: "The witness session has reached its three-request help limit."

The receipt records three states: sent, may not have reached your helper, and not sent. A relay refusal is recorded as not sent. A fourth message after the limit is not sent and not recorded. The gateway keeps an accepted message pending until it delivers it, and acceptance by the gateway does not prove the message reached Telegram.

Help text is filtered to printable characters, capped at 200 characters, quoted as untrusted device data, and injected into the saved helper conversation as a user-role model turn. It is not a direct notification with fixed text. The model is asked to relay the message and wait, but that wording cannot enforce a no-tool boundary. Treat device help text as a prompt-injection surface; witness approvals still apply to every later tool call.

The helper can request the built in `hands_checkup` tool. It returns structured device facts with `observed`, `unsupported`, or `error` availability. Its `inferences` list is currently empty. On Windows, the checkup can report aggregate print queue jobs and known pending reboot registry markers. It does not enumerate the Windows Update catalog, so `pending_updates` is unsupported. On Linux, Windows print queue and update facts are unsupported, while `pending_reboot` checks the known reboot marker files.

Screenshots work after a normal install, but only with the person's yes for each shot and only on a desktop session; a headless Linux machine has no screen to capture. They need two separate answers. After the session starts, the console asks `Allow screenshot requests this session?` and the person types `Y` and Enter to allow them. Each screenshot then asks `<helper> asks to see your screen. Allow this one screenshot?` and needs `Y` and Enter within 30 seconds. A declined or unanswered request captures no image, and the helper is told which of the two happened. After a timeout the console prints `No answer, so this was declined.` and can show a new request; input started before a fresh prompt cannot approve it. When the screen capture libraries cannot load, the session question is not asked, the console says screenshots are not set up on this computer, no screenshot is taken that session, and the helper is told that screenshot support is not available on that computer and that hermes-hands should be reinstalled. This session consent is separate from the normal `serve --allow-screen` setting.

The bundled `hands` skill contains five Windows troubleshooting playbooks. They start with diagnostics, state the limits of the live standard user checks, request the helper's approval for one repair, then recheck the result. Linux notes are read only comparisons and were not run live. The Windows checklist was tested as a standard user on Windows 11 Home. All listed diagnostics ran without elevation. No real repair was applied. The printer resume probe returned access denied even with `-WhatIf`, so permission to resume a real job is not established.

### What the gateway checks during a witness session

While the selected device has an active witness session, the plugin's `pre_tool_call` hook decides every tool call:

- Every tool call that reaches the device needs the helper's approval: `terminal`, `read_file`, `search_files`, `write_file`, `patch`, `vision_analyze`, `video_analyze`, `hands_checkup` and `hands_screenshot`. There is no read only shortcut: `whoami` and `hostname` need approval too. Each step needs its own approval.
- A short list of gateway only tools (web search and extract, memory, todo list, clarify, skill reading, `hands_devices`, tool search) runs as usual. Every other tool is blocked, `execute_code`, background process tools, delegation, cron jobs, messaging, browser and desktop tools, and MCP tools included.
- Terminal commands are blocked when they use shell composition or metacharacters (pipes, redirects, `;`, `&&`, `$(...)`, globs), script launchers and shells (`bash`, `sh`, `cmd`, `powershell`, `python`, `node` and others), shell state builtins such as `export` or `alias`, encoded PowerShell flags, or a Windows `/switch` without the exact `MSYS_NO_PATHCONV=1` prefix. A command line passed inside one argument, such as `git grep -O`, `tar --to-command` or a quoted command for `flock`, is checked the same way as the command itself, two levels deep. `sed` is allowed only with scripts that print, delete or substitute; a `sed` script that writes a file or runs a command, and `sed -f`, are refused. Programs that run other programs are refused (`ionice`, `taskset`, `chrt`, `strace`, `ltrace`, `unbuffer`, `caffeinate`, `flock`, `script`, `watch`, `tmux`, `screen`, `forfiles`, `chroot`, `unshare`, `nsenter`, `prlimit`, `numactl`, `faketime`, `firejail`, `systemd-run` and `pkexec`), and so is `vim` with `-c`, `--cmd`, a plus command, `-S`, `-s` or `-u`. Command-bearing environment assignments and rsync and scp program options are refused; ordinary quoted data such as `git commit -m 'start the server'` is allowed.
- Git program-selecting options and their abbreviations are refused on every subcommand unless consumed as option values or after `--`. Recognized Git nested-command carriers and other tool launchers, command-selecting configuration settings, all `alias.*` settings and unknown subcommands that could be aliases are refused. Explicit read-only `git config` query modes and `ssh.variant` remain allowed. Ordinary `git difftool` and `git mergetool`, including `-t`/`--tool`, are accepted for helper approval; difftool's `-x`/`--extcmd` command options, their abbreviations and command-selecting configuration settings remain refused. Explicit template directories for clone and init, and send-email recipient/header commands and its SMTP server option (every value), are refused. Config includes and protocol allowances are refused when set. Existing repository configuration and hooks can still launch programs.
- Common startup persistence is blocked, because it would keep running after the 30 minute session ends. The block covers writes and patches to startup and autostart folders (Windows Startup, XDG autostart, macOS LaunchAgents and LaunchDaemons), shell profiles and cron, systemd user folders and relative `user/<unit>` paths, and the login folders of fish and KDE Plasma. A recursive copy or extract into a systemd folder is not blocked; it only reaches the helper's approval. It also covers these terminal commands: `reg add` or `reg copy` under the Run, RunOnce or Winlogon keys, any `reg import`, `reg restore` or `reg load`, `regedit`, `schtasks /create` and `schtasks /change`, `crontab` other than `crontab -l`, `systemctl enable` or `link`, `cd` or a `workdir` into a startup folder or into a `systemd`, `fish` or `plasma-workspace` folder, `explorer.exe shell:startup`, bare `profile`, `crontab` and `bashrc` names, and option values glued to a short option, such as `cp -tStartup`. A terminal command that names a startup path is blocked even when it only reads that path. A bare name such as `startup` is fine as a search term in `grep`, `rg`, `git grep` and `findstr`. To read a systemd unit, use `systemctl cat <unit>`. The refusal says the change would outlast the session.
- Other ways to start a program at logon are not blocked. Examples are `reg add` of the `UserInitMprLogonScript` value under `HKCU\Environment`, of `AutoRun` under the Command Processor key, or of the `Load` value under the Windows NT `Windows` key, and `sc create` for a new service. Such a command reaches the helper's approval like any other command, so the helper must read it before approving.
- Patch directives such as `*** Begin Patch` and any patch mode other than replace are blocked. Arguments with hidden or control characters, and arguments Hermes would redact on the approval card or credential literals Hands recognizes, are blocked.
- The approval shows the tool, the device and every argument. A write shows the content length, the first 16 hex characters of its SHA-256 digest and as much of the start of the content as fits. The whole approval text must fit in 300 UTF-16 units after surface escaping and wrapping, or 500 on Telegram after core HTML escaping. Slack and Discord show literal code spans and refuse backticks in non-terminal arguments or card text; unknown surfaces refuse markdown control sequences. A longer call is refused, not shortened. The refusal names the longest argument and, when that is a path, suggests a `~/` path. In a witness session prefer `~/` paths, such as `~/Desktop/notes.txt`, over long absolute paths.
- A witness device job is refused without a human yes, including when approvals are off, yolo is on, or a single query, cron or unattended run would approve on its own. Turn approvals back on and yolo off for the session.
- Another plugin's `pre_tool_call` hook can change a call after the approval card is built, so Hands compares every command that reaches the device with what the card showed and refuses a mismatch: the exact terminal command, its background launch and its `workdir`, the path and every other argument of a read or search, and the exact bytes of a write, where only the BOM and CRLF line ends of the file being replaced may be kept. A `write_file` or `patch` needs a full path, such as `~/notes.txt` or `/c/Users/sam/notes.txt`, because Hermes can place a relative path in more than one folder. Each execution needs a matching Hands approval; identical bodies in a Desktop batch can consume each other's approvals, with no more executions than approvals. A yes to another plugin's approval card does not count. A `patch` runs only when the file it writes is the file as it is now with `old_string`, found exactly once unless the approved call has `replace_all=true`, replaced by `new_string`: Hands reads the file again on the device to check, and refuses a fuzzy match, no match, or several matches unless `replace_all=true` was approved, with a message that asks for the exact text. A `tool_execution` middleware runs before the hooks, so the card already shows its change. Other plugins, shell hooks and webhooks no longer need to be turned off.
- Session and Always on a witness approval do not carry over: every approval has a fresh rule key, so the next step asks again. Each Always tap also writes an unused `plugin_rule:hands-witness:<random>` entry to `command_allowlist` in the Hermes config. The owner can delete those entries.

This parser is a guard rail. It does not classify every possible executable or script runtime, and the helper's approval is the real check. A program named by its full path inside an unrecognized command-bearing argument, `awk -f` and wrappers that are not on this list can still run a script.

In Git Bash outside a witness session, a native Windows program turns a `/switch` argument into a path, so `cmd /c ...` runs nothing and still exits 0. Run such a program with `MSYS_NO_PATHCONV=1` in front and its switches written normally, with one slash, for example `MSYS_NO_PATHCONV=1 tasklist /FO CSV`. Never double the slash (`//c`, `//F`): that spelling hides the command from Hermes's approval check, which matches only the single slash form. Under `MSYS_NO_PATHCONV=1`, write that program's path arguments in Windows form. In a witness session `cmd` is blocked, and the bundled skill tells the model to write bash, not cmd.

### Transcript and receipts

The console timestamps its prompts and status lines. It prints command text as terminal and file jobs start, followed by their outcome, with local times. The signed JSON receipt keeps UTC times. File tools can appear as the shell command Hermes generates for that operation. When the session ends, the console says why in a plain sentence: "Session stopped. Nothing else will run on this computer." after `S`, and different sentences after the 30 minute limit, a revoke by the helper or an error. Local receipts keep the same command text, labels, timestamps, outcomes, checkup facts, help message states and the end reason. They do not contain command output or an exact list of file changes. Command text can include sensitive arguments or file content, so treat receipts as private. The device writes a text receipt and a signed JSON receipt under `~/.hermes-hands/receipts/` and prints both paths, the text one as "Your record of this session: <path>".

Verify the JSON receipt on the device with:

```sh
hermes-hands receipt verify ~/.hermes-hands/receipts/session-name.json
```

It checks the signature against this device's key and prints the key. To verify on another computer that has the device package installed, pass that key with the equals form, because a key can start with a dash:

```sh
hermes-hands receipt verify session-name.json --key=DEVICE_PUBLIC_KEY
```

`S` starts shutdown, cancels registered jobs, rejects work once the device enters its stopping state, and attempts a final relay heartbeat. On Linux, processes that stay in a job's process group are stopped, including ones a background command starts later. A process that moves to a new session or a new process group (for example with `setsid` or `set -m`) is not stopped and can outlive the witness session. The device agent runs with the logged in user's permissions. A compromised helper account or gateway can still issue requests to paired devices. Local consent and the stop key do not protect files from a compromised account.

The console shows every device job, including core's one-time shell snapshot setup. Core also runs login startup code and sources and refreshes its shell snapshot under the call's approval. These inherited shell jobs are not separately approved. The exact-execution guarantee covers the approved command and file operations, within that runtime envelope.

## How this is different from a tech support scam

The person at the computer starts the witness session and can stop it locally. The helper cannot start or restart witness mode remotely. The session is time limited, every command appears on the person's screen before it runs, and screenshot sharing needs session consent plus consent for every capture.

The gateway's witness hook requires the helper's approval for every device command and file operation and blocks scripts, shell composition, common startup persistence and other tools. The device process can access files allowed to the logged in account, including credentials, so witness mode is not a security sandbox.

The device connects out over HTTPS and does not open a listening port. Both sides sign requests with Ed25519 keys pinned at pairing. A local text receipt and signed JSON receipt record command text, session events, and outcomes. They do not contain command output or prove exactly what changed. A compromised helper account or gateway can still control paired devices, so the consent screen and stop key reduce risk but do not remove that risk.

Screenshot declines, local stops, session expiry, and unsupported job types return fixed plain language messages to the helper. The messages tell the model not to invent a cause or retry.

Device file searches use grep, even when ripgrep is installed, so they cannot reuse a cached executable path from the gateway. `hermes-hands doctor` reports whether Git Bash and Python are available inside it. The device needs Python on Git Bash's PATH for `execute_code` and some file operations.

## What runs on the device

On supported Hermes versions, Hands routes these tools through the selected device terminal backend: `terminal`, `execute_code`, `read_file`, `write_file`, `patch`, and `search_files`. `execute_code` needs Python available inside Git Bash, and it is blocked in witness sessions. Hands also registers `hands_screenshot`, `hands_devices`, and `hands_checkup` as its own tools, and a `tool_execution` middleware that carries the hook's decision into each device call.

The target is selected for each terminal call. The first terminal result after a target change identifies the target and device home. Terminal commands on a device start in the device's home folder. A relative path in a file tool resolves against the device's current terminal folder, as on a local backend, outside witness mode a `terminal.cwd` configured on the gateway still wins. In witness mode the approved relative destination stays bound to the device folder even when core resolves its spelling against the gateway configuration. `search_files` patterns reach the device exactly as the model wrote them. `/hands use server` switches terminal calls back to the gateway host. Once a conversation has used a terminal or file tool, including native server file operations, it cannot switch target. Start a new conversation with `/new`, then `/hands use <target>`; before the first terminal or file-tool execution, any target switch is allowed. Switching pauses while a call is pending; a first attempt that is declined or refused before execution releases that guard. Core keeps per-session file-tool caches and the recorded working folder from the previous machine, and no published seam clears them; see [ask 7](docs/HOOK-REQUEST-ISSUE.md). Witness writes and patches still require full paths. A chat that never chose a target uses `default_target`, which defaults to `server`; cron execution always uses `server`. The target belongs to the chat, so `/new` and `/reset` keep it: send `/new`, then `/hands use server` when a fresh conversation should run on the gateway. A device command never falls back to the gateway.

## Known limits

Text Hermes would mask on the approval card is refused so the person never sees different text from what runs, for example `token: Optional[str]`. Witness calls refuse text Hermes would mask, non-placeholder quoted credential values, token prefixes, Bearer values, key blocks, password flags, credential URLs and long or high-entropy values, including beyond a write preview; plain words and keyword arguments in a recognised source file, with or without spaces around `=`, are treated as variable references unless another refusal rule matches; in other files and in terminal commands, a bare word assigned to a secret-looking name is refused. Shell files (`.sh`, `.bash`, `.zsh`) still refuse no-space assignments, as do environment-lookup lookalikes such as `os.environXYZ123`. The source-file rule is based on the file extension, so text that looks like configuration inside a source file is treated as source. Keyword arguments whose value is a bare name, such as `token=token` inside `Client(token=token, api_key=api_key)` or `password=True`, can be masked by Hermes' own approval display and are refused so the card matches; the spaced form `password = True` works, but `Client(token = token, api_key = api_key)` is still masked and refused.

- Hermes takes no file checkpoints under `terminal.backend: hands`, on any target including `server`, and `/rollback` is refused.
- If a background job's pid is in use on two targets at once, `process kill` refuses that pid instead of guessing, until one of the jobs exits.
- If the gateway loses the relay's reply to `/local/exec`, Hands has no job ID to poll or cancel, fails with exit 255, and reports that the command may have been queued and may run on the device; if the relay queued it, the relay cancels unfetched jobs after about 60 seconds.
- When the device agent restarts, the gateway notices within about 10 seconds and then fails a command the old agent had taken, saying it may have partly run.
- A file tool path written as `~/...` lands in the device home, but the tool result's `resolved_path` shows the gateway's home, because core expands `~` on the gateway.
- In a witness session, a call whose arguments are not already their schema type, such as `"true"` for `background` or `"50"` for `limit`, is refused, and so is text Hermes would redact on the approval card or a credential pattern Hands recognizes. Other secrets are shown in cleartext on the card and can run if approved. Ordinary names such as `keyboard.txt` and `tokenizer.py` are allowed. A MEDIA line cannot fetch device files during a witness session; approved screenshots already cached on the gateway remain deliverable, and an oversized tool result stays in the chat instead of being saved on the device.
- In a witness session, an omitted or null terminal `timeout` for a foreground command becomes one explicit default from the public configuration bridge (180 seconds when unset), shown on the approval card and dispatched unchanged. Set an explicit `timeout` to choose another value. Preserving the scoped profile default needs a public accessor; see [ask 9](docs/HOOK-REQUEST-ISSUE.md). A background command has no time limit: in a witness session an explicit `timeout` is refused; leave out `timeout`; press S to stop it. Its approval card shows `background=true` and the no-time-limit statement without a timeout.
- `/hands use` and `hermes hands doctor` read the backend from `config.yaml`, `TERMINAL_ENV` and the profile `.env`, and do not see a managed-scope pin of `terminal.backend`.
- Switching target after a terminal or file-tool execution requires `/new`, then `/hands use <target>`. A `workdir` equal to the folder the other target last ended in, or to `terminal.cwd` before a device's first command, is read as the gateway's folder and the device starts in its own.
- Core's per-session file-tool caches and recorded working folder describe the previous machine; no published seam clears them (see [ask 7](docs/HOOK-REQUEST-ISSUE.md)).
- On Windows, revoking a device stops every job the agent started, foreground and background. On Linux the agent stops the processes that stay in a job's process group, including ones a background command starts later. A process that moves to a new session or a new process group (for example with `setsid`, or `set -m` in a shell) keeps running, so stop it on the device yourself. If the small watcher process the agent starts for each job group has died or stalled for more than a second, a process started late by a background command can also outlive Stop.
- File tools (`read_file`, `write_file`, `patch`, and `search_files`) check their generated command against only the device's self-protection deny rules (`.hermes-hands`, `hermes-hands` management commands, and stopping the agent or its `HermesHands` task), not general shell words such as `sudo` or `shutdown`. A file path or `search_files` pattern whose text matches one of those self-protection rules is still refused with exit 126.
- A command handed to a connection the device can no longer read, for example during a Wi-Fi switch while the same agent process keeps running, is not delivered again; it fails when the gateway's terminal timeout ends.
- The witness persistence block covers common routes only. Other routes, for example `reg add` of `AutoRun`, `at`, `launchctl load` of a file outside the blocked folders, `sc create`, symlink tricks, and a recursive extract into a protected folder, are not blocked. They only reach the helper's approval, where the person also sees the command on screen.
- macOS is not a supported device platform.
- Linux device command, file, timeout, witness, receipt, and revoke paths were tested live under WSL2. A separate native Linux host and Linux screenshots have not been tested live. Linux witness mode needs an interactive TTY. The service installer supports Windows Task Scheduler only.
- `hands_checkup` can report Windows print queue jobs and known Windows reboot registry markers. It does not enumerate Windows Update availability, so `pending_updates` is unsupported. Linux reports Windows-only print queue and update facts as unsupported; its `pending_reboot` fact checks known reboot marker files.

Reading a PDF or Office document transfers the whole file to the gateway before extraction, even when a page was requested with `offset` and `limit`. The person's console shows the whole-file transport command.

## Threat model limits

These are the limits of what Hermes Hands protects against. Read them before helping someone else's computer.

- In a witness session a `patch` must match its `old_string` exactly once unless the approved call has `replace_all=true`, so a patch Hermes would apply through a fuzzy match is refused and the model has to retry with the exact text. File tool commands whose complete generated command text does not match the approved operation are refused. Hands records its refusal for the model, but core can wrap a refused read or search in its own error, such as a document-extraction or unavailable-terminal error.
- Common startup persistence is blocked only in a witness session, and even there the block is a list of known methods, not all of them (see [What the gateway checks](#what-the-gateway-checks-during-a-witness-session)). Outside a witness session, an approved command can add any startup entry that runs after Hermes Hands stops.
- Plain `hermes-hands serve` has no local consent, no transcript on the device, no stop prompt and no witness hook. Commands then go through Hermes's normal approval rules only, and the person at the computer sees nothing. Use `serve --witness` when someone else is at the computer.
- The person at the computer does not approve commands. In witness mode the helper approves each call; the person sees each command before it runs and can stop the session.
- The gateway learns that a witness session started or ended from the device's heartbeat and poll requests, so its view can lag by a few seconds.
- If the device agent is killed hard, for example ended from Task Manager or with `kill -9`, no receipt is written.
- Screenshot consent covers the `hands_screenshot` tool. An approved terminal command could still capture the screen, so the helper's approval of each command matters.
- `hands_checkup` contacts fixed targets: it resolves `example.com` and opens connections to 1.1.1.1, 8.8.8.8 and 9.9.9.9 on port 443.
- Help text from the device is a prompt-injection surface (see [Witness mode](#witness-mode-help-someone-elses-computer)).
- The device deny list matches command text, so it is best effort, and the witness hook's parser does not know every program. Neither is a sandbox.

## Security model

The relay is trusted; whoever controls the gateway and dashboard can command every paired device, and the signatures protect the path between them, not against a compromised gateway. Pairing and target switching from chat are owner gated. `/hands pair` and `/hands use <device>` work only in a direct chat with the bot, because a pairing code is a secret and a device target in a shared chat would apply to everyone in it; `/hands use server` works anywhere. When `owner_ids` is set, which `hermes hands setup` does, it alone decides who the owner is; only when it is empty does the platform's `allow_admin_from` list for that chat count. The device keeps its private signing key locally; the gateway stores device public keys. Requests have a 300 second freshness window and the relay's nonce cache keeps used nonces for 600 seconds. Pairing codes expire after 600 seconds and are single use.

Hermes's token seam offers every plugin token route to every token provider, and core's drain route checks neither the provider nor the scope. So a fresh bearer token signed by a paired or revoked device's key, a pairing code that is still unused, and the gateway's local bearer (derived from the relay seed, held by the gateway and the dashboard) also pass the token check on other plugins' token routes, such as the drain route on a Hermes install that enables it. A revoked device's key keeps that access until 1 hour after the relay first tells the device to stop, or 7 days after revocation, whichever comes first; pairing a new device with the same name does not shorten that window. Hands cannot limit that from a plugin; it needs a change in Hermes core.

The approval transport selected with `security.approval.transport` must ask a human: a plugin transport can return `once` automatically, and Hands counts that response as approval.

Hermes's existing approval gate runs first. A device policy deny list adds a second guard. The relay checks the device policy hash against the hash recorded at pairing; if it changes, the relay refuses work until the owner accepts the changed policy. The deny list matches the text of each command, so it is best effort: it stops the commands it lists as they are usually written, and a command written to avoid it can still get through. It is a guard rail, not a sandbox.

The agent runs as the logged in device user. A same-user shell can read or change any file that user can access, including credentials. The deny list cannot isolate the agent from that user's permissions.

The device connects out and does not open a listening port. Ed25519 signatures authenticate requests in both directions. They detect forged or replayed requests between the paired device and relay but do not protect against a compromised gateway.

## Stored data and retention

The gateway stores the relay seed through Hermes's declared secret configuration, and stores device public keys and pairing metadata in the plugin database. It does not store device private keys. The device stores its Ed25519 private key in the OS keyring only when the `keyring` package is installed next to the agent (`pipx inject hermes-hands "keyring>=24,<26"`); otherwise it uses `~/.hermes-hands/device.json`. The keyring service is `hermes-hands` and the entry username is `device-private`. The fallback file is restricted to the device user: an owner only ACL on Windows, mode 0600 elsewhere.

Device output logs are written under `~/.hermes-hands/out/` and the device agent deletes them after 7 days. Hermes's temporary shell and cwd files on the device (`hermes-snap-*.sh` and `hermes-cwd-*.txt` in the system temp folder and in a local Hermes install's `cache/terminal` folder, if one exists) are removed after 24 hours. Both cleanups run when `serve` starts and then hourly while it runs. Delete output logs sooner with `rm -rf ~/.hermes-hands/out` or remove selected files there.

Screenshots are written on the gateway under `$HERMES_HOME/cache/hermes-hands/`. Each new screenshot first removes screenshots in that folder older than 24 hours, so the last ones stay until the next capture. Remove them sooner by deleting the files in that folder. A captured screenshot is sent to your configured vision model provider when the model describes it, and to the chat platform when it is delivered to the chat.

## Latency

About 0.4 s per small command (p50 409 ms, p90 411 ms over 30 runs, measured twice on an earlier build) from a Hermes v0.23.0 gateway in WSL to a Windows 11 laptop on the same machine, network latency excluded. Most of what remains is Hermes's own per command shell wrapper and its exit polling.

## Why a plugin, not a skill

1. A terminal backend core routes terminal and file tools through the selected environment.
2. An authenticated relay routes work to paired devices and handles pairing.
3. A process on the laptop receives signed work and enforces its own device policy.
4. Per conversation target selection and the Desktop pane let users choose and inspect the active device.

A skill can explain how to use a feature, but cannot register a terminal backend, provide authenticated relay routes, run a laptop process, or enforce local policy.

The current coupling to Hermes internals and the public interfaces that would replace it are described in [the hook request](docs/HOOK-REQUEST-ISSUE.md).

## Repository layout

This repository holds both halves. `hermes-hands/` is the gateway plugin that Hermes installs (the catalog entry points at this folder). `device/` is the device agent, the `hermes-hands` Python package. It is installed from this repository with `pipx` and is not on PyPI yet. `docs/` holds the upstream hook request and the catalog entry draft. `.github/workflows/` runs both test suites.

## Tests and validation

CI runs the full automated suite covering the gateway plugin and device agent on Hermes 0.23.1. Witness tests cover single query, cron and unattended approve and deny modes, finite unattended turns, a normal human yes, and secret refusal against core redaction. For the full integration run, use a Python environment with Hermes's test dependencies installed and point `PYTHONPATH` at a supported Hermes source checkout:

```sh
PYTHONPATH=/path/to/hermes-agent python -m pytest hermes-hands/tests device/tests -q -p no:cacheprovider
```

`hermes plugins validate hermes-hands` passes its checks and warns about two imports outside the public plugin list, `register_token_route` and `LocalEnvironment` which the hook request covers. It also reports that the plugin's dashboard authentication runs in the dashboard process.

The workflows in `.github/workflows/` cover the plugin on Ubuntu and Windows and the device on Ubuntu, Windows and macOS. The device CI tests on Python 3.11, 3.12 and 3.13 with the `keyring` extra installed. Plugin CI validates the plugin and doctor, runs the plugin suite against Hermes 0.23.1, validates the catalog entry draft, scans plugin payloads, and checks Python changes for Windows footguns. A push of a release tag also runs `scripts/check-freeze.py` against a temporary catalog copy whose SHA and URL pins must match the tagged commit.

## Live verification

The live checks below ran on earlier builds of 0.2.0, before the last round of witness changes (approval for every device call and the new console wording). They show the transport and the flow, not this exact build.

Live checks on a real Hermes 0.23.0 gateway in WSL and a native Windows 11 laptop confirmed pairing, terminal work on the laptop, persistent working directory, a 200,001 byte `write_file` round trip verified by SHA-256, timeout handling, offline failure without execution, and recovery after the device restarted. A witness run confirmed local consent, write blocking, screenshot decline and grant, checkup results, and signed JSON receipt verification. That build still let a short list of read only commands run without approval; the current build asks for every call. A follow up run verified that `S` stopped the active child, the gateway received `stopped_by_person`, and the device exited 2.59 seconds after `S`; both receipt paths existed.

An owner-operated Telegram run confirmed device selection, a checkup report, an approval prompt showing the actual command, and a real file write. Linux under WSL2 passed terminal, byte-exact file I/O, 1 MB output, timeout, checkup transport, interactive witness consent and stop, signed receipt verification, and process-tree revoke. That earlier Linux checkup reported one TEMP-folder fact error. A later in-process WSL check returned 27 schema-v1 facts with no inferences and marked the incomplete TEMP scan unsupported rather than error. The in-process recheck did not repeat the full Linux relay or witness flow.

A public HTTPS smoke test on 9 November 2026 used source candidate `5b6524607810dd0f4b9c79eeb95153a3532171b9`. A disposable Windows device paired with the owner's public Hands host, came online, ran a harmless command with the expected marker and exit code 0, and returned a schema-v1 checkup with 27 facts. Offline and revoked device requests failed closed; revocation stopped the reconnected agent. This used normal device mode. It did not test witness mode, Telegram, a phone, a hotspot, or screenshots.

A later owner-operated Telegram witness run confirmed screenshot delivery to the phone after local consent, no image after an explicit decline, and an unanswered request expiring after 30 seconds. Optional `H` help reached the phone after the gateway owner explicitly enabled `allow_gateway_injection`. File reads and searches each presented a separate approval. Stopping an active `sleep 30` prevented a subsequent `pwd`; the text receipt and signed JSON receipt were verified. This run did not measure stop latency. The checkup delivered 27 facts and no inferences, but the model added unsupported cause guidance; the subsequent guidance fix has not yet been retested by the owner.

A separate normal-mode public HTTPS test passed all seven transport checks while the Windows device used a phone hotspot with VPN TUN active. It did not test Telegram witness mode over the public relay.

The official browser-hosted Desktop interface was tested with source candidate `d3cd2a147af1d749f74d2caefe855f46b0afaeb5`. Enabling the Desktop part loaded the pane and status chip, displayed the live relay and an offline paired device, and switched a disposable conversation from `server` to that device and back. The Pair button was disabled for an empty name and enabled for a supplied name; minting a code through the UI was not tested. Native Electron was not tested.

Remaining live checks are a witness session on this build (consent wording, approval of every call, help delivery states and a screenshot after a fresh install), controlled stale-input recovery after a prompt timeout within the same session, the owner retest of checkup response guidance, and Windows scheduled-task installation and logon startup. The service installer's native Windows XML dry run passed, but no scheduled task was installed. macOS is not a supported device platform.

## Uninstall

On the device:

1. Stop the agent: press Ctrl+C in the terminal that runs `hermes-hands serve`, or, if the scheduled task started it, run `schtasks /End /TN HermesHands` in PowerShell. Then run `hermes-hands install-service --remove` if the task is installed.
2. Run `hermes-hands unpair`.
3. Remove `~/.hermes-hands`, and delete the keyring entry with service `hermes-hands` and username `device-private` if you installed `keyring`.
4. Uninstall the package with `pipx uninstall hermes-hands`.

On the gateway:

5. Revoke the paired device with `hermes hands revoke laptop` (replace `laptop` with its name).
6. Set `terminal.backend` back to the backend you used before Hands, for example `hermes config set terminal.backend local`, and undo the placement line with `hermes config unset bot_desktop.placement`.
7. Remove the plugin with `hermes plugins remove hermes-hands`. This also removes its settings, `owner_ids` included.
8. Delete the relay seed with `hermes config unset HANDS_RELAY_SEED`.
9. Delete the plugin data and the screenshot cache: `$HERMES_HOME/plugin-data/hermes-hands/` and `$HERMES_HOME/cache/hermes-hands/`.
10. Remove any `plugin_rule:hands-witness:` entries that Always taps left in `command_allowlist`.
11. Restart the gateway and the dashboard.

## Install from Hermes

Once Hermes Hands is listed in the plugin catalog, use the link that installs the reviewed commit: [Install Hermes Hands from the catalog](hermes://plugin/install?catalog=hermes-hands)

Repository: [Ridwannurudeen/hermes-hands-plugin](https://github.com/Ridwannurudeen/hermes-hands-plugin)

## License

MIT. See [LICENSE](LICENSE).
