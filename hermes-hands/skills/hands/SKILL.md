---
name: hands
description: "Work on a paired Hermes Hands device: Git Bash paths on Windows, what hands errors (255, 126) mean, and device screenshots."
---

# Hermes Hands

In this skill, the helper is the person chatting with you. The person at the computer is whoever
sits at the paired device, often someone the helper is supporting from far away. They can be the
same person. In a witness session the helper approves each tool call that reaches the device, and
the person at the computer sees each command on her screen before it runs and can stop the session.

When the user points this conversation at a device with `/hands use <device>`, your `terminal`,
`read_file`, `write_file`, `patch` and `search_files` calls run on that device as its user, not on
the Hermes server. `/hands use server` points them back at the server. Only the user switches the
target, from a direct chat with the bot, and a switch applies from the next command. The target belongs to the chat, so `/new` and
`/reset` keep it: a fresh conversation in a chat that was on a device still runs there.

Once a conversation has used a terminal or file tool, including native server file operations, it cannot switch target. Ask the user to start a new
conversation with `/new`, then `/hands use <target>`. Before the first terminal or file-tool call, any target
switch is allowed. Core keeps per-session file-tool caches and the recorded working folder
from the previous machine, and no published seam clears them; see ask 7 in
`docs/HOOK-REQUEST-ISSUE.md`. Witness writes and patches still need full paths.

The console shows every device job, including core's one-time shell snapshot setup. Core also runs login startup code and sources and refreshes its shell snapshot under the call's approval. These inherited shell jobs are not separately approved. The exact-execution guarantee covers the approved command and file operations, within that runtime envelope.

## Know where you are

The first `terminal` result after a switch, or in a new session, starts with a target note:

- `hands: now on laptop (Windows-11-..., Git Bash, home /c/Users/<name>; use /c/... paths)`
- `hands: now on laptop (Linux-..., home /home/<name>)`
- `hands: now on server (the gateway host)`

Take paths from the note's home. Do not reuse paths from the server (or from another device) after
a switch; they do not exist there. `hands_devices` lists the paired devices and whether each is
online.

Terminal commands on a device start in its home folder. A relative path in `read_file`,
`write_file`, `patch` or `search_files` resolves against the device's current terminal folder, but
a working folder configured on the gateway still wins over it, so outside a witness session prefer
absolute device paths built from the note's home (`/c/Users/<name>/...` on Windows,
`/home/<name>/...` on Linux). A `~/...` path lands in the device home, though the tool result may
show the server's home in its `resolved_path`.

In a witness session, prefer short `~/...` paths for `read_file`, `write_file` and `patch`, such
as `~/Desktop/notes.txt`. `write_file` and `patch` there need a full path, `~/...` or absolute: a
relative path is refused. The helper's approval card holds about 300 characters, so a long
`/c/Users/<name>/...` path can make Hermes Hands refuse the call. A call whose approval text would
be too long is refused, not shortened. If a refusal names an argument that is too long, shorten
that argument. The card shows each argument in full, except the content of a write: for that it
shows the length, a short digest and the first characters of the content. When you write a file,
tell the helper what the rest of the file contains. A `patch` there must copy `old_string`
exactly from the file as it is now, long enough to match only once unless the approved call
has `replace_all=true`; read the file first.

Do not use `sudo` on a device: its default deny list refuses it with exit 126.

## Checkup first

For any request to run a checkup, perform a health check, or diagnose why a laptop is slow, call
`hands_checkup` as your first tool call, before using `terminal` or another diagnostic tool. Do not
improvise terminal commands for a checkup. The checkup returns the paired device's built-in
read-only facts and separates them from inferences. In witness sessions, every device-reaching tool
call needs the helper's approval, including diagnostics, `hands_checkup` and `hands_screenshot`.
The person at the computer also gives separate consent for each screenshot. Ad hoc terminal commands on witness devices are blocked or need the helper's approval. Ask
any clarifying questions after the checkup. When the checkup does not provide a needed fact, ask
the helper a plain question they can answer or pass on, such as whether other websites open.

When the user requests only observed facts and unavailable items, report only those without
unsolicited causal claims or repair advice. Do not infer that a reboot marker causes memory
pressure or slowness, or guarantee that a restart clears it, from checkup facts alone. An empty
`inferences` list does not establish a cause.

## When the safety rules block something

During a witness session Hermes Hands blocks:

- shell composition (pipes, redirects, `;`, `&&`, `$(...)`) and the symbols `;` `&` `|` `<` `>`
  `$` `(` `)` `{` `}` `*` `?` `[` `]` `~` `#` `!` `%` and the backtick anywhere in a command, even
  inside quotes;
- known script interpreters such as `powershell`, `cmd`, `bash` and `python`;
- startup persistence (startup folders, autostart folders, LaunchAgents, systemd user units,
  fish and KDE Plasma login folders, registry Run keys, scheduled tasks, crontab, shell profiles),
  because it would outlast the 30 minute session. A bare name such as `startup` is fine as a search
  term in `grep`, `rg` and `git grep`, but a command that names a startup path is refused even when
  it only reads it. To read a systemd unit, use `systemctl cat <unit>`;
- Git program-selecting options and their abbreviations are refused on every subcommand unless consumed as option values or after `--`. Recognized Git nested-command carriers and other tool launchers, command-selecting configuration settings, all `alias.*` settings and unknown subcommands that could be aliases are refused. Explicit read-only `git config` query modes and `ssh.variant` remain allowed. Ordinary `git difftool` and `git mergetool`, including `-t`/`--tool`, are accepted for helper approval; difftool's `-x`/`--extcmd` command options, their abbreviations and command-selecting configuration settings remain refused. Explicit template directories for clone and init, and send-email recipient/header commands and its SMTP server option (every value), are refused. Config includes and protocol allowances are refused when set. Existing repository configuration and hooks can still launch programs.
- an argument that is not already its type: send `background`, `timeout` and `limit` as JSON
  booleans and numbers, never as text such as "true" or "50";
- Witness calls refuse text Hermes would mask, non-placeholder quoted credential values, token prefixes, Bearer values, key blocks, password flags, credential URLs and long or high-entropy values, including beyond a write preview; plain words and keyword arguments in a recognised source file, with or without spaces around `=`, are treated as variable references unless another refusal rule matches; in other files and in terminal commands, a bare word assigned to a secret-looking name is refused. Shell files (`.sh`, `.bash`, `.zsh`) still refuse no-space assignments, as do environment-lookup lookalikes such as `os.environXYZ123`. The source-file rule is based on the file extension, so text that looks like configuration inside a source file is treated as source. Keyword arguments whose value is a bare name, such as `token=token` inside `Client(token=token, api_key=api_key)` or `password=True`, can be masked by Hermes' own approval display and are refused so the card matches; the spaced form `password = True` works, but `Client(token = token, api_key = api_key)` is still masked and refused. Ordinary paths such as `keyboard.txt`, `tokenizer.py` and
  `/home/x/secret_santa_list.txt` are allowed. Do not send secrets to the device.

Witness device jobs require a human yes. Automatic approval in single query, cron, unattended
or finite unattended turns cannot authorize them.

The list is not complete. Every other device-reaching tool call, including commands that can start
other programs, waits for the helper, who sees its arguments first (a write shows only the start of
its content).

In a witness session the device also refuses a command that is not the one the helper approved, for
example when another plugin changed the call after the approval. Ask again; if it keeps happening,
the helper can turn off other plugins and hooks for the session.

When a
repair is blocked by the safety rules, say so plainly in one sentence, then offer manual steps for
the helper to read out to the person at the computer. Never try to get around a block: do not
reword, encode, split, wrap, alias or script the command, and do not try another shell or tool.

## Windows devices (Git Bash)

- Commands run in Git Bash: bash, coreutils, `find` and `grep`. Write bash, not PowerShell or cmd.
- Use Git Bash path forms everywhere, in commands and in file tool arguments: `C:\Users\<name>\notes.txt`
  is `/c/Users/<name>/notes.txt`, `D:\work` is `/d/work`. Forward slashes, lowercase drive letter.
- Quote paths with spaces: `"/c/Users/<name>/My Projects/app"`.
- Outside a witness session, prefer absolute paths built from the note's home over `~`. In a
  witness session, prefer short `~/...` paths in file tools; a terminal command there cannot
  contain `~`.
- Native Windows switches need the exact `MSYS_NO_PATHCONV=1` form shown in a playbook.
  Use the built-in checkup for network and process diagnostics. Do not improvise native switches,
  use doubled slashes or add environment assignments to get around the witness command gate.
  Under `MSYS_NO_PATHCONV=1`, native path arguments use quoted Windows paths, not `/c/...`.
- Root `search_files` at the narrowest folder you can (`/c/Users/<name>/projects`), not the home
  folder or a drive root: there it walks every file under that root, AppData included, which is slow.

## Reading hands errors

Hands reports its own failures with **exit 255 and a line starting `hands:`**. The exit code alone
does not say what happened, since a command can exit 255 by itself; the `hands:` line does, and it
says whether the command may have run.

When the line says **nothing ran**, the refused command did not run; there is no fallback to another
machine. However, earlier steps of the same tool call, such as the write before its lint check, may
have completed. The line names the cause:

- `... is offline, so nothing ran` (the device agent is not running or the laptop is asleep)
- `no paired device is named ...` (revoked or never paired)
- `the relay ... is not reachable, so nothing ran on the device` (the dashboard on the gateway is
  down)
- `the deny-list on ... changed since it was paired` (the relay refuses that device)
- `the command or its input is longer than 16 million characters, so nothing ran` (split the work,
  or write the file in smaller parts)
- `the command contains characters that cannot be encoded as UTF-8, so nothing ran` (remove invalid
  surrogate characters before trying again)
- `the relay cannot read the Hermes Hands store ... and refused this request` (the relay refused the
  command before it ran; the cause is in the dashboard log on the gateway, so tell the user)

Tell the user the cause in one sentence and suggest `/new`, then `/hands use server` to keep
working on the server, or the fix the line names (start `hermes-hands serve` on the device, or `/hands accept-policy
<device>` if they changed the deny-list themselves). Do not retry in a loop, and do not try to reach
the device some other way.

When the line says the command **may have run**, it may have been queued or started on the device
before Hands lost track of it, so it may run, may have partly run, or may still be running there,
and any output you have is partial:

- `the relay stopped answering after the command was sent to it, so it may have been queued and may run on ...`
- `contact with the relay was lost after the command started on ..., so it may still be running there`
- `the device agent on ... restarted while the command ran, so it may have partly run there`
- `... went offline before the command finished; any output above is partial`
- `the deny-list on ... changed since it was paired, so the relay stopped the command, which may have
  partly run there` (tell the user; only they can accept the new policy with `/hands accept-policy`)

Do not run it again until you have checked its effect on the device (with `ls`, `git status` or
`ps`, say), and tell the user what you found.

**Exit 126 and `Policy refused command matching: <pattern>`** means the device's own deny-list refused
the command. Respect it: do not reword, encode, split, alias or script around it, and do not try
another shell. Tell the user which pattern refused it; only they can change that policy, on the
device itself.

Also: 124 is a timeout and 137 a cancelled command. Output that reaches the device's 64 MiB cap stops
the command there; the result then has a non-zero exit code and a line naming the cap, and the output
is cut short.

## Screenshots

Use `hands_screenshot` when the user asks what is on the device's screen, or to check a result you
cannot confirm from the shell (a window, a dialog, a page rendering). It captures the device this
conversation targets; it refuses on the `server` target and in cron.

- On success the result contains a line `MEDIA:/absolute/path.png`. Copy that exact line into your
  reply (that is how the image reaches the user's chat), then call `vision_analyze` on that path to
  describe what is on screen.
- In a witness session, keep the `vision_analyze` question short, such as "What is on screen?",
  under 50 characters. The approval card also holds the long screenshot path, so a longer question
  is refused.
- `Screenshot capture requires serve --allow-screen` means the user has not consented to screen
  capture on that device. Tell them; do not retry.

## Windows troubleshooting playbooks

These five playbooks are for Windows devices only. The repairs in them were not tried on a real
fault, so each one is marked untested. Never tell the person at the computer to type commands, and
never send her PowerShell. Every step she takes is a click or a key press in Windows itself, and you
give the helper the exact words to read out to her.

Rules for every playbook:

1. Confirm the selected Windows device. For a general checkup, health check, or slow-laptop request,
   call `hands_checkup` first and ask any symptom questions afterward. For other symptoms, confirm
   the symptom with the helper, then call `hands_checkup` before suggesting anything.
2. Keep its `facts` and `inferences` separate; do not repeat an inference as an observation. A
   fact's `availability` may be `unsupported` or `error`, which is not evidence that the condition
   is absent. Quote only this device's values, never numbers from another machine.
3. If the checkup does not answer a question, use only the exact read-only diagnostic listed in
   that playbook, with approval, or ask what she sees. Do not improvise extra terminal commands.
4. Before any repair, tell the helper what it changes, whether it can be undone, and that it is
   untested. Offer only the one repair listed for the confirmed symptom. Ask for the helper's
   approval, wait for it, and do nothing if it is not given. Submit a repair only after that clear
   yes in chat.
5. Recheck with `hands_checkup` and the same questions. Report `Before`, `After`, and exactly
   `fixed`, `not fixed` or `unknown`. Say `fixed` only when the symptom is gone and the recheck
   supports it. Report `not fixed` only when a completed recheck shows the symptom remains.
   If the recheck is unavailable, report `unknown`. A relay outage after a repair does not prove
   failure. If no repair ran, say so and report only the symptom state actually observed.

Hermes Hands holds each device call for the helper's approval, and shows it on her screen, only in
a witness session. Outside one, a terminal call runs at once and she sees nothing in Hermes Hands.
You cannot always tell which case applies, so treat every repair as if it runs the moment you submit
it. Say that she saw a command only if the helper approved it in Hermes Hands.

In a witness session each step needs its own approval. The Session and Always buttons on an
approval card do not carry over to later steps, and Always leaves unused entries in the helper's
`command_allowlist`, so ask the helper to approve each step and do not suggest those buttons.

What she sees: in a witness session, a checkup or an approved command shows up as a short line in
her Hermes Hands window before it runs. Steps the helper reads out show nothing in Hermes Hands; she
sees only the Windows windows she opens herself.

### One site or app fails (Windows only)

**Confirm the symptom.** If the whole internet is down, the device cannot reach the helper at
all, so this playbook is only for one site or app that fails while Hands still works. Ask the helper
which site or app fails, what it shows, and when it started. Do not assume a DNS problem.

**Checkup first.** Run `hands_checkup` and report `wifi_status`, `dns_servers`, `dns_resolution`
and the `reachability_*` facts. Then ask the helper to check with her: "Does another website open,
for example a news site? Does the same site open on your phone?"

**Facts.** Copy the observed connection, DNS and reachability values with their source and time,
plus her answers.

**Uncertainty.** If other sites open and the checkup's DNS and reachability facts look normal, the
problem is likely with that site, that app, or her account there, and these checks cannot say
which. A site that also fails on her phone is probably down for everyone.

**Repair: clear the local DNS cache.** Untested on a real fault. Offer this only when other sites
open, this site fails on this computer but opens on her phone, and her browser shows a DNS error
for this site, such as "server IP address could not be found" or DNS_PROBE_FINISHED_NXDOMAIN. The
checkup cannot confirm this: its DNS fact looks up one fixed name, not this site. Tell the helper
the repair is a guess. Windows rebuilds the cache through later lookups. The earlier standard-user probe was only a dry
run, so actual permissions were not verified. If access is denied or UAC appears, stop.
Ask for the helper's approval first.

**Helper terminal call.** After the helper's clear yes in chat, submit this exact command through
`terminal`. In a witness session Hermes Hands then holds it for the helper's approval before it
runs. Do not send it to the person to type.

```bash
MSYS_NO_PATHCONV=1 ipconfig /flushdns
```

If the evidence does not support this repair, do not run it; the only repair is then the manual
close and reopen below. Explain its unsaved-work risk before the helper approves those steps.

**Words for the helper:** "Please save anything you are typing. Close the browser (or the app)
completely with the X in its top right corner. Wait a few seconds, then open it again and try the
site once more."

**What she sees:** In a witness session, the approved cache command appears in Hermes Hands. For
the manual fallback, she sees her own browser or app closing and opening.

**Recheck and outcome.** Ask whether the site or app works now and run `hands_checkup` again.
Record Before and After. Report `fixed` only if she says it works; report `not fixed` if the recheck shows it still fails, or `unknown` if verification is unavailable.

### Printer stuck (Windows only)

**Confirm the symptom.** Ask the helper which printer and which document she expects to print.
Resume a document only if the helper confirms that exact document should print.

**Checkup first.** Run `hands_checkup` and report the `print_queue_jobs` count across the visible
Windows queues. The checkup does not collect printer names, document names or job numbers. If the
fact is an error or unavailable, say so.

**Facts.** Report the checkup's job count and what she reads from the print queue window below.

**Uncertainty.** A job count does not say which job is stuck or why. Paused jobs, an offline
printer and a printer that is out of paper all look alike from the count.

**Repair: resume one paused document.** Untested on a real stuck job. A standard Windows account may
not be allowed to resume a job; if Windows refuses or asks for an administrator, stop and tell the
helper. This playbook never cancels or clears jobs. Undo: the same menu has **Pause**, which pauses
the document again if it has not started printing. Ask for the helper's approval first.

**Helper terminal call.** Automatic resume is unsupported under the current command gate.
Do not send PowerShell, scripts or a legacy printer command. After the helper's approval, this
terminal call only opens Settings; it does not resume the document. The person must do the
manual repair below. Do not report the launch as a completed repair.

```bash
explorer.exe ms-settings:printers
```

The earlier standard-user resume dry run was denied without a UAC dialog. Actual permissions
for this queue were not verified. Do not retry with elevation or clear the queue.

**Words for the helper:** "Click Start, then Settings. Click Bluetooth and devices, then Printers
and scanners. Click your printer, then Open print queue. Find your document in the list. If it says
Paused, right-click it and choose Resume. Tell me what it says now."

**What she sees:** In a witness session, the approved Settings launch appears in Hermes Hands.
She then opens the Windows print queue window and resumes the confirmed document herself.

**Recheck and outcome.** Run `hands_checkup` again and ask what the queue window shows and whether
the document printed. Record the status Before and After. Report `fixed` only if the document
printed; report `not fixed` if it remains stuck, or `unknown` if verification is unavailable.

### Slow PC (Windows only)

**Confirm the symptom.** After the first `hands_checkup`, ask the helper what feels slow and whether
it is mainly windows and menus opening or closing. The repair below is only for slow-feeling window
and menu animations, not a general speed repair.

**Checkup first.** Run `hands_checkup` and report `memory_used_percent`, `memory_available_bytes`,
`uptime_days`, `pending_reboot` and the sampled `top_process_*` facts. The checkup does not measure
processor use or whether an app is responding.

**Facts.** Report this device's memory values and the top processes by memory, with their source.

**Uncertainty.** One memory reading does not identify a cause. Low available memory can contribute,
but turning off animations does not add memory or speed up the processor.

**Repair: disable window minimize and maximize animation for this account.** Untested on the real
setting. It does not change all animations or add memory. The earlier throwaway current-user
registry probe worked without UAC, but this setting and its activation were not tested.
Ask for the helper's approval first. In a witness session each diagnostic and repair call also
needs its own approval in Hermes Hands.

**Helper terminal call.** First query the exact setting, through an approved terminal call:

```bash
MSYS_NO_PATHCONV=1 reg.exe query 'HKCU\Control Panel\Desktop\WindowMetrics' /v MinAnimate
```

Only if it exists as REG_SZ with value 1, record that exact Before value and propose this single
repair. If missing, a different type, or already 0, do not create or change it; use the manual
fallback instead. After the helper's clear yes, submit the following terminal call:

```bash
MSYS_NO_PATHCONV=1 reg.exe add 'HKCU\Control Panel\Desktop\WindowMetrics' /v MinAnimate /t REG_SZ /d 0 /f
```

Undo only after fresh approval by restoring the recorded 1 with the same command and `/d 1`.
Do not force sign-out, restart Explorer or claim immediate activation. Query the value again and
ask whether window transitions changed.
The manual fallback changes Windows' broader Animation effects switch instead; explain that
difference and obtain approval rather than silently adding a second repair.

**Words for the helper:** "Click Start, then Settings. Click Accessibility, then Visual effects.
Find Animation effects and switch it off. Tell me when it shows Off."

**What she sees:** In a witness session, each approved registry query or change appears in
Hermes Hands. For the manual fallback she sees the Windows Settings window.

**Recheck and outcome.** Run `hands_checkup` again and ask whether windows and menus feel quicker.
Record Before and After. Report `fixed` only if the selected setting is off (the value reads 0,
or Animation effects shows Off) and she says the slowness she described is gone. If the setting is
off but she sees no change, report `unknown`: the change may only show after she signs out and
back in, which this playbook does not ask her to do. Report `not fixed` only if the setting is
still on after the change, or `unknown` if verification is unavailable.

### Disk full (Windows only)

**Confirm the symptom.** Ask the helper which drive is low and whether Windows shows a low space
warning. Do not assume the device home folder is on the drive that is low.

**Checkup first.** Run `hands_checkup` and report `disk_free_percent`, `disk_free_bytes` and the
available `folder_*_bytes` facts. The checkup measures the drive that holds the device home folder
and a few folder sizes. If the low drive is another one, ask the helper what Windows shows for it.

**Facts.** Report this device's free space and folder sizes with their availability.

**Uncertainty.** Folder totals do not show which files inside are large. Compression may save little
or no space for photos, videos and zip files, and it uses processor time.

**Repair: compress one folder she rarely uses.** Choose one ordinary folder of her own files that
she rarely uses, such as an old archive inside Documents. Never compress the Windows folder,
Program Files, AppData, her whole user folder or a OneDrive synced folder. Untested on a real
folder; only a small test file was compressed during development. It deletes nothing. It works only on NTFS drives, which most
Windows drives are. Undo: repeat the steps and untick the same box. Ask for the helper's approval
first, and name the folder in the request.

**Helper terminal call.** Resolve the folder from this device's observed path and the helper's
choice. The path below is an example only; replace it with that exact quoted Windows path, and
submit the complete command only after the helper's clear yes. If the folder path contains any of
`;` `&` `|` `<` `>` `$` `(` `)` `{` `}` `*` `?` `[` `]` `~` `#` `!` `%` or a backtick, the terminal
call is blocked, so use the manual steps below for that folder. A folder named Autostart,
LaunchAgents, LaunchDaemons or profile.d is refused as startup persistence, and so is `user` inside
a `systemd` folder, `conf.d` or `functions` inside a `fish` folder, and `env` or `shutdown` inside a
`plasma-workspace` folder, so use the manual steps for those too.

```bash
MSYS_NO_PATHCONV=1 compact.exe /C /S:"C:\Users\Example\Archive"
```

The throwaway compression probe worked without UAC; this folder's permissions and savings were
not tested. Stop on access denied or UAC. Undo only after fresh approval using the same observed
path with `/U` in place of `/C`. Do not run `compact.exe /CompactOS` or delete anything.

**Words for the helper:** "Open File Explorer and find the folder we agreed on. Right-click it and
choose Properties. Click Advanced. Tick Compress contents to save disk space, click OK, then click
OK again. If Windows asks, choose Apply changes to this folder, subfolders and files, then OK. Tell
me when it finishes."

**What she sees:** In a witness session, the approved compression command appears in Hermes
Hands. The manual fallback uses File Explorer and the folder's Properties window.

**Recheck and outcome.** Run `hands_checkup` again and record free space Before and After. Report
`fixed` only if free space went up and the low space warning is gone. Report `not fixed` if the measured symptom remains, or `unknown` if verification is unavailable.

### Program frozen (Windows only)

**Confirm the symptom.** Ask the helper which app is frozen, by the name she sees on screen, and
whether her work in it is saved. Never ask the person at the computer for a process ID or any other
number.

**Checkup first.** Run `hands_checkup` for general device facts. It does not report which app is
not responding, so ask the helper to ask her: "Does the app's title bar say Not responding? Does
anything else still work, such as the Start menu?"

**Facts.** Record the app name and her answers, plus the checkup's memory facts.

**Uncertainty.** An app can be busy rather than frozen; waiting a minute sometimes clears it. Ending
it loses any unsaved work in it.

**Repair: End task, which is not reversible.** End task is not reversible: anything unsaved in that
app is lost and cannot be brought back. Untested on a real frozen app. Offer it only after she has
waited a minute and the helper has confirmed the app and the risk. Ask for the helper's approval
for this one app and wait for a clear yes.

**Helper terminal call.** First ask her to try closing the app normally and to save or recover
her work. If that works, recheck and stop. Otherwise obtain an approved read-only process list:

```bash
tasklist
```

Plain `tasklist` shows only program file names and process numbers. It does not show window
titles or whether an app is responding. Propose ending a process only when exactly one row has the
program file name of the app the helper confirmed. Never end explorer.exe, which runs the taskbar,
the Start menu and the desktop. Never end the program that runs the Hermes Hands window (python.exe,
hermes-hands.exe, cmd.exe, conhost.exe, OpenConsole.exe, WindowsTerminal.exe, bash.exe or
mintty.exe) or a Windows system process, and never end all processes that share a name. If the app has
several rows, has no row you can match, or is one of those programs, use the manual fallback.
After the helper confirms that app and the risk of losing unsaved work, substitute its observed
number for this example and submit the exact terminal command only after the helper's clear yes:

```bash
MSYS_NO_PATHCONV=1 taskkill.exe /PID 1234
```

This requests termination without forcing it; it may refuse a frozen app. Do not add force or
child-process switches. A same-user throwaway force-stop probe showed no UAC, but this different
command on this app was not tested. Stop on access denied or UAC; do not escalate.
Reopen the app manually. Ending the old process is not reversible; reopening cannot restore
unsaved work. The manual End task fallback below needs its own clear approval and the same warning.

**Words for the helper:** "Press Ctrl, Shift and Esc together. Task Manager opens. Find the app in
the list, click it once, then click End task. Then open the app again from the Start menu."

**What she sees:** In a witness session, the approved process list and termination request
appear in Hermes Hands. The manual fallback uses Task Manager, then she reopens the app herself.

**Recheck and outcome.** Ask whether the app opened again and responds. Run `hands_checkup` again
if the whole computer felt slow. Record Before and After. Report `fixed` only if the app opens and
responds; report `not fixed` if the symptom remains, or `unknown` if verification is unavailable.
