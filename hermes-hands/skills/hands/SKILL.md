---
name: hands
description: "Work on a paired Hermes Hands device: Git Bash paths on Windows, what hands errors (255, 126) mean, and device screenshots."
---

# Hermes Hands

When the user points this conversation at a device with `/hands use <device>`, your `terminal`,
`read_file`, `write_file`, `patch` and `search_files` calls run on that device as its user, not on
the Hermes server. `/hands use server` points them back at the server. Only the user switches the
target, from a direct chat with the bot, and a switch applies from the next command. The target belongs to the chat, so `/new` and
`/reset` keep it: a fresh conversation in a chat that was on a device still runs there.

## Know where you are

The first `terminal` result after a switch, or in a new session, starts with a target note:

- `hands: now on laptop (Windows-11-..., Git Bash, home /c/Users/ridwan; use /c/... paths)`
- `hands: now on laptop (Linux-..., home /home/ridwan)`
- `hands: now on server (the gateway host)`

Take paths from the note's home. Do not reuse paths from the server (or from another device) after
a switch; they do not exist there. `hands_devices` lists the paired devices and whether each is
online.

Terminal commands on a device start in its home folder. A relative path in `read_file`,
`write_file`, `patch` or `search_files` resolves against the device's current terminal folder, but
a working folder configured on the gateway still wins over it, so on a device prefer absolute device
paths built from the note's home (`/c/Users/ridwan/...` on Windows, `/home/ridwan/...` on Linux). A
`~/...` path lands in the device home, though the tool result may show the server's home in its
`resolved_path`.

Do not use `sudo` on a device: its default deny list refuses it with exit 126.

## Checkup first

For any request to run a checkup, perform a health check, or diagnose why a laptop is slow, call
`hands_checkup` as your first tool call, before using `terminal` or another diagnostic tool. The
checkup returns the paired device's built-in read-only facts and separates them from inferences.
Ad hoc terminal commands on witness devices are blocked or require owner approval. Ask any
clarifying questions after the checkup, and ask the owner to run extra read-only commands locally
when the checkup does not provide a needed fact.

## Windows devices (Git Bash)

- Commands run in Git Bash: bash, coreutils, `find` and `grep`. Write bash, not PowerShell or cmd.
- Use Git Bash path forms everywhere, in commands and in file tool arguments: `C:\Users\ridwan\notes.txt`
  is `/c/Users/ridwan/notes.txt`, `D:\work` is `/d/work`. Forward slashes, lowercase drive letter.
- Quote paths with spaces: `"/c/Users/ridwan/My Projects/app"`.
- Prefer absolute paths built from the note's home over `~`.
- Git Bash turns a `/switch` argument of a native Windows program (`cmd`, `tasklist`, `ipconfig`,
  `taskkill`, `schtasks`) into a path, so `cmd /c ...` runs nothing and still exits 0. Run such a
  program with `MSYS_NO_PATHCONV=1` in front and its switches written normally, with one slash:
  `MSYS_NO_PATHCONV=1 tasklist /FO CSV`, `MSYS_NO_PATHCONV=1 ipconfig /all`. Never double the slash
  (`//c`, `//F`): that spelling hides the command from Hermes's approval check, which only knows the
  single slash form. Under `MSYS_NO_PATHCONV=1`, write that program's path arguments in Windows form,
  quoted, such as `'C:\Users\ridwan\notes.txt'`, because `/c/...` paths stop working there. Leave
  path conversion on for everything else.
- Root `search_files` at the narrowest folder you can (`/c/Users/ridwan/projects`), not the home
  folder or a drive root: there it walks every file under that root, AppData included, which is slow.

## Reading hands errors

Hands reports its own failures with **exit 255 and a line starting `hands:`**. The exit code alone
does not say what happened, since a command can exit 255 by itself; the `hands:` line does, and it
says whether the command may have run.

When the line says **nothing ran**, nothing ran anywhere; there is no fallback to another machine.
The line names the cause:

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

Tell the user the cause in one sentence and suggest `/hands use server` to keep working on the
server, or the fix the line names (start `hermes-hands serve` on the device, or `/hands accept-policy
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
- `Screenshot capture requires serve --allow-screen` means the user has not consented to screen
  capture on that device. Tell them; do not retry.

## Windows troubleshooting playbooks

These five playbooks are Windows-only. The live checklist was run as a standard user on Windows 11
Home 10.0.26300, build 26300, x64. Those observations are a point-in-time baseline, not a claim
about the device you are helping now. The Linux equivalents below are read-only comparisons; they
were not run, and they do not provide Windows repair support through WSL.

### Shared F4 rules

1. Confirm the selected Windows device. For a general checkup, health check, or slow-laptop request,
   call `hands_checkup` first and ask any needed symptom questions afterward. For other symptoms,
   confirm the owner's symptom before checking anything.
2. Call `hands_checkup` for observed device facts. Keep its `facts` and `inferences` separate; do
   not repeat an inference as an observation. A fact's `availability` may be `unsupported` or
   `error`, which is not evidence that the condition is absent.
3. If a playbook needs a fact that `hands_checkup` does not provide, ask the owner to run the exact
   read-only PowerShell command below in a local Windows PowerShell session and share its output.
   The Hands device terminal is Git Bash, and the witness hook blocks pipelines and shell
   composition. Do not send these piped commands through the Hands terminal or reword, wrap, or
   script them to get around that gate.
4. State the observed UAC/admin facts before asking for a repair. Propose only the single repair
   listed for the confirmed symptom. Ask for one F2 owner approval, wait for it, and do nothing if
   it is denied. If the UI or PowerShell step cannot be performed with the available device tools,
   have the owner perform that exact step after approval; do not work around a policy refusal.
5. Re-run the same diagnostics after the repair. Report `Before`, `After`, and exactly `fixed` or
   `not fixed`. Say `fixed` only when the symptom is gone and the recheck supports that result. If
   the repair was not performed or the recheck is unavailable, report `not fixed` and state that
   the effect is unknown.

The core dangerous-command patterns include `Remove-Item -Recurse/-Force`, `del /s /q`,
`taskkill /F`, and `Stop-Process -Force`. None of the selected repairs needs those shell patterns.
For a frozen app, use Task Manager's **End task** action so the F2 repair approval does not lead to
a second dangerous-command prompt.

### No internet (Windows-only)

**Confirm the symptom.** Ask whether all internet access fails or only a named site/app, and when
the problem started. Do not assume a DNS problem from “no internet” alone.

**Read-only diagnostics.** Run `hands_checkup` and report `wifi_status`, `dns_servers`,
`dns_resolution`, and the `reachability_*` facts if available. For the Windows connection profile
and the named DNS lookup, ask the owner to run these exact checklist commands locally:

```powershell
Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,IPv4Connectivity,IPv6Connectivity
Resolve-DnsName www.microsoft.com | Select-Object Name,Type,IPAddress
Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -InformationLevel Quiet
```

**Facts.** Copy observed connectivity, DNS, and reachability values with their source and time.
The live checklist's profile, DNS lookup, and TCP test all worked without admin; that laptop had
internet at the time of the check.

**Uncertainty.** A failed DNS lookup with working IP reachability is consistent with a resolver
problem. If DNS and IP reachability both fail, the cause is not established by these checks. The
checklist's live success does not establish this device's present state.

**One reversible repair.** Only if the evidence points to stale or failed DNS resolution, propose
clearing the local DNS cache:

```powershell
Clear-DnsClientCache
```

`Clear-DnsClientCache -WhatIf` worked in the standard-user probe without UAC or access denied, but
the actual clear was not run, so actual repair permissions were not verified. State that limit
before requesting one F2 approval. Windows rebuilds the cache as lookups happen again.

**Recheck and outcome.** Repeat `hands_checkup` and the same three local PowerShell checks. Record
the DNS and TCP values before and after. Report `fixed` only if the earlier DNS failure is gone,
reachability succeeds, and the owner confirms the original symptom is resolved; otherwise report
`not fixed` with the values.

**Linux read-only equivalent (not run):** `ip route`, `getent ahosts www.microsoft.com`, and
`curl -I --connect-timeout 5 https://www.microsoft.com`. Clearing the Windows DNS Client cache is
not a Linux/WSL repair.

### Printer stuck (Windows-only)

**Confirm the symptom.** Ask which queue and document the owner expects to print. Resume a job only
if the owner confirms that exact paused job should print.

**Read-only diagnostics.** Run `hands_checkup` and report the `print_queue_jobs` count across the
visible Windows queues. The checkup does not collect queue names, document names, or job IDs. If its
fact is an error or unavailable, ask the owner to run these exact read-only checks locally:

```powershell
Get-Service -Name Spooler | Select-Object Name,Status,StartType
Get-Printer | Select-Object Name,PrinterStatus,WorkOffline
Get-PrintJob -PrinterName 'Microsoft Print to PDF' | Select-Object PrinterName,ID,DocumentName,JobStatus
Get-PrintJob -PrinterName 'OneNote (Desktop)' | Select-Object PrinterName,ID,DocumentName,JobStatus
```

**Facts.** Report the checkup's aggregate job count, plus the spooler status, queue status, and exact
job ID/status from the local checks. The live read-only checks worked as a standard user; the two
listed queues had no jobs at that time.

**Uncertainty.** The live checklist found no job to repair. It does not establish access to a
different queue or job. The standard-user probe
`Resume-PrintJob -PrinterName 'Microsoft Print to PDF' -ID 4294967295 -WhatIf` returned
`HRESULT 0x80070005` (Access is denied), and Windows showed no UAC dialog.

**Admin and one reversible repair.** Clearing a print job requires administrator privileges. This
playbook does not clear jobs or the whole queue. Its only repair is to resume one owner-confirmed
paused job by its exact queue and ID:

```powershell
Resume-PrintJob -PrinterName '<same printer>' -ID <same job ID>
```

The live standard-user `-WhatIf` probe was denied, so resuming may also require admin or queue
permissions. Tell the owner both facts before asking. Request one F2 approval only after the owner
confirms the job should print and the required permissions are available. If access is denied,
stop; do not retry or switch to clearing. If it remains queued, it can be re-paused before printing:

```powershell
Suspend-PrintJob -PrinterName '<same printer>' -ID <same job ID>
```

**Recheck and outcome.** Repeat the same spooler, printer, and job checks. Record the job's status
before and after, and ask whether the intended document printed. Report `fixed` only if the
confirmed job is no longer stuck and the owner confirms the result; otherwise report `not fixed`.

**Linux read-only equivalent (not run):** `lpstat -p -d` and `lpstat -o` when CUPS and a Linux
queue exist. WSL does not imply access to the Windows Spooler or these queues.

### Slow PC (Windows-only)

**Confirm the symptom.** After the initial `hands_checkup`, ask what feels slow and whether it is
specifically window/menu transitions. The visual-effects repair below is only for slow-feeling
transitions, not a general CPU or memory repair.

**Read-only diagnostics.** Run `hands_checkup` and report `memory_used_percent`,
`memory_available_bytes`, and the sampled `top_process_*` facts. It does not measure CPU utilization
or per-process responsiveness. For the exact Windows CPU, memory, and process samples, ask the
owner to run:

```powershell
Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3
Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize,LastBootUpTime
Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name,Id,CPU,WorkingSet64,Responding
```

**Facts.** Report the measured CPU samples and memory values. The live checklist measured CPU at
20.4%, 17.3%, and 15.4%, and about 2.39 GiB available of 31.21 GiB. `Get-Process`'s `CPU` field is
cumulative since process start, not current utilization.

**Uncertainty.** A short CPU sample and one memory reading do not identify a cause for all
slowness. Low available memory can contribute, but turning off animations does not increase CPU
or RAM capacity.

**One reversible repair.** Only for slow-feeling window or menu transitions, propose turning off
**Settings → Accessibility → Visual effects → Animation effects** for this account. The owner can
turn the same setting back on to undo it. The standard-user `-WhatIf` probe below worked, and a
throwaway HKCU test completed without UAC; the real animation setting was not changed during the
checklist:

```powershell
Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name MinAnimate -Value '0' -WhatIf
```

State that the live probe was not the Settings repair, then request one F2 approval and wait. Do
not use the registry probe as the repair.

**Recheck and outcome.** Repeat `hands_checkup` and the same local performance checks. Record the
before/after CPU samples, available memory, and animation-effects setting; ask whether transitions
improved. Report `fixed` only if the setting is off and the reported transition problem is gone;
otherwise report `not fixed`.

**Linux read-only equivalents (not run):** `free -h`, `top`, and
`ps -eo pid,comm,%cpu,%mem --sort=-%mem`. Animation settings are desktop-environment-specific and
are not a shared Windows/Linux repair.

### Disk full (Windows-only)

**Confirm the symptom.** Ask which drive is low and whether Windows reports a low-space warning.
Do not assume the device home folder is on C:.

**Read-only diagnostics.** Run `hands_checkup` and report `disk_free_percent`, `disk_free_bytes`,
and available `folder_*_bytes` facts. The checkup measures the device home volume and bounded
folder sizes. If the affected drive or TEMP total is not covered, ask the owner to run these exact
read-only checks locally:

```powershell
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,FileSystem,FreeSpace,Size
Get-ChildItem -LiteralPath $env:TEMP -File -Force | Measure-Object -Property Length -Sum
```

The TEMP total is immediate files only, not recursive.

**Facts.** Report the drive, filesystem, free bytes, total bytes, and any folder-size result with
its availability. The live checklist found C: was NTFS with about 24.6% free; it was not full at
that time.

**Uncertainty.** The TEMP listing does not identify nested folder sizes. Compression may save
little or no space for already-compressed media/archive files and uses CPU.

**One reversible repair.** Only for an owner-selected, infrequently accessed folder on NTFS,
propose compressing that folder. It does not delete files. The standard-user probe compressed and
uncompressed a throwaway 1 MiB text file with no UAC or access denied; the selected real folder's
permissions and savings were not tested.

```powershell
compact.exe /C /S:"<same folder>"
```

The owner can undo it on the same folder with:

```powershell
compact.exe /U /S:"<same folder>"
```

State the selected path and CPU/savings caveat, then request one F2 approval and wait. Do not
delete files as part of this repair.

**Recheck and outcome.** Repeat the same disk and folder checks and record free bytes before and
after. Report `fixed` only if free space increased and the owner's low-space symptom is resolved;
otherwise report `not fixed` with the measured values.

**Linux read-only equivalents (not run):** `df -hT /` and
`du -x -h --max-depth=1 "$HOME"`. Compression is filesystem-specific; WSL does not provide a
universal equivalent to NTFS `compact`.

### Program frozen (Windows-only)

**Confirm the symptom.** Confirm the exact app and PID and ask whether its work is saved or
recoverable. Do not end an app with unsaved work.

**Read-only diagnostics.** Run `hands_checkup` for general device facts, but it does not report
which process is unresponsive. Ask the owner to run this exact check in local Windows PowerShell:

```powershell
Get-Process | Where-Object { -not $_.Responding } | Select-Object Name,Id,Responding,StartTime
```

**Facts.** Record the app name, PID, `Responding` value, and start time from the output. The live
check returned no unresponsive processes.

**Uncertainty.** The live test used a throwaway Notepad process. Its `Stop-Process -Force` probe
exited without UAC, but that does not prove permission for this app or a process owned by another
account. Unsaved work may be lost.

**One reversible repair.** Only after the owner confirms the exact app and that its work is saved
or recoverable, propose **Task Manager → End task** for that app. Do not issue `Stop-Process -Force`
or `taskkill /F`; the GUI action avoids a second shell-pattern approval prompt. State the
same-user probe limit, request one F2 approval, and wait. Then relaunch the app.

**Recheck and outcome.** Repeat the unresponsive-process check and verify the relaunched app
responds. Record the original PID/status before and the remaining unresponsive list and relaunch
status after. Report `fixed` only if the old hung process is gone, the app relaunches, and the
owner confirms it responds; otherwise report `not fixed`.

**Linux read-only equivalent (not run):** `ps -p {PID} -o pid,stat,comm`. WSL process tools do not
manage Windows GUI processes.
