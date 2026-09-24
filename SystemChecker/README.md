# SystemChecker

SystemChecker is a modular, read-only toolkit that helps an authorized owner see how a Windows computer is configured. It prints a terminal report. It does not change the system.

## What this is

- A configuration assessment: operating system, UAC, installer policy, LSA settings, PowerShell logging, antivirus registration, application-control policy, and similar facts.
- Safe to run without administrator rights whenever Windows allows the read. If a check needs elevation, it prints `NEEDS ADMIN` and moves on.
- Written for Windows PowerShell 5.1. PowerShell 7 can run it, but 5.1 is the target.

## What this is not

- Not a WinPEAS or PEASS-ng clone, and not a copy of those projects.
- Not a privilege-escalation kit. There are no exploit payloads and no "how to abuse this" steps.
- Not a credential dumper. It does not dump LSASS, extract the SAM, decrypt browser passwords, or read secret values.

Run it only on computers you are allowed to inspect.

## Requirements

- Windows PowerShell 5.1 (`powershell.exe`).
- No network download. The toolkit does not fetch files.
- No files are written unless you pass `-Log`.

Windows PowerShell may refuse to run a downloaded script under the default execution policy. Bypass applies to this process only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Run-SystemChecker.ps1
```

Run that command from the `SystemChecker` directory, or pass the full path to the script.

## How to run

Runner (several modules in one process):

```powershell
.\Run-SystemChecker.ps1
.\Run-SystemChecker.ps1 -Modules system,users,services
.\Run-SystemChecker.ps1 -Plain
.\Run-SystemChecker.ps1 -Log .\systemchecker.log
.\Run-SystemChecker.ps1 -List
```

One module by itself:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\01_system.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\02_users_tokens.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\modules\04_services.ps1
```

`-Plain` turns ANSI color off. Color is on by default. `-Log` appends the same text without color codes. Console text uses `Write-Host`, so shell redirection is not a substitute for `-Log`.

The default runner selection is `system`, `users`, `services`, and `network`. File searches and event-log sweeps are not in the default set.

## Modules

| Alias | File | Status |
| --- | --- | --- |
| system | modules/01_system.ps1 | Implemented |
| users | modules/02_users_tokens.ps1 | Implemented |
| processes | modules/03_processes.ps1 | Stub |
| services | modules/04_services.ps1 | Implemented |
| apps | modules/05_applications.ps1 | Stub |
| network | modules/06_network.ps1 | Stub |
| creds | modules/07_credentials.ps1 | Stub |
| files | modules/08_files.ps1 | Stub |
| browser | modules/09_browser.ps1 | Stub |
| events | modules/10_events.ps1 | Stub |
| cloud | modules/11_cloud.ps1 | Stub |
| ad | modules/12_ad_optional.ps1 | Stub |

You can also pass `01` or the file name. Unknown names are rejected.

Stubs print `not implemented yet` and exit 0. They exist so the runner and the folder layout stay stable while later checks are added.

## Output labels

Each module prints a banner: module name, computer, user, timestamp, and whether the process is elevated.

| Label | Meaning |
| --- | --- |
| INFO | Fact about the current configuration. |
| REVIEW | Worth a look. Not proof of a compromise. |
| WEAK | A weaker setting an owner usually does not want. |
| WARN | The check could not be completed, including `NEEDS ADMIN`. |

An empty subsection prints `Nothing notable`.

Servicing notes compare the installed build with published lifecycle dates only. They are not a vulnerability map and they do not describe exploits.

## Adding the next module

1. Replace the stub's body. Keep the `#Requires -Version 5.1` line and dot-source `modules/00_common.ps1`.
2. Call `Write-SCHeader`, then `Start-SCSection` for each group of checks.
3. Report with `Write-SCInfo`, `Write-SCReview`, `Write-SCWeak`, or `Write-SCWarn`.
4. End with `Complete-SCSection`. If the runner set `SYSTEMCHECKER_NESTED=1`, `return` instead of `exit`, so one module cannot stop the others.
5. Reuse helpers in `00_common.ps1` (`Get-SCRegistryValue`, `Get-SCAclSummary`, `Test-SCWritableByNonAdmin`, `Test-SCUnquotedPath`, `Invoke-SCNative`). Do not shell out to tools you found on disk.
6. Update the `Status` field for that row in `Run-SystemChecker.ps1` when the module is real.

`06_network.ps1` is the suggested next module. It is still a stub, and the default run includes `network`. `03_processes.ps1` is the other unimplemented inventory module.
