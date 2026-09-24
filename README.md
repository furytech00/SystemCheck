# SystemCheck

SystemCheck is an authorized, read-only Windows configuration assessment toolkit.

The scripts live in [SystemChecker](SystemChecker/README.md).

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SystemChecker\Run-SystemChecker.ps1 -List
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SystemChecker\modules\01_system.ps1
```
