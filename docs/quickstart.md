# Quick start

Try the current build end to end: collect on a Windows host, analyze on any OS, open the report. Recipes: [usecases.md](usecases.md). Columns: [architecture.md](architecture.md#outputs).

| Step | Where | Needs |
|---|---|---|
| [1. Build](#1-build) | Mac/Linux/Windows | Rust 1.98 |
| [2. Smoke test](#2-smoke-test-no-windows) | any | nothing else |
| [3. Collect](#3-collect-on-windows) | Windows 10/11 x64, administrator | Rust and VS Build Tools (C++) on that host |
| [4. Baseline](#4-baseline) | any | a VanillaWindowsReference CSV |
| [5. Analyze](#5-analyze) | any | the extracted `$MFT` and `$J` |

Use a disposable or test host: `collect` reads the raw volume as administrator.

## 1. Build

```sh
cargo build --release --locked -p cli    # → target/release/mozu (mozu.exe on Windows)
```

`mozu collect` exists only in a Windows build; elsewhere it prints that it runs on Windows.

## 2. Smoke test (no Windows)

A synthetic `$MFT` checks that the build runs and writes all outputs:

```sh
cargo run -p xtask --release -- synth-mft 10000 /tmp/synth-MFT
target/release/mozu analyze -i /tmp/synth-MFT --rules testdata/rules \
  -o /tmp/synth.html --csv /tmp/synth.csv
```

## 3. Collect on Windows

In an elevated PowerShell on the host, after step 1 there. Write the zip to another drive (USB) when you can, so the collection does not change the volume it reads:

```powershell
.\target\release\mozu.exe collect -o D:\PC-042.zip      # -v C: is the default
Expand-Archive D:\PC-042.zip -DestinationPath D:\PC-042
Get-Content D:\PC-042\meta.json
```

- The zip holds `$MFT`, `$J` (stored part only), `$Boot`, `$SDS` and `meta.json` ([ADR 0024](adr/0024-collection-zip-format.md)). Without `-o` it is `<COMPUTERNAME>_<UTC start>.zip` in the current directory; an existing file is never overwritten.
- No `$J` entry and a warning: the volume has no USN journal. Analysis works without it.
- "access … denied; run as administrator": the shell is not elevated.

For the Phase 3 gate (P3-G in [plan.md](plan.md)), record time and peak memory while collecting (the whole `$MFT` is held in memory):

```powershell
$p = Start-Process .\target\release\mozu.exe -ArgumentList 'collect','-o','D:\PC-042.zip' -NoNewWindow -PassThru
$sw = [Diagnostics.Stopwatch]::StartNew(); $peak = 0
while (-not $p.HasExited) { $p.Refresh(); $peak = [Math]::Max($peak, $p.PeakWorkingSet64); Start-Sleep -Milliseconds 500 }
"exit $($p.ExitCode), $($sw.Elapsed), peak $([int]($peak / 1MB)) MB, zip $([int]((Get-Item D:\PC-042.zip).Length / 1MB)) MB"
```

Check that each file's size matches `meta.json`:

```powershell
$meta = Get-Content D:\PC-042\meta.json -Raw | ConvertFrom-Json
$meta.files | ForEach-Object { "{0}: meta {1}, file {2}" -f $_.name, $_.size, (Get-Item -LiteralPath "D:\PC-042\$($_.name)").Length }
```

## 4. Baseline

Build one from a [VanillaWindowsReference](https://github.com/AndrewRathbun/VanillaWindowsReference) CSV of the same Windows edition (client vs Server), as close to the host's build as available:

```sh
target/release/mozu baseline build --vwr <vwr.csv> -o win11.fst
```

Optional: without `--baseline` the `baseline` column is empty and the Outside-baseline tab has nothing.

## 5. Analyze

`analyze` reads the extracted files; zip input comes in Phase 4. Quote names with `$` so the shell does not expand them:

```sh
target/release/mozu analyze -i 'PC-042/$MFT' --usn 'PC-042/$J' \
  --baseline win11.fst --rules testdata/rules \
  -o PC-042.html --csv PC-042.csv
```

Add `--from 2026-09-28 --to 2026-10-02 --tz +09:00` to focus on a window (host's UTC offset). Open `PC-042.html`: Summary → click the critical/high count → Findings; the Outside-baseline tab lists files a clean Windows does not have.

On a clean test host, expect few findings: rules match attacker-like traces (deleted event logs, executables in Temp or Public, double extensions…), listed in `testdata/rules/`. To see one, for example, create and delete an `.exe` under `C:\Users\Public` before collecting (a USN rule: needs `--usn`).
