# Folders abused in intrusions

Surveyed 2026-11-07; revised the same day after an independent fact-check (not in the repository). Goal: list the Windows folders that intrusion reports and detection rules name, check what mozu can already express there, and list measurement candidates for the rule review (P4-9), P4-15 and the privilege-grouping question (product.md §6). HTML: [abused-folders.html](abused-folders.html). Plan items that follow: P4-24 (measure the candidates), P2-18 (`file_change`), P4-P candidate (merge the Public rules). Japanese: [abused-folders.ja.md](abused-folders.ja.md).

## Inputs

| Source | Version | Used for |
|---|---|---|
| ATT&CK Enterprise (`mitre/cti`) | `50be388e93` (2026-10-13) | Mentions: `uses` relationships whose procedure text names a folder |
| SigmaHQ `rules`, `rules-threat-hunting`, `rules-emerging-threats` (`windows/` only) | `46da2482c` (2026-10-20) | Rules that name a folder in a non-negated selection; statically loadable rules |
| [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md) | `master`, read 2026-11-07 | Folders under `C:\Windows` reported writable by standard users |
| mozu `detect` (`crates/detect/src/lib.rs`), own rules, `folder` categories | `main` `acbedc2` | What mozu emits to Sigma today ([architecture.md § Folder](../architecture.md#folder)) |
| ATT&CK [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | v20 | Staging examples (APT5 `C:\Users\Public`, Leviathan `C:\Windows\Debug`, `C:\PerfLogs`) |

Every count below is a row set in [abused-folders-counts.csv](abused-folders-counts.csv) (columns `source,folder,id,name,category,level,loadable,technique`; `source` is `attack`, `sigma` or `sigma-loadable`).

### Method

| Step | Rule |
|---|---|
| Folder match | One lower-cased regular expression per folder (e.g. `\\users\\public\\` or `%public%`); in ATT&CK prose the trailing `\` is optional and "Recycle Bin" also matches |
| Sigma positive text | Strings of all selections except those that occur **only** after `not` in `condition` (`not x`, `not 1 of x*`, `not all of x*`, `not (a or b)`). Selections used both ways count as positive |
| Sigma loadable (static) | `logsource.category` in `file_event`, `file_delete`, `file_rename`, `create_stream_hash`, and every field in every selection (negated ones included) is one mozu emits: `TargetFilename`, `SourceFilename`, `CreationUtcTime`, `UtcTime` |
| ATT&CK | `uses` relationships to techniques; revoked or deprecated relationships and techniques excluded |

Limits: the condition parser handles the forms above, not arbitrary nesting; correlation documents are skipped (no `detection`); "loadable" is a static check, not mozu's loader. The 88 loadable rules in `rules/` equal the loader's count on desktop6 in [detection-gaps.md](detection-gaps.md), but the two sets were not compared rule by rule. The script lives outside the repository; committing it is a separate plan-item decision.

## What mozu emits today

| Fact | Source | Limit relevant here |
|---|---|---|
| `file_event` with `TargetFilename`, `CreationUtcTime`, `FnCreationUtcTime`, `SiCreatedBeforeFnCreated` | Every in-use `$MFT` file | An existing file, not a creation |
| `file_event` / `file_rename` / `file_delete` with `TargetFilename` (+ `SourceFilename`), `UtcTime` | USN close records | Only USN events carry `UtcTime` |
| `create_stream_hash` | Named `$DATA` streams | — |
| `service: baseline_outside` | Baseline lookup | Needs a baseline |
| **Directories** | — | **Not emitted**: `file_target` returns `None` for directories (`crates/detect/src/lib.rs:82`) and USN directory records are skipped (`:105`). A rule sees a directory only through the paths of files under it |

## Conclusion

1. The folders named most often in ATT&CK procedure texts (user Temp 50, `AppData\Roaming` 31, `ntds.dit` copies 25, ProgramData 22, `Users\Public` 19, `Windows\Temp` 17) already have a mozu `folder` category or are reachable by path rules. Mention counts are not prevalence.
2. Most candidates can be written with today's file facts. Two cannot as stated: a folder whose own name is suspicious (F6) needs files under it or a new directory fact, and "created" (not "exists") needs an event condition that only USN rows satisfy (F2).
3. Three persistence or tampering traces can survive event-log deletion and have no own rule: Startup folders (T1547.001), task files under `System32\Tasks` (T1053.005), drivers outside the baseline. Paths alone do not show a task's action, a shortcut's target, a driver's vulnerability, or any execution.
4. A path does not show who can write a folder: a public list names 16 user-writable folders under `C:\Windows`. Grouping by privilege needs DACLs; P4-11 covers only the owner SID, so mozu cannot check this. Supports removing the grouping in P4-15.
5. SigmaHQ folder rules are mostly `process_creation` (`Image`): 57 of 103 `Users\Public` rules, 54 of 93 `Windows\Temp`. 0–12 rules per folder load statically here.
6. No new rule is proposed yet. F1–F7 are measurement candidates; levels follow ADR 0016 after measurement.

## Folder catalog

Write = default write access as reported by Microsoft or the public list above, not measured. ATT&CK = procedure texts naming the folder (texts / distinct groups, software or campaigns). Sigma = distinct rules naming it in a non-negated selection / of those statically loadable. Merged rows count distinct rules and sources.

| Folder | Write | Abuse (from ATT&CK texts or rule descriptions) | ATT&CK | Sigma | mozu `folder` | Own rules |
|---|---|---|---|---|---|---|
| `Users\<u>\AppData\Local\Temp` | user | Drop, staging (T1074.001 ×16), masquerade | 50 / 38 | 87 / 12 | `temp` | `executable_in_temp` (low), deleted (low) |
| `Users\<u>\AppData\Roaming` | user | Run-key payloads (T1547.001 ×6), staging | 31 / 26 | 47 / 4 | `appdata` | — |
| `Users\<u>\AppData\Local` (other) | user | Side-loading, browser data | 7 / 7 | 49 / 7 | `appdata` | — |
| `ProgramData` (root and new subfolders) | any user can create | Staging, persistence, hidden files (T1564.001), masquerade | 22 / 18 | 33 / 2 | `programdata` | — (ProgramData-root rule deferred in P1) |
| `Users\Public` | any user | Staging (T1074.001 ×6), tools, task payloads | 19 / 16 | 103 / 3 | `public` | `public_executable`, `public_script_or_archive` (medium) |
| `Windows\Temp` | any user can create | Staging, `ntds.dit` and hive copies, cleanup | 17 / 14 | 93 / 6 | `temp` | `executable_in_temp` (low), deleted (low) |
| `PerfLogs` | not verified | Staging (Leviathan, Wizard Spider) | 2 / 2 | 63 / 2 | `other` | — |
| `$Recycle.Bin` | user (own SID folder) | Staging (GALLIUM, menuPass, BackdoorDiplomacy); a fake `RECYCLE.BIN` on USB (Mustang Panda); 3 other mentions are wiping or discovery | 7 / 7 | 8 / 0 | `other` | — |
| Startup (`…\Start Menu\Programs\Startup`, per user and ProgramData) | user / admin | T1547.001, T1547.009 | 3 / 3 | 17 / 1 | `appdata` / `programdata` | — |
| `Windows\System32\Tasks`, `Windows\Tasks` | admin / any user (`Windows\Tasks`) | T1053.005 task files; drop folder | 0 / 0 | 23 / 2 | `windows` | — |
| `Windows\System32\drivers`, `.sys` elsewhere | admin | Drivers; masquerade | 1 / 1 | 2 / 0 | `windows` | — (`.sys` not in the baseline-binary rule) |
| User-writable `C:\Windows` subfolders (`Tracing`, `Registration\CRMLog`, `spool\drivers\color`, `MachineKeys`, …) | any user (per the list) | Drop and run where allow-lists trust `C:\Windows` | 0 / 0 | 3–5 / 0–1 each | `windows` | `outside_baseline_windows_binary` (high; `.exe`/`.dll`) |
| Rarely written `C:\Windows` subfolders (`Fonts`, `IME`, `Help`, `addins`, `debug`) | admin | Staging in `debug` (Leviathan); masquerade | 1 / 1 | 3–8 / 0 | `windows` | same |
| Mock folders (`C:\Windows \`, `C:\Program Files \`) | admin | UAC bypass, DLL search order (T1574) | 0 / 0 | 3 / 1 | `other` | — |
| `C:\` root (`C:\Intel`, `C:\temp`, `C:\program.exe`) | any user can create folders | Tool folders, unquoted service path (T1574.009) | 0 / 0 | 8 / 2 | `other` | — |
| `Users\<u>\Downloads`, `Desktop` | user | Initial access, ransom notes | 3 + 2 / 5 | 31 + 39 / 0 | `downloads`, `desktop` | `double_extension` (medium) |
| `inetpub\wwwroot`, Exchange `aspnet_client`/`FrontEnd` | admin / service | Web shells (T1505.003) | 2 / 1 | 11 / 1 | `other` | — |
| `NTDS`, `System32\config` copies | admin | Credential theft (T1003.003 ×16) | 27 / 20 | 16 / 3 | the copy's folder | — |
| `winevt\Logs`, `Prefetch` | admin | Trace removal (T1070) | 2 / 2 | 2 / 1 | `windows` | `event_log_deleted` (high), `prefetch_deleted` (medium) |
| `SYSVOL`, `NETLOGON` (DC) | domain admin | Deployment by GPO (T1484.001) | 0 / 0 | 5 / 0 | `windows` / `other` | — (Server out of MVP) |

Scheduled Task and Startup abuse is common, yet procedure texts rarely name the folder; low counts there say little.

### User-writable folders under `C:\Windows` (public list, not measured)

`Tasks`, `Temp`, `tracing`, `Registration\CRMLog`, `System32\FxsTmp`, `System32\com\dmp`, `System32\Microsoft\Crypto\RSA\MachineKeys`, `System32\spool\PRINTERS`, `System32\spool\SERVERS`, `System32\spool\drivers\color`, `System32\Tasks\Microsoft\Windows\SyncCenter`, `System32\Tasks_Migrated`, `SysWOW64\FxsTmp`, `SysWOW64\com\dmp`, `SysWOW64\Tasks\Microsoft\Windows\SyncCenter`, `SysWOW64\Tasks\Microsoft\Windows\PLA\System`.

mozu has no DACL fact, so it cannot check this list. Check it by hand on a baseline VM (`icacls`) if a decision depends on it.

## Candidates

Gate as [detection-gaps.md § Gate](detection-gaps.md#gate-for-a-new-rule) (G1 prevalence, G2 not already detected, G3 separable, G4 sample, G5 right layer). No candidate has a level: ADR 0016 sets it from the measurement.

| ID | Candidate | Facts today | A match shows / does not show | Normal cases to measure | Status |
|---|---|---|---|---|---|
| F1 | Executable, script or `.lnk` in a Startup folder, outside the baseline | `TargetFilename`, `baseline_outside` | A file there / not its target, nor that it ran. SigmaHQ's loadable rule omits `.exe` and `.lnk` | Vendor `.lnk` (Teams, OneDrive, VPN clients) | **Measure** |
| F2 | Task file under `Windows\System32\Tasks\`, outside the baseline | `TargetFilename`, `baseline_outside`; only USN rows carry `UtcTime` | A task file exists (or, with a USN-only condition, was created) / not its trigger, action or command | Updater tasks (Google, Edge, Adobe, OneDrive) | **Measure**; first show with a regression test that a rule can select USN-created rows only, else word it "exists" |
| F3 | `.sys` outside the baseline (outside-baseline driver candidate) | `TargetFilename`, `baseline_outside` | A driver-like file the baseline lacks / not vulnerability, signer, load, or use in defense evasion. Not a BYOVD detection | Hardware, AV, VPN and backup drivers | **Measure** |
| F4 | Executable, script or archive under `C:\PerfLogs\` | `TargetFilename` | A file there | Unknown; PerfLogs content on used hosts | **Measure** SigmaHQ `file_event_win_perflogs_susp_files` through mozu's loader and a regression sample |
| F5 | File directly under `$Recycle.Bin\<SID>\` whose name does not start with `$R`/`$I` and is not `desktop.ini` | `TargetFilename` (regex) | A file Explorer did not name / not who wrote it | Files under recycled folders (`$R…\<original names>`, excluded by "directly under"), applications writing there, Windows versions, migrations | **Measure** |
| F6 | Path with a folder name ending in a space or dot | `TargetFilename` (regex) on **files** under such a folder | Normal Win32 name handling strips trailing ASCII spaces and dots, but NTFS can hold such names / an empty folder is invisible (directories are not emitted) | Unknown | **Facts limit**: measure the file form; an empty folder needs a directory fact (new plan item) |
| F7 | Executable or script directly in `C:\ProgramData\` or `C:\` (files in subfolders excluded) | `TargetFilename` (regex, like `executable_in_users_root`) | A file at that level | Installers and agents that drop files at the root | **Measure** |
| F8 | Scripts (`.ps1`, `.bat`, `.vbs`, …) in user-writable `C:\Windows` subfolders | `TargetFilename`, `baseline_outside` | — | — | **Hold**: an extension change to the existing rule is H5, after measurement |
| F9 | Archive or `.dmp` in Temp/ProgramData/Public/PerfLogs, created then deleted | `file_event` + `file_delete`, `temporal_ordered` | — | Backups, crash dumps | **Hold** for P4-8; threshold from normal data |
| F10 | More system names in `system_binary_outside_system32` (`rundll32`, `dllhost`, `conhost`, `taskhostw`, `spoolsv`, `explorer`) | `TargetFilename` | — | Each name's normal locations | **Measure** before an H5 change |

Per candidate, record on the 12 local hosts: matching files, parent directory, extension, `$MFT` or USN origin and USN operation; then confirm on a regression sample (G4).

### SigmaHQ rules for neighboring cases (F11, split)

| Case | SigmaHQ rule(s) | Static check | Status |
|---|---|---|---|
| `ntds.dit`, SAM and hive copies | `file_event_win_sam_dump` (high), `file_event_win_ntds_exfil_tools` (high), `file_event_win_hktl_hivenightmare_file_exports` (high), `file_event_win_ntds_dit_creation` (low) | loadable | Not run through mozu's loader or a test event yet |
| LSASS dumps | `file_event_win_lsass_default_dump_file_names` (high) | loadable | Same |
| Default GPO folder writes | `file_event_win_susp_default_gpo_dir_write` (medium) | loadable | Same; Server is out of MVP |
| Web shells | `file_event_win_webshell_creation_detect` | not loadable (`Image`) | **Not covered** today; own rule "later" (detection-gaps.md) |

Out of reach (no fact): accessibility-binary replacement (`sethc.exe`) needs a data-overwrite category on baseline files; Defender exclusions are registry; SigmaHQ's Office `XLSTART`/Word `STARTUP` rules need `Image` except `office_addin_persistence`.

## Effect on existing features

| Feature | Finding | Suggestion |
|---|---|---|
| `folder` categories | The most-mentioned folders have a category; `PerfLogs`, `$Recycle.Bin`, `C:\` root and mock folders fall in `other`, Startup in `appdata`/`programdata` | No new category: rules match paths, the search covers the rest |
| Privilege grouping (product.md §6) | Path ≠ permission; DACLs are outside every planned item (P4-11 is owner SID only) | Remove in P4-15 as planned |
| P4-15 Outside-baseline by directory | New top-level folders in `ProgramData`, `C:\` and `Program Files` are a tool footprint | Keep; include `C:\` root folders in the list |
| `outside_baseline_windows_binary` | Does not cover `.sys` or scripts | F3/F8 after measurement (H5) |
| `executable_in_temp` / deleted (low) | Temp is named most and is noisy | Keep `low`; F9-style correlations add value |
| `double_extension` (medium) | Overlaps SigmaHQ `file_event_win_susp_double_extension` (high, statically loadable), but SigmaHQ is not shipped (Phase 2) | Keep |
| `file_change` category | USN `BASIC_INFO_CHANGE` is emitted as Sigma `file_change`; no own rule uses it and both SigmaHQ `file_change` rules need `Image` or `PreviousCreationUtcTime` (0 load). Sigma's `file_change` means Sysmon EID 2 (creation time changed), a narrower event | Stop emitting it (plan P2-18) |
| `public_executable` + `public_script_or_archive` | One folder, two rules split by extension; SigmaHQ has one | Merge candidate for P4-P (listed there) |

## For comparison with the Codex survey

| Check | This survey |
|---|---|
| Folders listed | 20 rows; 16 user-writable `C:\Windows` subfolders (public list) |
| ATT&CK mentions (top) | user Temp 50, Roaming 31, NTDS/config copies 27, ProgramData 22, Public 19, `Windows\Temp` 17 |
| Sigma rules naming a folder (top) | `Users\Public` 103, `Windows\Temp` 93, user Temp 87, `PerfLogs` 63 |
| SigmaHQ Windows rules statically loadable | 93 (88 `rules/`, 5 `rules-threat-hunting/`) |
| Outcome | 0 new rules; 7 measurement candidates (F1–F7, F6 with a facts limit); F8–F10 held or measured first |

## Caveats

- ATT&CK and Sigma counts measure reporting and rule writing, not prevalence.
- SigmaHQ `file_event` rules assume a creation by a process; here every `$MFT` file is a `file_event`, so loadable rules also fire on old files (detection-gaps.md).
- Nothing here has been run on the 12 local hosts or an attack corpus.
- Default ACLs come from Microsoft documentation and one public list; mozu cannot verify them.
