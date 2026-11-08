# Community knowledge: licenses and expected effect

Surveyed 2026-11-07; F3 wording aligned with the revised abused-folders.md the same day. Goal: for each community dataset beyond Sigma and ATT&CK, state whether mozu may use it under its license and decisions, and what it would add. Follows [abused-folders.md](abused-folders.md). Japanese: [community-knowledge.ja.md](community-knowledge.ja.md).

## Constraints that decide use

| Source | Rule |
|---|---|
| [ADR 0001](../adr/0001-license.md) | Code AGPL-3.0-only; rules DRL 1.1; dependencies AGPL-compatible |
| [ADR 0006](../adr/0006-gpl-reference-data.md) | GPL-3.0 data (LOLBAS, HijackLibs, winbindex) ships as data with the AGPL code, is matched at runtime and becomes **facts** and `service: unexpected_location`; never DRL rule content |
| [ADR 0019](../adr/0019-generic-rules-only.md) | Rules list no product or tool names and are not generated from third-party data. This overrides ADR 0006's "LOLDrivers may become DRL rules" |
| Inputs | Only `$MFT`, `$J`, `$Boot`, `$SDS`: names, paths, sizes, times, ADS names. **No hashes, signatures, content or process data** |
| No network | Data is pinned and shipped; never fetched at analysis time |

So a dataset can enter mozu in one of four ways:

| Way | Meaning | Decision needed |
|---|---|---|
| **Data** | Shipped with the binary, matched at runtime → fact / logsource; rules stay generic | H2 per dataset (ADR 0006 pattern); `NOTICE` + license text |
| **Dev** | Used only for tests and measurement, not shipped | Test data rules; no runtime dependency |
| **Reference** | Read to design rules, extension lists or texts; nothing copied | None |
| **No** | License, content or availability rules it out | — |

## Verdict per source

License from the GitHub API (`license.spdx_id`, `LICENSE` read where it was `NOASSERTION`), 2026-11-07. Counts from the published feeds or repository trees on the same day.

| Source | License | Last push | Use | Expected effect |
|---|---|---|---|---|
| [HijackLibs](https://github.com/wietze/HijackLibs) | GPL-3.0 | 2026-10-28 | **Data** (ADR 0006 already decides it) | **High** |
| [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Apache-2.0 | 2026-11-02 | **Data** (fact; not rules, ADR 0019) | **Medium–high** |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MIT | 2026-11-06 | **Dev** (G4 regression samples) | **High** (measurement) |
| [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | CC-BY-4.0 | 2026-08-29 | **Dev** (evaluation set) | **High** (measurement) |
| [ThreatLabz ransomware_notes](https://github.com/ThreatLabz/ransomware_notes) | MIT | 2026-08-13 | **Dev** (P4-9 thresholds) | **Medium–high** |
| [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | GPL-3.0 | 2026-09-26 | **Data** (ADR 0006) | Medium |
| [LOLRMM](https://github.com/magicsword-io/LOLRMM) | Apache-2.0 | 2026-11-05 | **Data**, detail view only (concept-review.md) | Medium |
| [KapeFiles](https://github.com/EricZimmerman/KapeFiles) | MIT | 2026-11-05 | **Reference** now; data for a follow-up manifest later | Medium |
| [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) | Apache-2.0 | 2026-11-01 | **Reference** (follow-up manifest) | Low–medium |
| [winbindex](https://github.com/m417z/winbindex) | GPL-3.0 | 2026-11-06 | **Data** possible (ADR 0006); hold | Low |
| NIST NSRL RDS | U.S. government work; redistribution terms not retrieved | quarterly | Hold | Unknown (see below) |
| [persistence-info](https://github.com/persistence-info/persistence-info.github.io) | GPL-3.0 | 2023-12-19 | **Reference** | Low |
| [Splunk security_content](https://github.com/splunk/security_content) | Apache-2.0 | 2026-11-05 | **Reference** | Low |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | Elastic License 2.0 | 2026-11-06 | **Reference only, copy nothing** | Low |
| [WTFBins](https://github.com/mttaggart/wtfbins) | MIT | 2025-03-30 | Reference | Low |
| [LOLAPPS](https://github.com/LOLAPPS-Project/LOLAPPS) | GPL-3.0 | 2025-02-19 | No (stale; LOLBAS covers the pattern) | Low |
| Microsoft vulnerable driver blocklist | Download Center terms, no open license | quarterly | No (LOLDrivers instead) | — |
| [ransomware.live](https://github.com/JMousqueton/ransomware.live) | Unlicense | 2026-07-20 | No (victim and leak-site data, no file facts) | — |
| [The DFIR Report Sigma-Rules](https://github.com/The-DFIR-Report/Sigma-Rules) | GPL-3.0 | 2026-07-08 | No (repository holds only `LICENSE` and `README.md`) | — |
| filesec.io | — | — | No (DNS failure 2026-11-07, no repository found) | — |

License compatibility: GPL-3.0 combines with AGPL-3.0 (GPLv3 §13); Apache-2.0, MIT and CC-BY-4.0 are one-way compatible with (A)GPL-3.0 and need attribution in `NOTICE`. Elastic License 2.0 is not open source and adds use restrictions, so its text and rule logic are not copied into AGPL code or DRL rules.

## Detail and expected effect

### Data candidates

| Source | Content (2026-11-07) | Usable from NTFS metadata | Fact it would add | Effect and why | Limits |
|---|---|---|---|---|---|
| HijackLibs | 627 DLLs; 597 with expected locations (428 in System32/SysWOW64); 1,907 side-loading, 459 environment-variable, 20 phantom, 17 search-order executable pairs | Name and path: all | `known hijackable DLL` + outside expected location → `service: unexpected_location`; optionally "the vulnerable executable is in the same folder" | **High**: DLL side-loading drops a signed executable and a DLL into ProgramData, AppData, Temp or Public, where `outside_baseline_windows_binary` (only `C:\Windows`) does not look. A generic rule (`unexpected_location` + `.dll`) adds no names to rules | 471 of 627 are Microsoft DLLs; legitimate apps bundle some names → combine with `baseline_outside`; measure on 12 hosts |
| LOLDrivers | 713 drivers (588 vulnerable, 125 malicious); 2,430 samples carry only hashes; file names are in `Tags`: 647 unique, 31 of them hash-like (`driver_<hex>.sys`) | Names only (no hashes here) | `known vulnerable driver name` on a `.sys` | **Medium–high**: narrows abused-folders.md F3 (outside-baseline driver candidates) to names the catalog lists. Driver abuse for defense evasion is reported before encryption (Defense Evasion is 24 of 225 tools in the Ransomware Tool Matrix) | A name match is not BYOVD: it does not show the version, signer, load or use. A renamed driver is missed; a patched driver with the same name still matches → fact, never a finding on its own |
| LOLBAS | 245 entries, 613 expected paths (227 System32/SysWOW64, 80 other `C:\Windows`, 282 Program Files, 24 other) | Name and path: all | `known LOLBin` + outside expected path | **Medium**: generalizes `system_binary_outside_system32` from 6 names to 245; a copied LOLBin outside its path is a masquerade signal | Execution is invisible; renamed copies are missed; already decided in ADR 0006 |
| LOLRMM | 358 tools; 318 with installation paths (846 bare names, 234 Program Files, 46 ProgramData, 35 AppData, 186 other); 111 tools with 845 disk artifacts | Names and paths | `catalog match` in the detail view of an outside-baseline directory (P4-15) | **Medium**: RMM is the largest ransomware tool category (42 tools); helps a non-expert recognize "AnyDesk folder" | ADR 0019 removed 307 product rules; data only, not findings |
| winbindex | Version and path history of Microsoft binaries | Names and paths | Microsoft binary outside its known paths | **Low**: the per-build baseline already answers this for the host's build | Large; useful only if baselines miss builds (P4-5 nearest-build fallback) |
| NSRL RDS | RDSv3 SQLite; very large (NIST warns); file rows carry name, size and hashes, no paths | Name + size (`$MFT` has size) | `known software file (name and size)` | Unknown: could reduce third-party noise among outside-baseline files (product.md P5), but name + size is weak and the data is huge | Terms not retrieved; compare first with P4-4 normalization |

### Dev and reference

| Source | Content | Effect and why |
|---|---|---|
| Atomic Red Team | 353 techniques. Windows tests: T1547.001 21, T1053.005 14, T1003.003 11, T1574.001 7, T1070.004 7, T1543.003 6, T1564.001 5, T1486 4, T1036.005 3, T1068 2, T1074.001 2, T1505.003 1 | **High** for measurement: G4 regression samples for abused-folders.md F1–F7 and P4-9 (run on the maintainer's VM, collect, keep the collection outside the repo) |
| Ransomware Tool Matrix | 225 tools in 8 categories (RMM 42, credential theft 42, discovery 36, offsec 28, exfiltration 28, defense evasion 24, networking 15, LOLBAS 10); 13 tools used by ≥ 10 gangs | **High** for measurement: a label set for P4-19 ("does the report show the footprint of the 13 tools used by ≥ 10 gangs?"); never rule content (ADR 0019) |
| ThreatLabz ransomware_notes | 222 families, 335 note files with original names (`readme*` 35, `how*to*recover*` 12) | **Medium–high**: tunes a generic P4-9 correlation "same new file name created in many directories within minutes" without listing note names |
| KapeFiles | 427 targets (Apps 194, Windows 102, compound 36, browsers 31, antivirus 29) | **Medium**: maps a finding to the KAPE target to collect next (concept-review.md follow-up manifest); M2 already reads KAPE output |
| ForensicArtifacts | Artifact path definitions (`windows.yaml`, `webservers.yaml`, …); `windows_dll_hijacking.yaml` is from Windows 7 | **Low–medium**: same role as KapeFiles for the manifest; its DLL list is covered by the baseline rule under `C:\Windows` |
| persistence-info | 44 entries, mostly registry; file-based: Startup folder, Task Scheduler, PowerShell profile, Recycle Bin, `wpbbin`, Windows Terminal profile | **Low**: confirms abused-folders.md F1/F2 and the PowerShell-profile rule; nothing else is visible in NTFS |
| Splunk security_content | 2,204 detections (1,529 endpoint), SPL | **Low**: mostly process-based like Sigma; conversion cost |
| Elastic detection-rules | EQL/KQL | **Low**, and license forbids reuse beyond reading |
| WTFBins | 48 entries of benign-but-noisy binaries | **Low**: process behavior, not file facts |

## Recommendation

| Order | Action | Why | Decision |
|---|---|---|---|
| 1 | HijackLibs as `unexpected_location` data + one generic rule | Already decided (ADR 0006); highest gain where the baseline rule does not look | Plan item (H1); data import is H2 |
| 2 | Atomic Red Team samples for F1–F7 and P4-9 | No rule is accepted without G4; cheap | Plan item; human runs the VM |
| 3 | Ransomware Tool Matrix as a P4-19 label set | Measures the product's own claim (≥ 80 % attack files shown) for the primary user's case | Part of P4-19 ADR |
| 4 | LOLDrivers names as a fact next to F3 candidates (after F3 is measured) | Tells a listed driver name from other third-party drivers; Apache-2.0 | New ADR (data from a non-GPL source, ADR 0019 boundary) |
| 5 | ThreatLabz notes for P4-9 thresholds | Generic correlation, measured | Within P4-9 |
| 6 | LOLBAS, LOLRMM facts | Detail-view value; not findings | After P4-13 |
| — | KapeFiles / ForensicArtifacts for a follow-up manifest | Only if that manifest becomes a plan item | Product need first |
| — | NSRL, winbindex | Hold until P4-4/P4-5 numbers show residual noise | Measurement first |

## Caveats

- Licenses are as declared by each repository; datasets may include third-party content under other terms. Re-check at import (ADR 0006 handling).
- "Effect" is a judgment from counts and fit, not a measurement. Each Data item needs per-host counts on the 12 local hosts before a rule level is set (ADR 0016).
- Name-only matching is evadable by renaming; every catalog match is a fact shown next to findings, never a ranking (AGENTS.md).
- Feeds were downloaded once for counting (GET only) into a scratch directory and not committed.
